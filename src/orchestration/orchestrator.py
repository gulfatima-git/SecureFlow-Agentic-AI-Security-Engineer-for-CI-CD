"""SecureFlow orchestrator (Step 16).

The orchestrator coordinates the specialized agents. Given a ``RepositoryContext``
it:

* selects the relevant agents deterministically from repository contents
  (source code → Code Agent, dependency manifests → Dependency Agent,
  CI/CD/deployment configuration → CI/CD Agent; documentation alone selects no
  agents);
* executes only the selected agents, in the deterministic order
  Code → Dependency → CI/CD;
* bounds the number of agent executions;
* records each agent's outcome (success / no-finding / failure / not-run) without
  crashing the run; and
* aggregates the canonical ``SecurityFinding`` outputs produced by the agents
  that actually ran.

Per the project's architecture principle, the orchestrator ONLY coordinates. It
does not perform vulnerability analysis, does not move security logic out of the
agents, and does not modify agent investigation behavior. It never executes
code, shell commands, subprocesses, Docker/kubectl/cloud CLIs, or network calls.

Routing is a deterministic function of ``RepositoryContext`` — the ingestor's
categorized file lists (``source_files``, ``dependency_files``,
``cicd_files``, ``config_files``, ...) — not of hard-coded fixture names.

An ``agent_factory`` seam (a callable mapping an :class:`AgentName` to an agent
instance) allows tests to inject fake agents and an offline future model to
swap implementations without changing orchestration logic.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol

from src.agents import (
    CICDSecurityAgent,
    CodeSecurityAgent,
    DependencyAgent,
)
from src.agents.code_security_agent import AgentTerminatedError
from src.llm.base import LLMProvider
from src.models.code_finding import CodeAgentResult, CodeFinding
from src.models.finding import AgentName, SecurityFinding
from src.models.repository import RepositoryContext
from src.orchestration.models import (
    AgentRunRecord,
    AgentRunStatus,
    OrchestrationResult,
    OrchestrationStatus,
)


class AgentLike(Protocol):
    """Minimal agent surface the orchestrator depends on."""

    def investigate(self) -> CodeAgentResult: ...
    def to_security_finding(self, finding: CodeFinding) -> SecurityFinding: ...


AgentFactory = Callable[[AgentName], AgentLike]


# Deterministic execution/ordering policy: Code, then Dependency, then CI/CD.
# This is an initial policy, not claimed to be optimal; changing ordering is a
# one-line configuration rather than a redesign.
DEFAULT_AGENT_ORDER: tuple[AgentName, ...] = (
    AgentName.CODE_SECURITY,
    AgentName.DEPENDENCY,
    AgentName.CICD,
)

DEFAULT_MAX_AGENTS = 3
DEFAULT_MAX_EXECUTIONS = 3
DEFAULT_MAX_PASSES = 1

# Directory-path tokens that identify deployment/container manifests. Such files
# are classified by the ingestor as CONFIG (YAML is a config extension) but are
# CI/CD/deployment-relevant, so they must route the CI/CD agent.
_DEPLOYMENT_DIR_TOKENS: frozenset[str] = frozenset(
    {
        "k8s",
        "deploy",
        "deployment",
        "deployments",
        "manifests",
        "helm",
        "charts",
        "infra",
    }
)


class Orchestrator:
    """Coordinate the specialized agents over a ``RepositoryContext``.

    Args:
        context: The ingested ``RepositoryContext`` that routing inspects.
        llm: The ``LLMProvider`` used by the default agent factory. Ignored when
            ``agent_factory`` is provided.
        repository_path: Repository root passed to the default factory. When
            omitted, ``context.local_path`` is used.
        agent_factory: Optional factory mapping an ``AgentName`` to an agent
            instance, enabling tests to inject fakes.
        max_agents: Hard ceiling on distinct agents executed in one run.
        max_executions: Hard ceiling on total agent executions across a run.
        max_passes: Reserved bound for future iterative passes. Step 16 performs
            a single deterministic pass; this field is recorded for later steps.
        agent_order: Deterministic execution order (defaults to
            Code → Dependency → CI/CD).
    """

    def __init__(
        self,
        *,
        context: RepositoryContext,
        llm: LLMProvider | None = None,
        repository_path: str | Path | None = None,
        agent_factory: AgentFactory | None = None,
        max_agents: int = DEFAULT_MAX_AGENTS,
        max_executions: int = DEFAULT_MAX_EXECUTIONS,
        max_passes: int = DEFAULT_MAX_PASSES,
        agent_order: Sequence[AgentName] | None = None,
    ) -> None:
        self._context = context
        self._max_agents = max_agents
        self._max_executions = max_executions
        self._max_passes = max_passes
        self._agent_order: tuple[AgentName, ...] = (
            tuple(agent_order) if agent_order else DEFAULT_AGENT_ORDER
        )

        if agent_factory is not None:
            self._factory: AgentFactory = agent_factory
        else:
            if llm is None:
                raise ValueError("Either agent_factory or llm must be provided")
            resolved_path = Path(repository_path) if repository_path else Path(context.local_path)
            self._factory = self._build_default_factory(llm, resolved_path)

    def select_agents(self) -> list[AgentName]:
        """Return the ordered subset of agents selected by routing.

        Routing is a deterministic function of the repository's categorized
        contents. Documentation and unrelated configuration never select an
        agent on their own.
        """
        selected: set[AgentName] = set()
        if self._context.source_files:
            selected.add(AgentName.CODE_SECURITY)
        if self._context.dependency_files:
            selected.add(AgentName.DEPENDENCY)
        if self._cicd_relevant():
            selected.add(AgentName.CICD)
        return [agent for agent in self._agent_order if agent in selected]

    def orchestrate(self) -> OrchestrationResult:
        """Route, execute, and aggregate a single deterministic pass.

        Returns:
            An ``OrchestrationResult`` summarizing routing, per-agent outcomes,
            the collected canonical findings, and the applied bounds.
        """
        selected = self.select_agents()
        runs: list[AgentRunRecord] = []
        executions = 0

        for agent in selected:
            if executions >= self._max_agents or executions >= self._max_executions:
                runs.append(
                    AgentRunRecord(
                        agent=agent,
                        selected=True,
                        status=AgentRunStatus.NOT_RUN,
                        note=(
                            "not run: bounded agent execution limit reached "
                            f"(max_agents={self._max_agents}, "
                            f"max_executions={self._max_executions})"
                        ),
                    )
                )
                continue

            record = self._run_agent(agent)
            runs.append(record)
            if record.status is AgentRunStatus.NOT_RUN:
                continue
            executions += 1

        findings = [r.finding for r in runs if r.finding is not None]

        return OrchestrationResult(
            repository_name=self._context.repository_name,
            selected_agents=selected,
            runs=runs,
            findings=findings,
            status=self._overall_status(selected, runs),
            agent_order=list(self._agent_order),
            passes_run=1 if selected else 0,
            limits={
                "max_agents": self._max_agents,
                "max_executions": self._max_executions,
                "max_passes": self._max_passes,
            },
        )

    # -- Internal helpers -------------------------------------------

    def _cicd_relevant(self) -> bool:
        """True when the repo contains CI/CD or deployment/container config."""
        if self._context.cicd_files:
            return True
        return any(
            _is_deployment_config(entry.path) for entry in self._context.config_files
        )

    def _run_agent(self, agent: AgentName) -> AgentRunRecord:
        """Instantiate, run, and canonicalize a single selected agent.

        Failures at any stage are recorded as a status (``FAILED`` or
        ``NO_FINDING``) rather than crashing the run, preserving the invariant
        that untrusted repository content cannot take down the whole pass.
        """
        try:
            instance = self._factory(agent)
        except Exception as exc:  # noqa: BLE001 - any factory failure is controlled
            return AgentRunRecord(
                agent=agent,
                selected=True,
                status=AgentRunStatus.FAILED,
                note=f"agent construction failed: {exc}",
            )

        try:
            result = instance.investigate()
            finding = instance.to_security_finding(result.finding)
        except AgentTerminatedError as exc:
            return AgentRunRecord(
                agent=agent,
                selected=True,
                status=AgentRunStatus.NO_FINDING,
                note=str(exc),
                tool_calls_used=getattr(exc, "tool_calls_used", 0),
                iterations_used=getattr(exc, "steps_used", 0),
            )
        except Exception as exc:  # noqa: BLE001 - any agent failure is controlled
            return AgentRunRecord(
                agent=agent,
                selected=True,
                status=AgentRunStatus.FAILED,
                note=f"agent investigation failed: {exc}",
            )

        return AgentRunRecord(
            agent=agent,
            selected=True,
            status=AgentRunStatus.SUCCESS,
            finding=finding,
            tool_calls_used=result.tool_calls_used,
            iterations_used=result.iterations_used,
        )

    def _build_default_factory(self, llm: LLMProvider, path: Path) -> AgentFactory:
        def factory(agent: AgentName) -> AgentLike:
            if agent is AgentName.CODE_SECURITY:
                return CodeSecurityAgent(llm, path, context=self._context)
            if agent is AgentName.DEPENDENCY:
                return DependencyAgent(llm, path, context=self._context)
            if agent is AgentName.CICD:
                return CICDSecurityAgent(llm, path, context=self._context)
            raise ValueError(f"Unknown agent: {agent!r}")

        return factory

    @staticmethod
    def _overall_status(
        selected: list[AgentName], runs: list[AgentRunRecord]
    ) -> OrchestrationStatus:
        if not selected:
            return OrchestrationStatus.EMPTY
        if any(r.status is AgentRunStatus.FAILED for r in runs):
            return OrchestrationStatus.FAILED
        if any(r.status is AgentRunStatus.NOT_RUN for r in runs):
            return OrchestrationStatus.PARTIAL
        return OrchestrationStatus.COMPLETED


def _is_deployment_config(rel_path: str) -> bool:
    """Whether a config-category path is a deployment/container manifest.

    Uses deterministic path tokens only — it never resolves or executes paths,
    and never depends on repository names or fixture names.
    """
    normalized = rel_path.replace("\\", "/").lstrip("/")
    parts = normalized.split("/")
    return any(part in _DEPLOYMENT_DIR_TOKENS for part in parts)
