"""Tests for the SecureFlow orchestrator (Step 16).

The orchestrator routes a ``RepositoryContext`` to the relevant specialized
agents, executes only the selected ones in deterministic order, bounds the
number of executions, records each agent's outcome without crashing the run,
and aggregates canonical ``SecurityFinding`` outputs.

All tests are offline and deterministic: routing uses a directly-constructed
``RepositoryContext`` and execution uses fake agents injected through the
``agent_factory`` seam. The real agent classes are never exercised here except
in the default-factory test, which uses ``FakeLLM``. No fixture repository is
ever executed.
"""

from __future__ import annotations

from pathlib import Path

from src.agents.code_security_agent import AgentTerminatedError
from src.llm.fake import FakeLLM
from src.models import (
    AgentName,
    CodeAgentResult,
    CodeFinding,
    EvidenceItem,
    EvidenceKind,
    FileCategory,
    FileEntry,
    FindingCategory,
    RepositoryContext,
    SecurityFinding,
    Severity,
)
from src.orchestration import (
    AgentRunStatus,
    OrchestrationResult,
    OrchestrationStatus,
    Orchestrator,
)

FIXTURES = Path(__file__).parent / "fixtures" / "orchestrator"
SOURCE_ONLY = FIXTURES / "source_only"
ALL_TYPES = FIXTURES / "all_types"


class FakeAgent:
    """A fake agent that records calls and simulates a configurable outcome.

    ``Outcome`` values:
      * ``success`` — returns a canonical finding.
      * ``empty_result`` — returns a result whose finding has no evidence.
      * ``no_finding`` — raises ``AgentTerminatedError`` (controlled termination).
      * ``failure`` — raises an unexpected exception (unhandled failure).
    """

    def __init__(self, name: AgentName, execute_log: list[AgentName], outcome: str = "success"):
        self._name = name
        self._execute_log = execute_log
        self._outcome = outcome

    def investigate(self) -> CodeAgentResult:
        self._execute_log.append(self._name)
        if self._outcome == "no_finding":
            raise AgentTerminatedError(
                steps_used=2, tool_calls_used=1, reason="No evidence of a vulnerability"
            )
        if self._outcome == "failure":
            raise RuntimeError("simulated unexpected failure")
        finding = CodeFinding(
            finding_id="F-1",
            severity=Severity.ERROR,
            confidence=0.9,
            file="file.py",
            description=f"finding from {self._name}",
        )
        return CodeAgentResult(finding=finding, tool_calls_used=1, iterations_used=2)

    def to_security_finding(self, finding: CodeFinding) -> SecurityFinding:
        return SecurityFinding(
            finding_id="X-1",
            agent=self._name,
            category=_category(self._name),
            severity=Severity.ERROR,
            confidence=0.9,
            file="file.py",
            description=f"canonical finding from {self._name}",
            evidence=[
                EvidenceItem(
                    kind=EvidenceKind.OBSERVED, content="observed: deterministic evidence"
                )
            ],
        )


def _category(name: AgentName) -> FindingCategory:
    return {
        AgentName.CODE_SECURITY: FindingCategory.CODE,
        AgentName.DEPENDENCY: FindingCategory.DEPENDENCY,
        AgentName.CICD: FindingCategory.CICD,
    }[name]


def make_factory(
    execute_log: list[AgentName],
    outcome_by_agent: dict[AgentName, str] | None = None,
    fail_factory_for: set[AgentName] | None = None,
):
    """Build an agent factory that records executions and simulates outcomes.

    ``fail_factory_for`` causes construction (``_factory(agent)``) to raise,
    which should surface as a FAILED record attributed to that agent.
    """
    outcome_by_agent = outcome_by_agent or {}
    fail_factory_for = fail_factory_for or set()

    def factory(agent: AgentName):
        if agent in fail_factory_for:
            raise RuntimeError("simulated factory failure")
        outcome = outcome_by_agent.get(agent, "success")
        return FakeAgent(agent, execute_log, outcome)

    return factory


def make_context(
    *,
    source: tuple[str, ...] = (),
    dependency: tuple[str, ...] = (),
    cicd: tuple[str, ...] = (),
    config: tuple[str, ...] = (),
    docs: tuple[str, ...] = (),
    other: tuple[str, ...] = (),
    name: str = "demo",
) -> RepositoryContext:
    """Build a RepositoryContext with the given categorized files."""
    return RepositoryContext(
        repository_name=name,
        repository_url="file:///demo",
        local_path="C:/repos/demo",
        commit_sha="a" * 40,
        source_files=[FileEntry(path=p, category=FileCategory.SOURCE) for p in source],
        dependency_files=[
            FileEntry(path=p, category=FileCategory.DEPENDENCY) for p in dependency
        ],
        cicd_files=[FileEntry(path=p, category=FileCategory.CICD) for p in cicd],
        config_files=[FileEntry(path=p, category=FileCategory.CONFIG) for p in config],
        documentation_files=[
            FileEntry(path=p, category=FileCategory.DOCUMENTATION) for p in docs
        ],
        other_files=[FileEntry(path=p, category=FileCategory.OTHER) for p in other],
    )


CODE = AgentName.CODE_SECURITY
DEP = AgentName.DEPENDENCY
CICD = AgentName.CICD


# ---------------------------------------------------------------------------
# Routing — selection
# ---------------------------------------------------------------------------


class TestRouting:
    def test_source_only_selects_code_agent(self) -> None:
        ctx = make_context(source=("src/app.py",))
        orchestrator = Orchestrator(context=ctx, agent_factory=make_factory([]))
        assert orchestrator.select_agents() == [CODE]

    def test_dependency_only_selects_dependency_agent(self) -> None:
        ctx = make_context(dependency=("requirements.txt",))
        orchestrator = Orchestrator(context=ctx, agent_factory=make_factory([]))
        assert orchestrator.select_agents() == [DEP]

    def test_cicd_only_selects_cicd_agent(self) -> None:
        ctx = make_context(cicd=(".github/workflows/ci.yml",))
        orchestrator = Orchestrator(context=ctx, agent_factory=make_factory([]))
        assert orchestrator.select_agents() == [CICD]

    def test_source_and_dependency_selects_code_and_dependency(self) -> None:
        ctx = make_context(source=("src/app.py",), dependency=("requirements.txt",))
        orchestrator = Orchestrator(context=ctx, agent_factory=make_factory([]))
        assert orchestrator.select_agents() == [CODE, DEP]

    def test_all_types_selects_all_three(self) -> None:
        ctx = make_context(
            source=("src/app.py",),
            dependency=("requirements.txt",),
            cicd=(".github/workflows/ci.yml",),
        )
        orchestrator = Orchestrator(context=ctx, agent_factory=make_factory([]))
        assert orchestrator.select_agents() == [CODE, DEP, CICD]

    def test_deployment_config_routes_cicd_agent(self) -> None:
        # Deployment YAML is classified as CONFIG but must route CI/CD.
        ctx = make_context(config=("deploy/app-deployment.yaml",))
        orchestrator = Orchestrator(context=ctx, agent_factory=make_factory([]))
        assert orchestrator.select_agents() == [CICD]

    def test_non_deploy_config_alone_selects_no_agents(self) -> None:
        # Arbitrary (non-deployment) configuration must not route any agent.
        ctx = make_context(config=(".eslintrc.json",))
        orchestrator = Orchestrator(context=ctx, agent_factory=make_factory([]))
        assert orchestrator.select_agents() == []

    def test_source_plus_deployment_selects_code_and_cicd(self) -> None:
        ctx = make_context(source=("src/app.py",), config=("deploy/app.yaml",))
        orchestrator = Orchestrator(context=ctx, agent_factory=make_factory([]))
        assert orchestrator.select_agents() == [CODE, CICD]

    def test_documentation_only_selects_no_agents(self) -> None:
        ctx = make_context(docs=("README.md", "docs/guide.md"))
        orchestrator = Orchestrator(context=ctx, agent_factory=make_factory([]))
        assert orchestrator.select_agents() == []

    def test_empty_repository_selects_no_agents(self) -> None:
        ctx = make_context()
        orchestrator = Orchestrator(context=ctx, agent_factory=make_factory([]))
        assert orchestrator.select_agents() == []

    def test_routing_ignores_documentation_when_source_present(self) -> None:
        # Docs are not a trigger, but source code still is.
        ctx = make_context(source=("src/app.py",), docs=("README.md",))
        orchestrator = Orchestrator(context=ctx, agent_factory=make_factory([]))
        assert orchestrator.select_agents() == [CODE]

    def test_routing_is_content_based_not_fixture_based(self) -> None:
        # Arbitrary source path (not any known fixture name) still routes Code.
        ctx = make_context(source=("pkg/module/src.py",))
        orchestrator = Orchestrator(context=ctx, agent_factory=make_factory([]))
        assert orchestrator.select_agents() == [CODE]


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


class TestExecution:
    def _run(self, ctx: RepositoryContext, **kwargs) -> tuple[OrchestrationResult, list[AgentName]]:
        executed: list[AgentName] = []
        orchestrator = Orchestrator(context=ctx, agent_factory=make_factory(executed), **kwargs)
        return orchestrator.orchestrate(), executed

    def test_only_selected_agents_executed(self) -> None:
        # Source + deployment → Code + CI/CD. Dependency is NOT executed.
        ctx = make_context(source=("src/app.py",), config=("deploy/app.yaml",))
        result, executed = self._run(ctx)
        assert executed == [CODE, CICD]
        assert [r.agent for r in result.runs] == [CODE, CICD]
        assert all(r.selected for r in result.runs)

    def test_execution_order_code_dependency_cicd(self) -> None:
        ctx = make_context(
            source=("src/app.py",),
            dependency=("requirements.txt",),
            cicd=(".github/workflows/ci.yml",),
        )
        result, executed = self._run(ctx)
        assert executed == [CODE, DEP, CICD]
        assert [r.agent for r in result.runs] == [CODE, DEP, CICD]

    def test_findings_aggregated_in_execution_order(self) -> None:
        ctx = make_context(
            source=("src/app.py",),
            dependency=("requirements.txt",),
            cicd=(".github/workflows/ci.yml",),
        )
        result, _ = self._run(ctx)
        assert [f.agent for f in result.findings] == [CODE, DEP, CICD]
        for f, record in zip(result.findings, result.runs):
            assert f.agent == record.agent

    def test_finding_agent_stamped_and_run_status_success(self) -> None:
        ctx = make_context(source=("src/app.py",))
        result, _ = self._run(ctx)
        assert len(result.runs) == 1
        record = result.runs[0]
        assert record.status is AgentRunStatus.SUCCESS
        assert record.finding is not None
        assert record.finding.agent is CODE
        assert record.finding.category is FindingCategory.CODE
        assert record.tool_calls_used == 1
        assert record.iterations_used == 2

    def test_overall_completed_when_all_selected_succeed(self) -> None:
        ctx = make_context(source=("src/app.py",), dependency=("requirements.txt",))
        result, _ = self._run(ctx)
        assert result.status is OrchestrationStatus.COMPLETED

    def test_empty_overall_status(self) -> None:
        ctx = make_context(docs=("README.md",))
        result, executed = self._run(ctx)
        assert result.status is OrchestrationStatus.EMPTY
        assert executed == []
        assert result.selected_agents == []
        assert result.runs == []
        assert result.findings == []

    def test_repository_name_propagated(self) -> None:
        ctx = make_context(source=("src/app.py",), name="myapp")
        result, _ = self._run(ctx)
        assert result.repository_name == "myapp"

    def test_limits_recorded(self) -> None:
        ctx = make_context(source=("src/app.py",))
        result, _ = self._run(ctx, max_agents=2, max_executions=2, max_passes=1)
        assert result.limits == {"max_agents": 2, "max_executions": 2, "max_passes": 1}


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------


class TestFailureHandling:
    def test_no_finding_recorded_and_others_still_run(self) -> None:
        ctx = make_context(
            source=("src/app.py",),
            dependency=("requirements.txt",),
            cicd=(".github/workflows/ci.yml",),
        )
        executed: list[AgentName] = []
        orchestrator = Orchestrator(
            context=ctx,
            agent_factory=make_factory(
                executed, outcome_by_agent={CODE: "no_finding", DEP: "success", CICD: "success"}
            ),
        )
        result = orchestrator.orchestrate()
        assert executed == [CODE, DEP, CICD]  # no-finding agent still ran; others run too
        code_record = result.runs[0]
        assert code_record.status is AgentRunStatus.NO_FINDING
        assert code_record.finding is None
        assert "No evidence" in code_record.note
        assert result.runs[1].status is AgentRunStatus.SUCCESS
        assert result.runs[2].status is AgentRunStatus.SUCCESS
        assert result.findings == [result.runs[1].finding, result.runs[2].finding]

    def test_failed_agent_does_not_crash_run(self) -> None:
        ctx = make_context(
            source=("src/app.py",),
            cicd=(".github/workflows/ci.yml",),
        )
        executed: list[AgentName] = []
        orchestrator = Orchestrator(
            context=ctx,
            agent_factory=make_factory(executed, outcome_by_agent={CICD: "failure"}),
        )
        result = orchestrator.orchestrate()
        assert executed == [CODE, CICD]  # both ran; failure is contained
        assert result.runs[0].status is AgentRunStatus.SUCCESS
        assert result.runs[1].status is AgentRunStatus.FAILED
        assert result.runs[1].note
        assert result.status is OrchestrationStatus.FAILED
        assert [f.agent for f in result.findings] == [CODE]

    def test_factory_failure_recorded_as_failed(self) -> None:
        ctx = make_context(
            source=("src/app.py",),
            cicd=(".github/workflows/ci.yml",),
        )
        executed: list[AgentName] = []
        orchestrator = Orchestrator(
            context=ctx,
            agent_factory=make_factory(executed, fail_factory_for={CICD}),
        )
        result = orchestrator.orchestrate()
        # Construction failure for CICD does not stop Code from running.
        assert executed == [CODE]
        assert result.runs[0].status is AgentRunStatus.SUCCESS
        assert result.runs[1].status is AgentRunStatus.FAILED
        assert "construction failed" in result.runs[1].note
        assert result.status is OrchestrationStatus.FAILED

    def test_no_finding_only_overall_completed(self) -> None:
        # Every agent ran; none failed — overall is COMPLETED even with no findings.
        ctx = make_context(source=("src/app.py",), dependency=("requirements.txt",))
        executed: list[AgentName] = []
        orchestrator = Orchestrator(
            context=ctx,
            agent_factory=make_factory(
                executed,
                outcome_by_agent={CODE: "no_finding", DEP: "no_finding"},
            ),
        )
        result = orchestrator.orchestrate()
        assert [r.status for r in result.runs] == [
            AgentRunStatus.NO_FINDING,
            AgentRunStatus.NO_FINDING,
        ]
        assert result.findings == []
        assert result.status is OrchestrationStatus.COMPLETED


# ---------------------------------------------------------------------------
# Bounded execution
# ---------------------------------------------------------------------------


class TestBounds:
    def test_max_agents_stops_execution_and_marks_not_run(self) -> None:
        ctx = make_context(
            source=("src/app.py",),
            dependency=("requirements.txt",),
            cicd=(".github/workflows/ci.yml",),
        )
        executed: list[AgentName] = []
        orchestrator = Orchestrator(
            context=ctx, agent_factory=make_factory(executed), max_agents=2, max_executions=2
        )
        result = orchestrator.orchestrate()
        assert executed == [CODE, DEP]
        assert [r.agent for r in result.runs] == [CODE, DEP, CICD]
        assert result.runs[0].status is AgentRunStatus.SUCCESS
        assert result.runs[1].status is AgentRunStatus.SUCCESS
        assert result.runs[2].status is AgentRunStatus.NOT_RUN
        assert "limit reached" in result.runs[2].note
        assert result.status is OrchestrationStatus.PARTIAL

    def test_max_executions_bounds_distinct_agents(self) -> None:
        ctx = make_context(
            source=("src/app.py",),
            dependency=("requirements.txt",),
            cicd=(".github/workflows/ci.yml",),
        )
        executed: list[AgentName] = []
        orchestrator = Orchestrator(
            context=ctx, agent_factory=make_factory(executed), max_executions=1
        )
        result = orchestrator.orchestrate()
        assert executed == [CODE]
        assert [r.status for r in result.runs] == [
            AgentRunStatus.SUCCESS,
            AgentRunStatus.NOT_RUN,
            AgentRunStatus.NOT_RUN,
        ]
        assert result.status is OrchestrationStatus.PARTIAL


# ---------------------------------------------------------------------------
# Default factory (real agents with a fake LLM)
# ---------------------------------------------------------------------------


class TestDefaultFactory:
    def test_default_factory_runs_real_code_agent(self) -> None:
        # Only the Code agent is routed for a source-only repo; it is built by
        # the default factory using the injected FakeLLM.
        finding = CodeFinding(
            finding_id="CODE-1",
            severity=Severity.ERROR,
            confidence=0.9,
            file="src/app.py",
            description="Insecure subprocess usage.",
            evidence=["observed: source:subprocess usage"],
        )
        fake = FakeLLM([finding])
        ctx = RepositoryContext(
            repository_name="demo",
            repository_url="file:///demo",
            local_path=str(SOURCE_ONLY),
            commit_sha="a" * 40,
            source_files=[
                FileEntry(path="src/app.py", category=FileCategory.SOURCE),
            ],
        )
        orchestrator = Orchestrator(context=ctx, llm=fake)
        result = orchestrator.orchestrate()
        assert result.selected_agents == [CODE]
        assert result.runs[0].status is AgentRunStatus.SUCCESS
        assert result.findings[0].agent is CODE
        assert result.findings[0].category is FindingCategory.CODE

    def test_requires_llm_or_factory(self) -> None:
        ctx = make_context(source=("src/app.py",))
        try:
            Orchestrator(context=ctx)  # type: ignore[call-arg]
        except ValueError as exc:
            assert "agent_factory or llm" in str(exc)
        else:  # pragma: no cover - assertion is the intent
            raise AssertionError("expected ValueError")
