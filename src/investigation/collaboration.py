"""Application-controlled specialist collaboration interface (Step 17).

The Investigation Agent must never directly instantiate or execute another
agent, and must never pass arbitrary tool names or repository-derived text into
an agent/resolver. Every request for additional specialist evidence passes
through :class:`CollaborationInterface`, which:

* validates the request's ``target_agent`` against the known specialist agents;
* validates ``request_type`` against a strict per-agent allow-list;
* invokes a bound specialist capability (never arbitrary tool names);
* returns a structured :class:`SpecialistResponse` (success or explicit
  failure, never fabricated evidence);
* records the request/response transcript; and
* bounds the number of evidence items returned per response.

The registry maps a target agent to the set of request types that agent may
answer. Default handlers reuse the existing deterministic tool layers
(``AgentTools``, ``DependencyAgentTools``, ``CICDSecurityAgentTools``) which
already confine reads/searches to the repository root and never execute code.
For tests, the registry may be injected with mock handlers so behaviour is
exercised offline and deterministically.

This layer contains NO arbitrary shell/subprocess/Docker/kubectl/cloud/gh
execution and NO network calls.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from src.investigation.models import InvestigationRequest, SpecialistResponse
from src.models.finding import AgentName
from src.models.repository import RepositoryContext

# Strict per-agent allow-list of request types.
CODE_REQUEST_TYPES: frozenset[str] = frozenset(
    {"source_context", "symbol_usage", "related_files"}
)
DEPENDENCY_REQUEST_TYPES: frozenset[str] = frozenset(
    {"dependency_usage", "dependency_details", "affected_component"}
)
CICD_REQUEST_TYPES: frozenset[str] = frozenset(
    {"workflow_context", "permission_context", "deployment_context"}
)

ALLOWED_REQUEST_TYPES: dict[str, frozenset[str]] = {
    AgentName.CODE_SECURITY.value: CODE_REQUEST_TYPES,
    AgentName.DEPENDENCY.value: DEPENDENCY_REQUEST_TYPES,
    AgentName.CICD.value: CICD_REQUEST_TYPES,
}

DEFAULT_MAX_EVIDENCE_ITEMS = 20

# A request handler takes a validated request and returns a structured response.
SpecialistHandler = Callable[[InvestigationRequest], SpecialistResponse]
SpecialistRegistry = dict[str, dict[str, SpecialistHandler]]


class CollaborationInterface:
    """Application-controlled gate for specialist collaboration.

    Args:
        registry: Optional mapping of target agent → {request_type → handler}.
            When omitted, real handlers are built from the existing tool layers.
        repository_path: Repository root used to build real handlers when
            ``registry`` is not provided.
        context: Optional ``RepositoryContext`` for inventory-based handlers.
        max_evidence_items: Bounds the number of evidence items in a response.
    """

    def __init__(
        self,
        *,
        registry: SpecialistRegistry | None = None,
        repository_path: str | Path | None = None,
        context: RepositoryContext | None = None,
        max_evidence_items: int = DEFAULT_MAX_EVIDENCE_ITEMS,
    ) -> None:
        # Build the default (real) registry unless an explicit registry is given.
        if registry is None:
            registry = self._build_default_registry(repository_path, context)
        self._registry = registry
        self._max_evidence_items = max_evidence_items
        self._request_log: list[InvestigationRequest] = []

    @property
    def request_log(self) -> list[InvestigationRequest]:
        """Record of every request processed (for application bookkeeping)."""
        return list(self._request_log)

    def execute(self, request: InvestigationRequest) -> SpecialistResponse:
        """Validate and route a single specialist request.

        Validation failures (unknown target agent, unsupported request type) are
        returned as structured ``success=False`` responses so the investigation
        can record them and continue. No arbitrary tool names are ever executed.

        Args:
            request: The structured request from the Investigation Agent.

        Returns:
            A structured :class:`SpecialistResponse`.
        """
        self._request_log.append(request)

        if request.target_agent not in ALLOWED_REQUEST_TYPES:
            return _failure(
                request,
                agent=request.target_agent,
                reason=f"unknown target agent: {request.target_agent!r}",
            )

        allowed = ALLOWED_REQUEST_TYPES[request.target_agent]
        if request.request_type not in allowed:
            return _failure(
                request,
                agent=request.target_agent,
                reason=(
                    f"request type {request.request_type!r} is not allowed for "
                    f"agent {request.target_agent!r}; allowed: {sorted(allowed)}"
                ),
            )

        agent_handlers = self._registry.get(request.target_agent)
        if not agent_handlers:
            return _failure(
                request,
                agent=request.target_agent,
                reason=f"no capability registered for agent {request.target_agent!r}",
            )

        handler = agent_handlers.get(request.request_type)
        if handler is None:
            return _failure(
                request,
                agent=request.target_agent,
                reason=(
                    f"capability {request.request_type!r} is not registered for "
                    f"agent {request.target_agent!r}"
                ),
            )

        try:
            response = handler(request)
        except Exception as exc:  # noqa: BLE001 - bound all handler failures
            return _failure(
                request,
                agent=request.target_agent,
                reason=f"specialist capability failed: {exc}",
            )

        response.agent = request.target_agent
        response.evidence = response.evidence[: self._max_evidence_items]
        return response

    # -- Default (real) capability registry -------------------------

    def _build_default_registry(
        self,
        repository_path: str | Path | None,
        context: RepositoryContext | None,
    ) -> SpecialistRegistry:
        from src.investigation.handlers import build_default_registry

        return build_default_registry(repository_path=repository_path, context=context)


def _failure(
    request: InvestigationRequest,
    *,
    agent: str,
    reason: str,
) -> SpecialistResponse:
    """Build a structured failure response with no fabricated evidence."""
    return SpecialistResponse(
        request_id=request.request_id,
        agent=agent,
        success=False,
        failure_reason=reason,
    )
