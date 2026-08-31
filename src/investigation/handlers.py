"""Default specialist capabilities for collaboration (Step 17).

These handlers implement the request types in the per-agent allow-list using
the existing deterministic tool layers (``AgentTools``,
``DependencyAgentTools``, ``CICDSecurityAgentTools``). They produce *real*
structured evidence from repository content via the safe, confined tool layers —
they never fabricate evidence and never execute anything.

Every handler returns a :class:`SpecialistResponse`. Failures (missing path,
tool error) are surfaced as ``success=False`` by the collaboration interface,
never as invented evidence.
"""

from __future__ import annotations

from pathlib import Path

from src.agents.cicd_tools import CICDSecurityAgentTools
from src.agents.dependency_tools import DependencyAgentTools
from src.agents.tools import AgentTools
from src.investigation.collaboration import SpecialistHandler, SpecialistRegistry
from src.investigation.models import InvestigationRequest, SpecialistResponse
from src.models.finding import AgentName, EvidenceItem, EvidenceKind
from src.models.repository import FileEntry, RepositoryContext


def build_default_registry(
    *,
    repository_path: str | Path | None,
    context: RepositoryContext | None,
) -> SpecialistRegistry:
    """Build real specialist capabilities reusing the existing tool layers."""
    if repository_path is None and context is not None:
        repository_path = context.local_path
    if repository_path is None:
        raise ValueError(
            "A repository_path (or context with local_path) is required to "
            "build real specialist capabilities"
        )

    root = Path(repository_path)
    reader = AgentTools(root)
    dep_tools = DependencyAgentTools(root, context=context)
    cicd_tools = CICDSecurityAgentTools(root, context=context)

    source_files = list(context.source_files) if context else []

    code: dict[str, SpecialistHandler] = {
        "source_context": _read_source(reader),
        "symbol_usage": _search_source(dep_tools),
        "related_files": _list_source_files(source_files),
    }
    dependency: dict[str, SpecialistHandler] = {
        "dependency_usage": _search_source(dep_tools),
        "dependency_details": _read_manifest(dep_tools, context),
        "affected_component": _list_source_files(source_files),
    }
    cicd: dict[str, SpecialistHandler] = {
        "workflow_context": _read_cicd(cicd_tools),
        "permission_context": _search_cicd(cicd_tools),
        "deployment_context": _read_cicd(cicd_tools),
    }

    return {
        AgentName.CODE_SECURITY.value: code,
        AgentName.DEPENDENCY.value: dependency,
        AgentName.CICD.value: cicd,
    }


# -- Handler factories ------------------------------------------


def _read_source(reader: AgentTools) -> SpecialistHandler:
    def handle(request: InvestigationRequest) -> SpecialistResponse:
        path = request.query
        if not path:
            return _failure(request, reason="source_context requires a file path in 'query'")
        content = reader.read_file(path)
        return _observed(request, content, source="code:source_context")

    return handle


def _search_source(dep_tools: DependencyAgentTools) -> SpecialistHandler:
    def handle(request: InvestigationRequest) -> SpecialistResponse:
        token = request.query
        if not token:
            return _failure(request, reason=f"{request.request_type} requires a token in 'query'")
        content = dep_tools.search_source(token)
        return _observed(request, content, source=f"code/dependency:{request.request_type}")

    return handle


def _list_source_files(source_files: list[FileEntry]) -> SpecialistHandler:
    def handle(request: InvestigationRequest) -> SpecialistResponse:
        if not source_files:
            return _observed(
                request,
                "(no source file inventory available)",
                source="code:related_files",
                success=True,
            )
        paths = "\n".join(f"- {e.path}" for e in source_files)
        return _observed(request, f"[source inventory] available source files:\n{paths}",
                         source="code:related_files")

    return handle


def _read_manifest(
    dep_tools: DependencyAgentTools, context: RepositoryContext | None
) -> SpecialistHandler:
    def handle(request: InvestigationRequest) -> SpecialistResponse:
        path = request.query
        if not path and context and context.dependency_files:
            path = context.dependency_files[0].path
        if not path:
            return _failure(
                request,
                reason="dependency_details requires a manifest path in 'query'",
            )
        content = dep_tools.read_manifest(path)
        return _observed(request, content, source="dependency:dependency_details")

    return handle


def _read_cicd(cicd_tools: CICDSecurityAgentTools) -> SpecialistHandler:
    def handle(request: InvestigationRequest) -> SpecialistResponse:
        path = request.query
        if not path:
            return _failure(
                request,
                reason=f"{request.request_type} requires a config path in 'query'",
            )
        content = cicd_tools.read_cicd_file(path)
        return _observed(request, content, source=f"cicd:{request.request_type}")

    return handle


def _search_cicd(cicd_tools: CICDSecurityAgentTools) -> SpecialistHandler:
    def handle(request: InvestigationRequest) -> SpecialistResponse:
        token = request.query or "permissions"
        content = cicd_tools.search_cicd(token)
        return _observed(request, content, source="cicd:permission_context")

    return handle


# -- Response builders -----------------------------------------


def _observed(
    request: InvestigationRequest,
    content: str,
    *,
    source: str,
    success: bool = True,
) -> SpecialistResponse:
    return SpecialistResponse(
        request_id=request.request_id,
        agent=request.target_agent,
        success=success,
        evidence=[EvidenceItem(kind=EvidenceKind.OBSERVED, content=content, source=source)],
        related_finding_ids=list(request.context_finding_ids),
        explanation=_request_echo(request),
    )


def _failure(request: InvestigationRequest, *, reason: str) -> SpecialistResponse:
    return SpecialistResponse(
        request_id=request.request_id,
        agent=request.target_agent,
        success=False,
        failure_reason=reason,
        metadata={"request_type": request.request_type},
    )


def _request_echo(request: InvestigationRequest) -> str:
    return f"specialist response for {request.request_type} on {request.target_agent}"
