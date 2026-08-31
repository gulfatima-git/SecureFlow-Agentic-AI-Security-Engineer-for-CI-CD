"""Application-controlled tool layer for the Dependency Agent.

This module implements the bounded tool set the Dependency Agent may request.
The LLM never executes these directly — the agent loop invokes them on the
LLM's behalf and their results are returned to the model as data.

Tools are restricted to dependency investigation: reading a dependency
manifest, running the deterministic dependency scanner, and searching source
code for package usage. There is NO arbitrary shell execution, NO unrestricted
command execution, and all reads/searches are confined to the repository root.

The deterministic scanner (``DependencyAnalyzer``) is the authoritative source
of vulnerability evidence; this layer never invents scanner output.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from src.agents.tools import AgentTools, ToolExecutionError
from src.models.code_finding import ToolCall, ToolResult
from src.models.repository import FileEntry
from src.models.security_finding import ScanResult, SecurityFinding
from src.tools.dependency_analyzer import DependencyAnalyzer
from src.tools.repository_ingestor import EXCLUDED_DIRS, SOURCE_EXTENSIONS

# Maximum characters in a single tool result returned to the model.
DEFAULT_MAX_TOOL_CONTENT = 200_000
# Maximum source lines returned per source-search hit.
DEFAULT_SEARCH_LINES_PER_FILE = 40
# Maximum total search results returned.
DEFAULT_SEARCH_MAX_RESULTS = 200

_ALLOWED_TOOLS = {"read_manifest", "run_dependency_scan", "search_source"}


class DependencyToolExecutionError(Exception):
    """Raised when a dependency tool cannot be executed safely."""

    pass


class DependencyAgentTools:
    """Provides the bounded, safe tool set for the Dependency Agent.

    Args:
        repository_path: Absolute path to the repository root.
        dependency_analyzer: Optional existing ``DependencyAnalyzer`` to reuse.
            If None, one is created lazily (it queries the OSV API).
        context: Optional ``RepositoryContext`` used to inventory dependency and
            source files for manifest reads and source search.
        max_tool_content: Limit on characters in a single tool result.
        max_search_lines_per_file: Max matching lines returned per source file.
        max_search_results: Max total source-search results returned.
    """

    def __init__(
        self,
        repository_path: str | Path,
        *,
        dependency_analyzer: DependencyAnalyzer | None = None,
        context: object | None = None,
        max_tool_content: int = DEFAULT_MAX_TOOL_CONTENT,
        max_search_lines_per_file: int = DEFAULT_SEARCH_LINES_PER_FILE,
        max_search_results: int = DEFAULT_SEARCH_MAX_RESULTS,
    ) -> None:
        # Reuse the existing confined file reader for manifest/environment reads.
        self._reader = AgentTools(repository_path)
        self._root = self._reader.repository_path
        self._dependency_analyzer = dependency_analyzer
        self._max_tool_content = max_tool_content
        self._max_search_lines_per_file = max_search_lines_per_file
        self._max_search_results = max_search_results

        # Optional RepositoryContext for file inventory. If absent, the tool
        # layer discovers files directly from the filesystem.
        self._dependency_files: list[FileEntry] = []
        self._source_files: list[FileEntry] = []
        if context is not None:
            dep_files = getattr(context, "dependency_files", None)
            src_files = getattr(context, "source_files", None)
            if dep_files is not None:
                self._dependency_files = list(dep_files)
            if src_files is not None:
                self._source_files = list(src_files)

    @property
    def repository_path(self) -> Path:
        return self._root

    # -- Public execution entry point -------------------------------

    def execute(self, tool_call: ToolCall) -> ToolResult:
        """Execute a requested tool call, returning its structured result.

        Failures are surfaced as an ``ok=False`` result so the agent can reason
        over them, never as an uncontrolled crash for untrusted input.

        Raises:
            DependencyToolExecutionError: Only for internal misconfiguration,
                never for untrusted input.
        """
        if tool_call.name not in _ALLOWED_TOOLS:
            return ToolResult(
                name=tool_call.name,
                ok=False,
                error=f"Unknown or disallowed tool: {tool_call.name!r}",
            )

        try:
            if tool_call.name == "read_manifest":
                content = self.read_manifest(tool_call.arguments.get("path", ""))
                return ToolResult(name=tool_call.name, content=content)
            if tool_call.name == "run_dependency_scan":
                content = self.run_dependency_scan()
                return ToolResult(name=tool_call.name, content=content)
            if tool_call.name == "search_source":
                content = self.search_source(tool_call.arguments.get("query", ""))
                return ToolResult(name=tool_call.name, content=content)
        except (ToolExecutionError, DependencyToolExecutionError) as exc:
            return ToolResult(name=tool_call.name, ok=False, error=str(exc))

        return ToolResult(name=tool_call.name, ok=False, error="Unhandled tool")

    # -- Individual tools -------------------------------------------

    def read_manifest(self, rel_path: str) -> str:
        """Return the contents of a repository-relative dependency manifest.

        Confinement and never-execute guarantees are inherited from the shared
        file reader (``AgentTools``). Only the bytes are decoded and returned.

        Args:
            rel_path: A repository-relative path (e.g. ``requirements.txt``).

        Returns:
            The file contents (possibly truncated).
        """
        content = self._reader.read_file(rel_path)
        return self._truncate(content)

    def run_dependency_scan(self) -> str:
        """Request dependency vulnerability analysis.

        The deterministic ``DependencyAnalyzer`` is the authoritative evidence
        source. A missing scan result or tool failure is surfaced as a graceful
        controlled result so the agent sees an ``ok=False`` rather than a crash.

        Returns:
            Formatted dependency findings (package, version, vuln id, severity,
            fixed version) plus the scan status.
        """
        try:
            analyzer = self._dependency_analyzer or DependencyAnalyzer()
            result = analyzer.scan(self._root)
        except Exception as exc:  # noqa: BLE001 - any analyzer failure is controlled
            raise DependencyToolExecutionError(f"Dependency scan unavailable: {exc}")
        content = _dependency_result_to_text(result)
        return self._truncate(content)

    def search_source(self, query: str) -> str:
        """Search source files for usage of a dependency/package.

        The search is confined to the repository root, matches the query
        case-insensitively against each source file's lines, and returns
        bounded matching lines with surrounding context so the agent can judge
        whether a dependency is actually imported/used.

        Args:
            query: A package name or import token (e.g. ``requests``).

        Returns:
            A summary of matching files and lines (possibly truncated), or a
            message stating no usage was found.
        """
        if not isinstance(query, str) or not query.strip():
            return "(search_source requires a non-empty 'query' argument)\n"

        needle = query.strip().lower()
        files = self._source_files or self._discover_source_files()

        results: list[str] = []
        total_hits = 0
        for entry in files:
            display = _posix_path(entry.path)
            path = self._confine(entry.path)
            if path is None:
                continue
            try:
                raw = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            matched_lines = [
                (idx, line)
                for idx, line in enumerate(raw.splitlines(), start=1)
                if needle in line.lower()
            ]
            if not matched_lines:
                continue
            shown = matched_lines[: self._max_search_lines_per_file]
            total_hits += len(shown)
            header = f"[{display}] contains {len(matched_lines)} matching line(s):"
            block = [f"  {lineno}: {line.strip()}" for lineno, line in shown]
            results.append("\n".join([header] + block))

            if total_hits >= self._max_search_results:
                break

        if not results:
            return (
                f"[search_source] no source usage found for {query!r} "
                "in the repository\n"
            )

        body = "[search_source] matches:\n" + "\n".join(results)
        if total_hits > self._max_search_results:
            body += f"\n...[truncated: more than {self._max_search_results} results]"
        return self._truncate(body)

    # -- Internal helpers -------------------------------------------

    def _discover_source_files(self) -> list[FileEntry]:
        """Enumerate repository source files, honoring existing exclusions."""
        from src.models.repository import FileCategory

        entries: list[FileEntry] = []
        for item in sorted(self._root.rglob("*")):
            if not item.is_file():
                continue
            rel = item.relative_to(self._root)
            if _is_excluded_source_path(rel):
                continue
            if item.suffix.lower() in SOURCE_EXTENSIONS:
                entries.append(
                    FileEntry(
                        path=_posix_path(str(rel)),
                        category=FileCategory.SOURCE,
                        extension=item.suffix.lower(),
                    )
                )
        return entries

    def _confine(self, rel_path: str) -> Path | None:
        """Resolve a repo-relative path and confirm it stays inside the root."""
        if not rel_path:
            return None
        if rel_path.startswith("\\") or re.match(r"^[a-zA-Z]:", rel_path):
            return None
        candidate = (self._root / rel_path).resolve()
        if self._root not in candidate.parents and candidate != self._root:
            return None
        if not candidate.is_file():
            return None
        return candidate

    def _truncate(self, content: str) -> str:
        if len(content) <= self._max_tool_content:
            return content
        return (
            content[: self._max_tool_content]
            + f"\n...[truncated: result exceeds {self._max_tool_content} characters]"
        )


def _posix_path(value: str) -> str:
    """Normalize a repo-relative path to forward slashes for stable output."""
    return value.replace(os.sep, "/") if os.sep != "/" else value


def _is_excluded_source_path(rel: Path) -> bool:
    """Check whether a relative source path is in an excluded directory."""
    for part in rel.parts:
        if part in EXCLUDED_DIRS:
            return True
        if part.endswith(".egg-info"):
            return True
    return False


def _dependency_result_to_text(result: ScanResult) -> str:
    """Format a dependency ``ScanResult`` as compact evidence text for the model."""
    lines: list[str] = [f"[dependency-analyzer] status={result.status}"]
    if result.error_message:
        lines.append(f"[dependency-analyzer] info={result.error_message}")

    for finding in result.findings:
        lines.append(_dependency_finding_line(finding))

    if not result.findings:
        lines.append("[dependency-analyzer] no dependency vulnerabilities found")

    return "\n".join(lines)


def _dependency_finding_line(f: SecurityFinding) -> str:
    """Render a single dependency finding as a compact evidence line."""
    sev = f.severity.value if f.severity else "unknown"
    pkg = f.package_name or ""
    declared = f.declared_version or "-"
    resolved = f.resolved_version or "-"
    vuln_id = f.rule_id or f.metadata.get("osv_id", "-")
    fixed = f.metadata.get("fixed_version", "")
    fixed_part = f" fixed={fixed}" if fixed else ""
    message = f.message or ""
    return (
        f"[dependency-analyzer] severity={sev} package={pkg} "
        f"declared={declared} resolved={resolved} vuln={vuln_id}"
        f"{fixed_part} manifest={f.file_path or '-'} :: {message}"
    )
