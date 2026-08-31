"""Application-controlled tool layer for the CI/CD Security Agent.

This module implements the bounded tool set the CI/CD Security Agent may
request. The LLM never executes these directly — the agent loop invokes them on
the LLM's behalf and their results are returned to the model as data.

Tools are restricted to CI/CD/deployment investigation: listing relevant
configuration files, reading an allowed configuration file, running the
deterministic CI/CD analyzer, and searching CI/CD configuration for a token.
There is NO arbitrary shell execution, NO subprocess/Docker/kubectl/cloud CLI
execution, and all reads/searches are confined to the repository root. The
deterministic analyzer (``CICDAnalyzer``) is the authoritative finding source;
this layer never invents analyzer output.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from src.agents.tools import AgentTools, ToolExecutionError
from src.models.code_finding import ToolCall, ToolResult
from src.models.repository import FileEntry
from src.models.security_finding import ScanResult, SecurityFinding
from src.tools.cicd_analyzer import CICDAnalyzer
from src.tools.repository_ingestor import EXCLUDED_DIRS

# Maximum characters in a single tool result returned to the model.
DEFAULT_MAX_TOOL_CONTENT = 200_000
# Maximum source lines returned per search hit.
DEFAULT_SEARCH_LINES_PER_FILE = 40
# Maximum total search results returned.
DEFAULT_SEARCH_MAX_RESULTS = 200

_ALLOWED_TOOLS = {"list_cicd_files", "read_cicd_file", "analyze_cicd", "search_cicd"}

# CI/CD configuration filenames (Docker / compose / simple CI).
_CICD_FILENAMES: set[str] = {
    "Dockerfile",
    "Dockerfile.yaml",
    "Dockerfile.yml",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".dockerignore",
    "Makefile",
    "Procfile",
    "Vagrantfile",
    ".travis.yml",
    ".gitlab-ci.yml",
    "appveyor.yml",
    "azure-pipelines.yml",
    "buildspec.yml",
    "cloudbuild.yaml",
}

# Directories whose contents are CI/CD configuration.
_CICD_DIRS: set[str] = {".github", ".gitlab-ci", ".circleci"}

# Deployment/container config file extensions (YAML family).
_DEPLOYMENT_EXTENSIONS: set[str] = {".yml", ".yaml"}


class CICDToolExecutionError(Exception):
    """Raised when a CI/CD tool cannot be executed safely."""

    pass


class CICDSecurityAgentTools:
    """Provides the bounded, safe tool set for the CI/CD Security Agent.

    Args:
        repository_path: Absolute path to the repository root.
        cicd_analyzer: Optional existing ``CICDAnalyzer`` to reuse. If None,
            one is created lazily.
        context: Optional ``RepositoryContext`` used to inventory CI/CD files.
        max_tool_content: Limit on characters in a single tool result.
        max_search_lines_per_file: Max matching lines returned per file.
        max_search_results: Max total search results returned.
    """

    def __init__(
        self,
        repository_path: str | Path,
        *,
        cicd_analyzer: CICDAnalyzer | None = None,
        context: object | None = None,
        max_tool_content: int = DEFAULT_MAX_TOOL_CONTENT,
        max_search_lines_per_file: int = DEFAULT_SEARCH_LINES_PER_FILE,
        max_search_results: int = DEFAULT_SEARCH_MAX_RESULTS,
    ) -> None:
        # Reuse the existing confined file reader for configuration reads.
        self._reader = AgentTools(repository_path)
        self._root = self._reader.repository_path
        self._cicd_analyzer = cicd_analyzer
        self._max_tool_content = max_tool_content
        self._max_search_lines_per_file = max_search_lines_per_file
        self._max_search_results = max_search_results

        self._cicd_files: list[FileEntry] = []
        if context is not None:
            cicd_files = getattr(context, "cicd_files", None)
            if cicd_files is not None:
                self._cicd_files = list(cicd_files)

    @property
    def repository_path(self) -> Path:
        return self._root

    # -- Public execution entry point -------------------------------

    def execute(self, tool_call: ToolCall) -> ToolResult:
        """Execute a requested tool call, returning its structured result.

        Failures are surfaced as an ``ok=False`` result so the agent can reason
        over them, never as an uncontrolled crash for untrusted input.

        Raises:
            CICDToolExecutionError: Only for internal misconfiguration, never
                for untrusted input.
        """
        if tool_call.name not in _ALLOWED_TOOLS:
            return ToolResult(
                name=tool_call.name,
                ok=False,
                error=f"Unknown or disallowed tool: {tool_call.name!r}",
            )

        try:
            if tool_call.name == "list_cicd_files":
                content = self.list_cicd_files()
                return ToolResult(name=tool_call.name, content=content)
            if tool_call.name == "read_cicd_file":
                content = self.read_cicd_file(tool_call.arguments.get("path", ""))
                return ToolResult(name=tool_call.name, content=content)
            if tool_call.name == "analyze_cicd":
                content = self.analyze_cicd()
                return ToolResult(name=tool_call.name, content=content)
            if tool_call.name == "search_cicd":
                content = self.search_cicd(tool_call.arguments.get("query", ""))
                return ToolResult(name=tool_call.name, content=content)
        except (ToolExecutionError, CICDToolExecutionError) as exc:
            return ToolResult(name=tool_call.name, ok=False, error=str(exc))

        return ToolResult(name=tool_call.name, ok=False, error="Unhandled tool")

    # -- Individual tools -------------------------------------------

    def list_cicd_files(self) -> str:
        """Return the repository's CI/CD and deployment configuration files."""
        entries = self._cicd_files or self._discover_ci_cd_files()
        if not entries:
            return "(no CI/CD or deployment configuration files found)\n"
        paths = "\n".join(f"- {_posix_path(e.path)}" for e in entries)
        return f"[cicd] relevant configuration files:\n{paths}"

    def read_cicd_file(self, rel_path: str) -> str:
        """Return the contents of an allowed CI/CD/deployment file.

        The path must be a repository-relative CI/CD configuration file. It is
        validated against the CI/CD allow-list and then read through the shared
        confined reader (never executed).

        Args:
            rel_path: A repository-relative path to an allowed file.

        Returns:
            The file contents (possibly truncated).
        """
        if not isinstance(rel_path, str) or not rel_path:
            raise CICDToolExecutionError("read_cicd_file requires a non-empty 'path'")
        if not self._is_allowed_cicd_path(rel_path):
            raise CICDToolExecutionError(
                f"Not an allowed CI/CD/deployment configuration file: {rel_path!r}"
            )
        content = self._reader.read_file(rel_path)
        return self._truncate(content)

    def analyze_cicd(self) -> str:
        """Run the deterministic CI/CD analyzer over the repository.

        The existing ``CICDAnalyzer`` is the authoritative evidence source. A
        missing analyzer or tool failure is surfaced as a graceful controlled
        result so the agent sees an ``ok=False`` rather than a crash.

        Returns:
            Formatted deterministic CI/CD findings plus the scan status.
        """
        try:
            analyzer = self._cicd_analyzer or CICDAnalyzer()
            result = analyzer.analyze(self._root)
        except Exception as exc:  # noqa: BLE001 - any analyzer failure is controlled
            raise CICDToolExecutionError(f"CICD analyzer unavailable: {exc}")
        return self._truncate(_cicd_result_to_text(result))

    def search_cicd(self, query: str) -> str:
        """Search CI/CD/deployment configuration for a token.

        The search is confined to the repository root, matches the query
        case-insensitively against each allowed CI/CD file's lines, and returns
        bounded matching lines as data only.

        Args:
            query: A config token to search for (e.g. ``permissions``).

        Returns:
            A summary of matching files and lines, or a no-match message.
        """
        if not isinstance(query, str) or not query.strip():
            return "(search_cicd requires a non-empty 'query' argument)\n"

        needle = query.strip().lower()
        files = self._cicd_files or self._discover_ci_cd_files()

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
                f"[search_cicd] no CI/CD configuration match for {query!r} "
                "in the repository\n"
            )

        body = "[search_cicd] matches:\n" + "\n".join(results)
        if total_hits > self._max_search_results:
            body += f"\n...[truncated: more than {self._max_search_results} results]"
        return self._truncate(body)

    # -- Internal helpers -------------------------------------------

    def _discover_ci_cd_files(self) -> list[FileEntry]:
        """Enumerate repository CI/CD and deployment configuration files."""
        from src.models.repository import FileCategory

        entries: list[FileEntry] = []
        for item in sorted(self._root.rglob("*")):
            if not item.is_file():
                continue
            rel = item.relative_to(self._root)
            if _is_excluded_path(rel):
                continue
            if self._is_allowed_cicd_path(str(rel)):
                entries.append(
                    FileEntry(
                        path=_posix_path(str(rel)),
                        category=FileCategory.CICD,
                        extension=item.suffix.lower(),
                    )
                )
        return entries

    def _is_allowed_cicd_path(self, rel_path: str) -> bool:
        """Return True if a repo-relative path is allowed CI/CD/deployment config."""
        normalized = rel_path.replace("\\", "/")
        if normalized.startswith("/"):
            return False
        parts = normalized.split("/")
        name = parts[-1]

        # CI/CD directories (e.g. .github, .circleci, .gitlab-ci).
        if any(p in _CICD_DIRS for p in parts):
            return True
        # Known CI/CD filenames (Dockerfile family, compose, simple CI).
        if name in _CICD_FILENAMES:
            return True
        if name.startswith("Dockerfile"):
            return True
        # Deployment/container YAML config.
        if Path(name).suffix.lower() in _DEPLOYMENT_EXTENSIONS:
            return True
        return False

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


def _is_excluded_path(rel: Path) -> bool:
    """Check whether a relative path is in an excluded directory."""
    for part in rel.parts:
        if part in EXCLUDED_DIRS:
            return True
        if part.endswith(".egg-info"):
            return True
    return False


def _cicd_result_to_text(result: ScanResult) -> str:
    """Format a CI/CD ``ScanResult`` as compact evidence text for the model."""
    lines: list[str] = [f"[cicd-analyzer] status={result.status}"]
    if result.error_message:
        lines.append(f"[cicd-analyzer] info={result.error_message}")

    for finding in result.findings:
        lines.append(_cicd_finding_line(finding))

    if not result.findings:
        lines.append("[cicd-analyzer] no CI/CD security findings")

    return "\n".join(lines)


def _cicd_finding_line(f: SecurityFinding) -> str:
    """Render a single CI/CD finding as a compact evidence line."""
    sev = f.severity.value if f.severity else "unknown"
    rule = f.rule_id or "-"
    loc = _posix_path(f.file_path or "")
    line = f.start_line or 0
    message = f.message or ""
    return f"[cicd-analyzer] severity={sev} rule={rule} file={loc}:{line} :: {message}"
