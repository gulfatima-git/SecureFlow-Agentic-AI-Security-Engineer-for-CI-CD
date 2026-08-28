"""Application-controlled tool layer for the Code Security Agent.

This module implements the four tools the LLM may request. The LLM never
executes these directly — the agent loop invokes them on the LLM's behalf,
and their results are returned to the model as data.

All tools treat repository contents as untrusted input and enforce strict
safety boundaries (path confinement, no code execution, bounded output).
"""

from __future__ import annotations

import re
from pathlib import Path

from src.models.code_finding import ToolCall, ToolResult
from src.tools.bandit_runner import BanditError, BanditRunner
from src.tools.repository_ingestor import RepositoryIngestor
from src.tools.semgrep_runner import SemgrepError, SemgrepRunner

# Maximum characters of file content returned to the model.
DEFAULT_MAX_FILE_BYTES = 200_000
# Maximum characters of a single tool result returned to the model.
DEFAULT_MAX_TOOL_CONTENT = 200_000

_ALLOWED_TOOLS = {"read_file", "get_diff", "run_semgrep", "run_bandit"}


class ToolExecutionError(Exception):
    """Raised when a requested tool cannot be executed safely."""


class AgentTools:
    """Provides the bounded, safe tool set for the Code Security Agent.

    Args:
        repository_path: Absolute path to the repository root.
        semgrep_runner: Optional existing ``SemgrepRunner`` to reuse. If None,
            one is created lazily.
        bandit_runner: Optional existing ``BanditRunner`` to reuse. If None,
            one is created lazily.
        repository_ingestor: Optional ingestor used to produce the diff.
        max_file_bytes: Limit on bytes read from a single file.
        max_tool_content: Limit on characters in a single tool result.
    """

    def __init__(
        self,
        repository_path: str | Path,
        *,
        semgrep_runner: SemgrepRunner | None = None,
        bandit_runner: BanditRunner | None = None,
        repository_ingestor: RepositoryIngestor | None = None,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_tool_content: int = DEFAULT_MAX_TOOL_CONTENT,
    ) -> None:
        root = Path(repository_path)
        root = root.resolve()
        if not root.is_dir():
            raise ToolExecutionError(
                f"Repository path does not exist or is not a directory: {root}"
            )
        self._root = root
        self._semgrep_runner = semgrep_runner
        self._bandit_runner = bandit_runner
        self._ingestor = repository_ingestor
        self._max_file_bytes = max_file_bytes
        self._max_tool_content = max_tool_content

    @property
    def repository_path(self) -> Path:
        return self._root

    # -- Public execution entry point -------------------------------

    def execute(self, tool_call: ToolCall) -> ToolResult:
        """Execute a requested tool call, returning its structured result.

        Args:
            tool_call: The tool invocation requested by the LLM.

        Returns:
            A ``ToolResult``. Never raises for untrusted input; failures are
            surfaced as an ``ok=False`` result so the agent can reason over it.

        Raises:
            ToolExecutionError: Only for internal misconfiguration, never for
                untrusted input.
        """
        if tool_call.name not in _ALLOWED_TOOLS:
            return ToolResult(
                name=tool_call.name,
                ok=False,
                error=f"Unknown or disallowed tool: {tool_call.name!r}",
            )

        try:
            if tool_call.name == "read_file":
                content = self.read_file(tool_call.arguments.get("path", ""))
                return ToolResult(name=tool_call.name, content=content)
            if tool_call.name == "get_diff":
                content = self.get_diff()
                return ToolResult(name=tool_call.name, content=content)
            if tool_call.name == "run_semgrep":
                content = self.run_semgrep()
                return ToolResult(name=tool_call.name, content=content)
            if tool_call.name == "run_bandit":
                content = self.run_bandit()
                return ToolResult(name=tool_call.name, content=content)
        except ToolExecutionError as exc:
            return ToolResult(name=tool_call.name, ok=False, error=str(exc))

        return ToolResult(name=tool_call.name, ok=False, error="Unhandled tool")

    # -- Individual tools -------------------------------------------

    def read_file(self, rel_path: str) -> str:
        """Return the contents of a repository-relative source file.

        The path is confined to the repository root. Path traversal (``..``),
        absolute paths, and symlinks escaping the root are rejected. The file
        is never executed — only its bytes are read.

        Args:
            rel_path: A repository-relative path.

        Returns:
            The file contents (possibly truncated).

        Raises:
            ToolExecutionError: If the path is unsafe or unreadable.
        """
        path = self._confine_path(rel_path)
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            raise ToolExecutionError(f"File not found: {rel_path}")
        except OSError as exc:
            raise ToolExecutionError(f"Cannot read {rel_path}: {exc}")

        if len(data) > self._max_file_bytes:
            data = data[: self._max_file_bytes]
            return (
                data.decode("utf-8", errors="replace")
                + f"\n...[truncated: file exceeds {self._max_file_bytes} bytes]"
            )
        return data.decode("utf-8", errors="replace")

    def get_diff(self) -> str:
        """Return the current repository working-tree diff.

        Reuses the repository-ingestion diff extraction rather than
        duplicating Git logic. If the path is not a Git repository (or has no
        commits yet), an empty diff is returned rather than raising, because a
        missing diff is not a security consideration.
        """
        try:
            from git import GitCommandError, InvalidGitRepositoryError, Repo

            repo = Repo(self._root)
            try:
                diff: str = repo.git.diff("HEAD")
            except GitCommandError:
                diff = ""
            return self._truncate(diff)
        except (GitCommandError, InvalidGitRepositoryError, OSError):
            return "(repository has no diff available)\n"

    def run_semgrep(self) -> str:
        """Request static analysis via the existing ``SemgrepRunner``.

        A missing binary or temporary tool failure is surfaced as a graceful
        ``ToolExecutionError`` so the agent (and callers) see an ``ok=False``
        result rather than an unhandled crash.
        """
        try:
            runner = self._semgrep_runner or SemgrepRunner()
            result = runner.scan(self._root)
        except SemgrepError as exc:
            raise ToolExecutionError(f"Semgrep unavailable: {exc}")
        content = _scan_result_to_text("semgrep", result)
        return self._truncate(content)

    def run_bandit(self) -> str:
        """Request Python security analysis via the existing ``BanditRunner``."""
        try:
            runner = self._bandit_runner or BanditRunner()
            result = runner.scan(self._root)
        except BanditError as exc:
            raise ToolExecutionError(f"Bandit unavailable: {exc}")
        content = _scan_result_to_text("bandit", result)
        return self._truncate(content)

    # -- Internal helpers -------------------------------------------

    def _confine_path(self, rel_path: str) -> Path:
        """Resolve ``rel_path`` and ensure it stays inside the repository root."""
        if not isinstance(rel_path, str) or not rel_path:
            raise ToolExecutionError("read_file requires a non-empty 'path' argument")

        invalid = rel_path.startswith("\\") or re.match(r"^[a-zA-Z]:", rel_path)
        if invalid:
            raise ToolExecutionError("Absolute paths are not allowed")

        candidate = (self._root / rel_path).resolve()
        if self._root not in candidate.parents and candidate != self._root:
            raise ToolExecutionError(f"Path escapes repository root: {rel_path}")

        if not candidate.is_file():
            raise ToolExecutionError(f"Not a regular file: {rel_path}")

        return candidate

    def _truncate(self, content: str) -> str:
        if len(content) <= self._max_tool_content:
            return content
        return (
            content[: self._max_tool_content]
            + f"\n...[truncated: result exceeds {self._max_tool_content} characters]"
        )


def _scan_result_to_text(tool_name: str, result: object) -> str:
    """Format a deterministic ``ScanResult`` as compact text for the model."""
    findings = getattr(result, "findings", None)
    status = getattr(result, "status", "success")
    error_message = getattr(result, "error_message", "")

    lines: list[str] = [f"[{tool_name}] status={status}"]
    if error_message:
        lines.append(f"[{tool_name}] error={error_message}")

    if findings is None:
        lines.append(f"[{tool_name}] no finding model in result")
        return "\n".join(lines)

    if not findings:
        lines.append(f"[{tool_name}] no findings")
        return "\n".join(lines)

    for f in findings:
        sev = getattr(f, "severity", None)
        conf = getattr(f, "confidence", None)
        rule = getattr(f, "rule_id", "")
        file_path = getattr(f, "file_path", "")
        line = getattr(f, "start_line", 0)
        msg = getattr(f, "message", "")
        lines.append(
            f"[{tool_name}] {sev} (confidence={conf}) rule={rule} "
            f"file={file_path}:{line} :: {msg}"
        )
    return "\n".join(lines)
