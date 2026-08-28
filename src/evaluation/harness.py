"""Evaluation harness for the Step 12 Code Security Agent baseline.

The harness runs the *existing* :class:`CodeSecurityAgent` against each
controlled fixture using a caller-supplied ``LLMProvider`` and scores the
result against the fixture's ground truth. It is shared by deterministic
tests (which inject a ``FakeLLM``) and the optional real-LLM entry point.

The harness adds NO behavior to the agent itself; it only drives, records, and
scores it. Repository fixtures are untrusted input and are never executed.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from src.agents import AgentTerminatedError, CodeSecurityAgent
from src.evaluation.ground_truth import ALL_CASE_NAMES, EVAL_CASES
from src.evaluation.scoring import EvaluationResult, score_case
from src.llm.base import LLMProvider
from src.models.repository import FileCategory, FileEntry, RepositoryContext
from src.tools.bandit_runner import BanditError, BanditRunner
from src.tools.semgrep_runner import SemgrepError, SemgrepRunner


class EvaluationError(Exception):
    """Raised when the evaluation harness cannot run a case."""


def optional_tool_output(root: Path, tool: str) -> list[str]:
    """Collect available deterministic tool output for the fixture.

    Offline-safe: a missing analyzer yields no output rather than failing.
    Returns a list of textual evidence lines from the tool, if any.
    """
    tool_text: list[str] = []
    try:
        if tool == "bandit":
            result = BanditRunner().scan(root)
        else:
            result = SemgrepRunner().scan(root)
    except (BanditError, SemgrepError):
        return tool_text

    if getattr(result, "status", "success") != "success":
        return tool_text

    for f in getattr(result, "findings", []) or []:
        tool_text.append(f"[{tool}] {f.severity.value} rule={f.rule_id} {f.message}")
    return tool_text


def collect_tool_output(root: Path) -> list[str]:
    """Collect both Semgrep and Bandit output for the fixture, if available."""
    return optional_tool_output(root, "semgrep") + optional_tool_output(root, "bandit")


def build_context(repository_path: Path, fixture_name: str) -> RepositoryContext:
    """Build a :class:`RepositoryContext` from a fixture directory.

    The fixtures are not Git repositories, so the context is constructed
    directly (mirroring repository ingestion) instead of via
    :class:`RepositoryIngestor`, which requires a Git checkout.
    """
    source_files: list[FileEntry] = []
    for py in sorted(repository_path.rglob("*.py")):
        if any(part in {".git", "__pycache__"} for part in py.parts):
            continue
        rel = py.relative_to(repository_path).as_posix()
        source_files.append(FileEntry(path=rel, category=FileCategory.SOURCE))
    return RepositoryContext(
        repository_name=fixture_name,
        repository_url=f"file:///{repository_path}",
        local_path=str(repository_path),
        commit_sha="0" * 40,
        source_files=source_files,
    )


def run_evaluation(
    fixture_dir: Path,
    provider_factory: Callable[[], LLMProvider],
    *,
    max_iterations: int = 10,
    max_tool_calls: int = 15,
    fixtures: list[str] | None = None,
) -> list[EvaluationResult]:
    """Run each evaluation case through the agent and return a scorecard.

    Args:
        fixture_dir: Root directory containing ``case_a`` ... ``case_e``.
        provider_factory: Callable returning a fresh ``LLMProvider`` per case
            (so each case gets an independent conversation).
        max_iterations: Agent loop bound.
        max_tool_calls: Agent tool-call bound.
        fixtures: Optional subset of fixture names to run.

    Returns:
        A list of :class:`EvaluationResult`, one per case.
    """
    names = fixtures or list(ALL_CASE_NAMES)
    for name in names:
        if name not in EVAL_CASES:
            raise EvaluationError(f"Unknown evaluation fixture: {name}")
        root = fixture_dir / name
        if not root.is_dir():
            raise EvaluationError(f"Fixture directory missing: {root}")

    results: list[EvaluationResult] = []
    for name in names:
        root = fixture_dir / name
        provider = provider_factory()
        agent = CodeSecurityAgent(
            provider,
            root,
            context=build_context(root, name),
            max_iterations=max_iterations,
            max_tool_calls=max_tool_calls,
        )

        tool_calls_used = 0
        iterations_used = 0
        terminated = False
        reason = ""
        finding = None

        try:
            outcome = agent.investigate()
            finding = outcome.finding
            tool_calls_used = outcome.tool_calls_used
            iterations_used = outcome.iterations_used
        except AgentTerminatedError as exc:
            terminated = True
            reason = exc.reason
            tool_calls_used = exc.tool_calls_used
            iterations_used = exc.steps_used

        results.append(
            score_case(
                root,
                name,
                finding,
                tool_calls_used=tool_calls_used,
                iterations_used=iterations_used,
                terminated=terminated,
                termination_reason=reason,
                extra_corpus=collect_tool_output(root),
            )
        )
    return results
