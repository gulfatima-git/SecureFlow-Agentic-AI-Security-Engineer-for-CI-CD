"""Scoring functions for the Step 12 Code Security Agent evaluation.

The metrics distinguish *observed evidence* (repository content and
deterministic tool output) from the *agent's interpretation/reasoning*. The
agent is allowed to reason beyond raw evidence, but it must not present
invented evidence or claim a scanner reported something it did not.

Semantics (kept explicit to avoid misunderstanding):

* ``passed`` — CORE investigation success. For a vulnerable repo this is
  ``detection and localization and evidence_grounded``. For the safe repo it is
  ``not hallucination``. It intentionally does NOT include ``severity_ok``.
* ``severity_ok`` — an INDEPENDENT dimension: whether the reported severity is
  within the case's acceptable range. It is not part of ``passed``.
* ``confidence`` — an independent recorded metric (0-1). It is recorded, never
  treated as automatically correct.
* ``hallucination`` — an unsupported claim (safe-repo assertion, or fabricated
  evidence in a vulnerable repo).

Evidence grounding here is a **lexical grounding proxy**, NOT provenance
tracking: an evidence string is grounded if it appears, case-insensitively,
somewhere in the observed corpus. It does NOT prove the finding was derived
from that evidence (that would require provenance tracking, which is not
implemented yet). See also ``docs/code-agent-evaluation.md``.

This module is intentionally heuristic and per-case (not a fixed global
classifier), because each fixture has a known intended vulnerability.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from src.evaluation.ground_truth import GroundTruth
from src.models.code_finding import CodeFinding


class EvaluationResult(BaseModel):
    """Inspectable outcome for a single evaluation case.

    Field semantics:
        passed: Core investigation success (detection + localization +
            evidence grounding for vulnerable repos; no hallucination for the
            safe repo). Does NOT depend on ``severity_ok`` or ``confidence``.
        severity_ok: Independent dimension — whether the reported severity is in
            the case's acceptable range.
        confidence: Independent recorded metric (0-1); recorded, not judged.
        hallucination: Unsupported claim (safe-repo assertion or fabricated
            evidence in a vulnerable repo).
        evidence_grounded: Lexical grounding proxy — whether each evidence
            entry appears verbatim (case-insensitive) in the observed corpus.
    """

    fixture: str
    category_expected: str
    detection: bool = False
    localization: bool = False
    localization_line: int = 0
    evidence_grounded: bool = False
    grounded_entries: list[str] = Field(default_factory=list)
    ungrounded_entries: list[str] = Field(default_factory=list)
    hallucination: bool = False
    severity_ok: bool = False
    confidence: float = 0.0
    file: str = ""
    line: int = 0
    description: str = ""
    evidence: list[str] = Field(default_factory=list)
    tool_calls_used: int = 0
    iterations_used: int = 0
    terminated: bool = False
    termination_reason: str = ""
    passed: bool = False

    def to_dict(self) -> dict[str, object]:
        return self.model_dump()


def combined_finding_text(finding: CodeFinding) -> str:
    """Return the agent's own text: description + file + evidence.

    This is the *interpretation* surface we classify against. It is kept
    separate from the raw evidence corpus.
    """
    parts = [finding.description or "", finding.file or ""]
    parts.extend(finding.evidence)
    return " ".join(parts).lower()


def collect_corpus(repository_root: Path) -> list[str]:
    """Collect the observed evidence available to judge grounding.

    This is the repository's source text (untrusted input, treated as data)
    plus any deterministic tool output for the repo. It reflects what a
    grounded finding may legitimately cite.
    """
    corpus: list[str] = []
    for py in sorted(repository_root.rglob("*.py")):
        if any(part in {".git", "__pycache__"} for part in py.parts):
            continue
        try:
            corpus.append(py.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return corpus


def is_evidence_grounded(
    evidence: list[str], corpus: list[str]
) -> tuple[bool, list[str], list[str]]:
    """Check each evidence entry against the observed corpus.

    IMPORTANT: this is a **lexical grounding proxy**, not provenance tracking.
    An entry is grounded if it appears (case-insensitively) somewhere in the
    repository content or tool output. A paraphrased-but-true statement that is
    not verbatim in the corpus would be flagged ungrounded, and a verbatim
    match does not prove the finding was actually derived from that source.
    Returns ``(all_grounded, grounded_entries, ungrounded_entries)``.
    """
    blob = "\n".join(corpus).lower()
    grounded: list[str] = []
    ungrounded: list[str] = []
    for entry in evidence:
        if entry and entry.lower() in blob:
            grounded.append(entry)
        else:
            ungrounded.append(entry)
    all_grounded = bool(ungrounded) is False
    if not evidence:
        # No evidence cited at all — treat as not grounded (nothing to verify).
        all_grounded = False
    return all_grounded, grounded, ungrounded


def detected_target(finding: CodeFinding | None, gt: GroundTruth) -> bool:
    """Return True if the finding references the intended vulnerability."""
    if finding is None or gt.is_safe_repo:
        return False
    text = combined_finding_text(finding)
    return any(sig in text for sig in gt.signals)


def is_localized(finding: CodeFinding, gt: GroundTruth) -> tuple[bool, int]:
    """Return (localized, line).

    Localization requires the correct file. The line is acceptable when:
      * it is within ``line_tolerance`` of ``expected_line`` (when the ground
        truth defines an expected line), OR
      * it is 0 — a file-level finding, which is still a *weaker but supported*
        form of localization (the agent located the file but not a specific
        line).

    That is, an explicitly wrong line (outside tolerance) fails localization
    when an expected line is defined; file-level findings remain supported.
    """
    if gt.expected_file and finding.file != gt.expected_file:
        return False, finding.line
    line = finding.line
    if gt.expected_line and line:
        # A non-zero line is checked against the tolerance when one is defined.
        if abs(line - gt.expected_line) > gt.line_tolerance:
            return False, line
    return True, line


def is_severity_ok(finding: CodeFinding | None, gt: GroundTruth) -> bool:
    if finding is None:
        return False
    value = finding.severity.value if finding.severity is not None else "unknown"
    return value in gt.acceptable_severities


def is_hallucination(finding: CodeFinding | None, gt: GroundTruth) -> bool:
    """Return True if the finding reports an unsupported vulnerability.

    Definition of hallucination used here:

    * Safe repository (``case_d``): any assertion — a non-empty description or
      any cited evidence — is an unsupported claim.

    For vulnerable repositories, hallucination is instead characterized by
    fabricated (ungrounded) evidence; that is applied by :func:`score_case`
    from the grounding result, not re-derived here. This keeps the two
    definitions explicit and distinct.
    """
    if finding is None:
        return False
    if gt.is_safe_repo:
        # Report something non-trivial at all in a safe repo == hallucination.
        return bool(finding.description.strip()) or bool(finding.evidence)
    return False


def score_case(
    fixture_root: Path,
    fixture_name: str,
    finding: CodeFinding | None,
    *,
    tool_calls_used: int = 0,
    iterations_used: int = 0,
    terminated: bool = False,
    termination_reason: str = "",
    extra_corpus: list[str] | None = None,
) -> EvaluationResult:
    """Score one evaluation case against its ground truth.

    ``passed`` reflects CORE investigation success only:

    * vulnerable repo: detection AND localization AND evidence grounding;
    * safe repo: NOT hallucination.

    It deliberately does NOT include ``severity_ok`` or ``confidence``. Those
    are reported as independent dimensions so a researcher can distinguish
    "the agent found and grounded the right issue" (`passed`) from "the agent
    also assigned a sensible severity" (`severity_ok`) and from its stated
    ``confidence`` (which is recorded, not treated as correctness).
    """
    gt = _require_ground_truth(fixture_name)
    corpus = collect_corpus(fixture_root)
    if extra_corpus:
        corpus.extend(extra_corpus)

    result = EvaluationResult(
        fixture=fixture_name,
        category_expected=gt.category,
        tool_calls_used=tool_calls_used,
        iterations_used=iterations_used,
        terminated=terminated,
        termination_reason=termination_reason,
    )

    if finding is None:
        # No value produced (agent terminated). Detection fails by definition.
        result.passed = False
        return result

    result.file = finding.file
    result.line = finding.line
    result.description = finding.description or ""
    result.evidence = list(finding.evidence)
    result.confidence = finding.confidence if finding.confidence is not None else 0.0

    result.detection = detected_target(finding, gt)
    result.localization, result.localization_line = is_localized(finding, gt)
    result.evidence_grounded, grounded, ungrounded = is_evidence_grounded(
        finding.evidence, corpus
    )
    result.grounded_entries = grounded
    result.ungrounded_entries = ungrounded
    # Severity is an INDEPENDENT dimension, deliberately NOT part of `passed`.
    result.severity_ok = is_severity_ok(finding, gt)

    if gt.is_safe_repo:
        # Safe repo: any assertion is a hallucination. Passing requires the
        # agent not to invent a vulnerability.
        result.hallucination = is_hallucination(finding, gt)
        result.passed = not result.hallucination
    else:
        # Vulnerable repo: CORE success = detect the intended issue, localize
        # it, and ground its evidence in observed repository/tool content.
        # Severity_ok and confidence are reported separately, not in `passed`.
        result.hallucination = bool(ungrounded)
        result.passed = (
            result.detection
            and result.localization
            and result.evidence_grounded
        )

    return result


def _require_ground_truth(fixture_name: str) -> GroundTruth:
    from src.evaluation.ground_truth import EVAL_CASES

    if fixture_name not in EVAL_CASES:
        raise KeyError(f"No ground truth registered for fixture {fixture_name!r}")
    return EVAL_CASES[fixture_name]
