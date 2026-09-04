"""Step 27: Baseline A — deterministic scanner-only evaluation.

Baseline A is the "traditional tools" arm of the Phase 10 comparison
(Baseline A vs. single-LLM Baseline B vs. SecureFlow Baseline C).  It runs the
existing, deterministic tool layer — Bandit and the CI/CD analyzer — over the
Step 26 vulnerability corpus (one vulnerable fixture plus one clean control per
case) and produces precision/recall against the explicit ground truth defined
in :mod:`src.evaluation.vulnerability`.

Design rules (enforced by ``tests/test_baseline_a_evaluation.py``):

* No LLM, no AI agent, no delegation: the runner calls deterministic scanners
  only.
* Every vulnerable case and every clean control is evaluated.  A missing
  fixture directory aborts the run (no silent skip).
* A category that the installed toolchain cannot detect is reported honestly as
  a false negative; the runner never invents findings and never special-cases
  a benchmark case ID or fixture name.
* Offline only: the run makes no network calls.  Scanner tools that require
  network (dependency analysis via the OSV API) or that are not installed
  (Semgrep) are recorded as *unavailable* and contribute zero findings.
* Matching is deterministic and fully documented:

  1. *Category* — each scanner finding is mapped to a benchmark category from
     its tool + rule ID (see ``classify_finding``).  A rule that maps to no
     category can never match ground truth.
  2. *File* — the finding's file, resolved relative to the scanned fixture, must
     equal the case's ``vulnerable_file``.
  3. *Location* — the finding's line range must overlap the ground-truth range
     within ``line_tolerance`` lines.  A finding with no line information
     (``start_line == 0``) is treated as a file-level match and passes this
     check.
  4. *Severity is not required* for a true positive.

* One ground-truth issue counts once: the first matching finding credits the
  true positive; additional matching findings are *duplicates* and are
  excluded from both the TP count and the FP count.  Unmatched findings on a
  vulnerable fixture, and every finding on a clean control, count as false
  positives.

Metrics

* ``precision = TP / (TP + FP)``, ``recall = TP / (TP + FN)``; a zero
  denominator yields ``0.0``.
* ``FP`` (count) is reported explicitly, together with raw ``TP``/``FN``,
  total vulnerable cases, total clean controls, and total scanner findings.
* Detection time measures only the scanner invocations with
  ``time.perf_counter`` (setup, discovery and formatting are excluded); the
  per-case, total, mean and median are recorded.

Reproduce with::

    python -m src.evaluation.baseline_a

which writes ``evaluation/results/baseline_a.json`` by default.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from pydantic import BaseModel

from src.evaluation.vulnerability import (
    ALL_VULNERABILITY_CASE_IDS,
    ALL_VULNERABILITY_CASES,
    FAKE_CREDENTIAL_VALUE,
    VulnerabilityCase,
    VulnerabilityCategory,
)
from src.models.security_finding import ScanResult, ToolFinding
from src.tools.bandit_runner import (
    BANDIT_TOOL_NAME,
    BanditError,
    BanditNotInstalledError,
    BanditRunner,
)
from src.tools.cicd_analyzer import ANALYZER_TOOL_NAME as CICD_TOOL_NAME
from src.tools.cicd_analyzer import CICDAnalyzer
from src.tools.dependency_analyzer import ANALYZER_TOOL_NAME as DEPENDENCY_TOOL_NAME
from src.tools.semgrep_runner import (
    SEMGREP_TOOL_NAME,
    SemgrepError,
    SemgrepNotInstalledError,
    SemgrepRunner,
)

DEFAULT_LINE_TOLERANCE = 3
DEFAULT_OUTPUT_PATH = Path("evaluation") / "results" / "baseline_a.json"
BASELINE_BENCHMARK_VERSION = "1.0.0"


class BaselineARuntimeError(RuntimeError):
    """Raised when a Baseline A run cannot proceed as specified."""


class ScannerAdapter:
    """Uniform scanner wrapper used by Baseline A.

    ``scan`` is an existing deterministic scanner entry point (e.g. a bound
    ``BanditRunner.scan`` or ``CICDAnalyzer.analyze``).  An adapter that is
    ``available == False`` (tool not installed, or requiring network) is never
    invoked; calling it raises :class:`BaselineARuntimeError`.
    """

    def __init__(
        self,
        name: str,
        scan: Callable[[str | Path], ScanResult] | None = None,
        *,
        available: bool = True,
        reason: str = "",
    ) -> None:
        self.name = name
        self._scan = scan
        self.available = available
        self.reason = reason

    def scan(self, repository_path: Path) -> ScanResult:
        if not self.available or self._scan is None:
            raise BaselineARuntimeError(
                f"scanner {self.name!r} is unavailable: {self.reason}"
            )
        return self._scan(repository_path)


class _RedactedText(str):
    """Marker for text already passed through :func:`_redact_text`."""


def _redact_text(value: str) -> str:
    """Replace the benchmark fake credential with a redaction marker.

    The fake credential exists only for benchmarking; keeping it out of
    serialized artifacts avoids ever exposing a credential-like value.
    """
    return value.replace(FAKE_CREDENTIAL_VALUE, "[REDACTED]")


# ---------------------------------------------------------------------------
# Toolchain
# ---------------------------------------------------------------------------

_BANDIT_CATEGORY_MAP: dict[str, VulnerabilityCategory] = {
    "B602": VulnerabilityCategory.COMMAND_INJECTION,
    "B604": VulnerabilityCategory.COMMAND_INJECTION,
    "B605": VulnerabilityCategory.COMMAND_INJECTION,
    "B607": VulnerabilityCategory.COMMAND_INJECTION,
    "B608": VulnerabilityCategory.SQL_INJECTION,
    "B105": VulnerabilityCategory.HARDCODED_SECRET,
    "B106": VulnerabilityCategory.HARDCODED_SECRET,
    "B107": VulnerabilityCategory.HARDCODED_SECRET,
}


def default_toolchain() -> tuple[ScannerAdapter, ...]:
    """Build the deterministic offline Baseline A toolchain.

    * Bandit — used when the binary is installed (it is in this environment).
    * CI/CD analyzer — runs offline against workflows, Dockerfiles, Compose.
    * Semgrep — recorded unavailable when the binary is not installed.
    * Dependency analyzer — requires the OSV API over the network and is
      therefore excluded from the offline benchmark.

    An unavailable tool contributes zero findings; the results it would have
    produced are honestly reported as false negatives.
    """
    adapters: list[ScannerAdapter] = []

    try:
        bandit = BanditRunner()
    except BanditNotInstalledError:
        adapters.append(
            ScannerAdapter(
                BANDIT_TOOL_NAME,
                available=False,
                reason="Bandit binary not found",
            )
        )
    except BanditError as exc:
        adapters.append(
            ScannerAdapter(
                BANDIT_TOOL_NAME,
                available=False,
                reason=f"Bandit unavailable: {exc}",
            )
        )
    else:
        adapters.append(ScannerAdapter(BANDIT_TOOL_NAME, bandit.scan))

    cicd = CICDAnalyzer()
    adapters.append(ScannerAdapter(CICD_TOOL_NAME, cicd.analyze))

    try:
        semgrep = SemgrepRunner()
    except SemgrepNotInstalledError:
        adapters.append(
            ScannerAdapter(
                SEMGREP_TOOL_NAME,
                available=False,
                reason="Semgrep binary not found",
            )
        )
    except SemgrepError as exc:
        adapters.append(
            ScannerAdapter(
                SEMGREP_TOOL_NAME,
                available=False,
                reason=f"Semgrep unavailable: {exc}",
            )
        )
    else:
        adapters.append(ScannerAdapter(SEMGREP_TOOL_NAME, semgrep.scan))

    adapters.append(
        ScannerAdapter(
            DEPENDENCY_TOOL_NAME,
            available=False,
            reason=(
                "requires network access to the OSV API; excluded from the "
                "offline Baseline A benchmark"
            ),
        )
    )

    return tuple(adapters)


# ---------------------------------------------------------------------------
# Finding classification and matching
# ---------------------------------------------------------------------------

_KEYWORD_CATEGORIES: tuple[tuple[tuple[str, ...], VulnerabilityCategory], ...] = (
    (("xss", "cross-site scripting"), VulnerabilityCategory.XSS),
    (("sql",), VulnerabilityCategory.SQL_INJECTION),
    (
        ("secret", "password", "credential", "api_key", "api-key"),
        VulnerabilityCategory.HARDCODED_SECRET,
    ),
    (
        ("command", "os.system", "shell", "subprocess", "system-call"),
        VulnerabilityCategory.COMMAND_INJECTION,
    ),
    (("docker", "compose"), VulnerabilityCategory.DOCKER_MISCONFIGURATION),
    (("workflow", "action", "permission"), VulnerabilityCategory.INSECURE_CI_CD),
    (("dependency", "cve", "osv", "ghsa"), VulnerabilityCategory.DEPENDENCY_VULNERABILITY),
)


def classify_finding(tool: str, rule_id: str, message: str) -> VulnerabilityCategory | None:
    """Map a scanner finding to a benchmark category, or ``None``.

    Bandit rules and CI/CD analyzer rule prefixes are mapped explicitly.
    Findings from the dependency analyzer always map to the dependency
    category.  Any other tool/rule falls back to deterministic keyword
    matching over ``rule_id`` and ``message``.
    """
    if tool == BANDIT_TOOL_NAME:
        return _BANDIT_CATEGORY_MAP.get(rule_id.split(".", 1)[0])
    if tool == CICD_TOOL_NAME:
        if rule_id.startswith("CICD.GHA."):
            return VulnerabilityCategory.INSECURE_CI_CD
        if rule_id.startswith(("CICD.DOCKER.", "CICD.COMPOSE.")):
            return VulnerabilityCategory.DOCKER_MISCONFIGURATION
        return None
    if tool == DEPENDENCY_TOOL_NAME:
        return VulnerabilityCategory.DEPENDENCY_VULNERABILITY

    text = f"{rule_id} {message}".lower()
    for keywords, category in _KEYWORD_CATEGORIES:
        if any(keyword in text for keyword in keywords):
            return category
    return None


def _normalised_relative(root: Path, file_path: str) -> str:
    """Return ``file_path`` as a case-folded, forward-slash path relative to root."""
    candidate = Path(str(file_path).replace("\\", "/"))
    try:
        resolved = candidate.resolve()
    except OSError:
        resolved = candidate
    try:
        return resolved.relative_to(root.resolve()).as_posix().casefold()
    except ValueError:
        return resolved.as_posix().casefold()


def _expected_file(case: VulnerabilityCase) -> str:
    return Path(case.vulnerable_file).as_posix().casefold()


def _lines_overlap(
    finding: ToolFinding,
    start_line: int,
    end_line: int,
    tolerance: int,
) -> bool:
    """Return whether the finding's lines overlap the ground-truth range.

    A finding with no line information (``start_line == 0``) is a file-level
    match and passes this check; ``tolerance`` absorbs minor anchor drift.
    """
    if finding.start_line == 0:
        return True
    finding_start = finding.start_line or finding.end_line
    finding_end = finding.end_line or finding.start_line
    return not (finding_end < start_line - tolerance or finding_start > end_line + tolerance)


def finding_matches(
    root: Path,
    finding: ToolFinding,
    case: VulnerabilityCase,
    tolerance: int = DEFAULT_LINE_TOLERANCE,
) -> bool:
    """Return whether ``finding`` corresponds to ``case``'s ground truth.

    All of category, file, and line must match (see module docstring).
    """
    if classify_finding(finding.tool, finding.rule_id, finding.message) != case.category:
        return False
    if _normalised_relative(root, finding.file_path) != _expected_file(case):
        return False
    return _lines_overlap(finding, case.start_line, case.end_line, tolerance)


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------


class FindingEvidence(BaseModel):
    """Serialization of one scanner finding for the audit trail."""

    tool: str
    rule_id: str
    severity: str
    confidence: str
    message: str
    file_path: str
    start_line: int
    end_line: int


class BaselineACaseResult(BaseModel):
    """Per-fixture audit record for one benchmark case variant."""

    case_id: str
    variant: str
    category: VulnerabilityCategory
    expected_file: str
    expected_lines: list[int]
    expected_finding: str
    evidence: str
    findings: list[FindingEvidence]
    matched_findings: list[FindingEvidence]
    duplicate_findings: list[FindingEvidence]
    unmatched_findings: list[FindingEvidence]
    true_positive: bool
    false_negative: bool
    false_positive_count: int
    true_negative: bool
    detection_duration_seconds: float
    tool_notes: list[str]


class BaselineAMetrics(BaseModel):
    """Aggregate TP/FP/FN counts and derived rates."""

    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    true_negative_count: int
    total_vulnerable_cases: int
    total_clean_controls: int
    total_scanner_findings: int
    unsupported_categories: list[str]


class BaselineATiming(BaseModel):
    """Detection-time summary measured with ``time.perf_counter``."""

    total_detection_seconds: float
    mean_per_case_seconds: float
    median_per_case_seconds: float


class BaselineATool(BaseModel):
    """Tool availability metadata recorded in the report."""

    name: str
    available: bool
    reason: str = ""
    version: str = ""


class BaselineAResult(BaseModel):
    """Full Baseline A report, serialized to ``baseline_a.json``."""

    baseline_id: str = "baseline_a"
    benchmark_name: str = "secureflow-vulnerability-benchmark"
    benchmark_version: str = BASELINE_BENCHMARK_VERSION
    tools: list[BaselineATool]
    evaluated_case_ids: list[str]
    num_vulnerable_cases: int
    num_clean_controls: int
    metrics: BaselineAMetrics
    timing: BaselineATiming
    per_case: list[BaselineACaseResult]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

_PERF_COUNTER: Callable[[], float] = time.perf_counter


class BaselineARunner:
    """Evaluate deterministic scanners against the Step 26 vulnerability corpus.

    Args:
        tools: Scanners to run.  Defaults to
            :func:`default_toolchain` (real Bandit and CI/CD analyzer offline).
        line_tolerance: Allowed line drift when matching findings to ground
            truth (see module docstring).
    """

    def __init__(
        self,
        tools: Sequence[ScannerAdapter] | None = None,
        line_tolerance: int = DEFAULT_LINE_TOLERANCE,
    ) -> None:
        self._tools = list(tools) if tools is not None else list(default_toolchain())
        self._tolerance = line_tolerance

    def run(
        self,
        case_ids: Sequence[str] | None = None,
        fixtures_root: Path | None = None,
    ) -> BaselineAResult:
        """Evaluate the selected cases (all by default).

        ``fixtures_root`` overrides the fixture directory (used by tests to
        exercise the no-silent-skip path without touching repository fixtures).
        """
        cases = self._select_cases(case_ids)

        per_case: list[BaselineACaseResult] = []
        tool_versions: dict[str, str] = {}

        for case in cases:
            for variant, root, is_vulnerable in self._variant_roots(case, fixtures_root):
                if not root.is_dir():
                    raise BaselineARuntimeError(
                        f"fixture directory missing for {variant!r} variant of "
                        f"{case.case_id!r}: {root}"
                    )

                findings: list[ToolFinding] = []
                notes: list[str] = []
                durations: list[float] = []

                for tool in self._tools:
                    if not tool.available:
                        continue
                    started = _PERF_COUNTER()
                    scan_result = tool.scan(root)
                    durations.append(_PERF_COUNTER() - started)
                    tool_versions.setdefault(tool.name, scan_result.tool_version)
                    findings.extend(scan_result.findings)
                    if scan_result.error_message:
                        notes.append(f"{tool.name}: {scan_result.error_message}")
                    if scan_result.status != "success":
                        notes.append(f"{tool.name}: status {scan_result.status}")

                per_case.append(
                    self._score_variant(
                        case=case,
                        root=root,
                        variant=variant,
                        is_vulnerable=is_vulnerable,
                        findings=findings,
                        durations=durations,
                        notes=notes,
                    )
                )

        return self._build_result(cases, per_case, tool_versions)

    def _select_cases(self, case_ids: Sequence[str] | None) -> list[VulnerabilityCase]:
        if case_ids is None:
            return list(ALL_VULNERABILITY_CASES)
        for case_id in case_ids:
            if case_id not in ALL_VULNERABILITY_CASE_IDS:
                raise BaselineARuntimeError(f"unknown benchmark case: {case_id!r}")
        return [ALL_VULNERABILITY_CASES[ALL_VULNERABILITY_CASE_IDS.index(cid)] for cid in case_ids]

    def _variant_roots(
        self,
        case: VulnerabilityCase,
        fixtures_root: Path | None,
    ) -> list[tuple[str, Path, bool]]:
        if fixtures_root is not None:
            return [
                ("vulnerable", fixtures_root / case.case_id, True),
                ("clean", fixtures_root / case.clean_control_id, False),
            ]
        return [
            ("vulnerable", case.fixture_path(), True),
            ("clean", case.clean_fixture_path(), False),
        ]

    def _score_variant(
        self,
        *,
        case: VulnerabilityCase,
        root: Path,
        variant: str,
        is_vulnerable: bool,
        findings: list[ToolFinding],
        durations: list[float],
        notes: list[str],
    ) -> BaselineACaseResult:
        matched_indices = (
            [
                i
                for i, finding in enumerate(findings)
                if finding_matches(root, finding, case, self._tolerance)
            ]
            if is_vulnerable
            else []
        )
        matched = [findings[i] for i in matched_indices]
        unmatched = [f for i, f in enumerate(findings) if i not in matched_indices]
        duplicates = matched[1:]

        true_positive = False
        false_negative = False
        false_positive_count = 0
        true_negative = False

        if is_vulnerable:
            true_positive = bool(matched)
            false_negative = not true_positive
            false_positive_count = len(unmatched)
        else:
            false_positive_count = len(findings)
            true_negative = not findings

        return BaselineACaseResult(
            case_id=case.case_id,
            variant=variant,
            category=case.category,
            expected_file=case.vulnerable_file,
            expected_lines=[case.start_line, case.end_line],
            expected_finding=_redact_text(case.expected_finding),
            evidence=_redact_text(case.evidence),
            findings=[_finding_evidence(f) for f in findings],
            matched_findings=[_finding_evidence(f) for f in matched[:1]],
            duplicate_findings=[_finding_evidence(f) for f in duplicates],
            unmatched_findings=[_finding_evidence(f) for f in unmatched],
            true_positive=true_positive,
            false_negative=false_negative,
            false_positive_count=false_positive_count,
            true_negative=true_negative,
            detection_duration_seconds=float(sum(durations)),
            tool_notes=notes,
        )

    def _build_result(
        self,
        cases: list[VulnerabilityCase],
        per_case: list[BaselineACaseResult],
        tool_versions: dict[str, str],
    ) -> BaselineAResult:
        vulnerable = [c for c in per_case if c.variant == "vulnerable"]
        clean = [c for c in per_case if c.variant == "clean"]

        tp = sum(1 for c in vulnerable if c.true_positive)
        fn = sum(1 for c in vulnerable if c.false_negative)
        fp = sum(c.false_positive_count for c in per_case)
        tn = sum(1 for c in clean if c.true_negative)

        total_findings = sum(len(c.findings) for c in per_case)
        detected_categories = {c.category for c in vulnerable if c.true_positive}
        unsupported_categories = [
            category.value
            for category in VulnerabilityCategory
            if category not in detected_categories
        ]

        durations = [c.detection_duration_seconds for c in per_case]
        total_time = sum(durations)
        mean_time = total_time / len(durations) if durations else 0.0
        median_time = statistics.median(durations) if durations else 0.0

        metrics = BaselineAMetrics(
            tp=tp,
            fp=fp,
            fn=fn,
            precision=_rate(tp, tp + fp),
            recall=_rate(tp, tp + fn),
            true_negative_count=tn,
            total_vulnerable_cases=len(cases),
            total_clean_controls=len(cases),
            total_scanner_findings=total_findings,
            unsupported_categories=unsupported_categories,
        )

        return BaselineAResult(
            tools=[
                BaselineATool(
                    name=tool.name,
                    available=tool.available,
                    reason=tool.reason,
                    version=tool_versions.get(tool.name, ""),
                )
                for tool in self._tools
            ],
            evaluated_case_ids=[c.case_id for c in cases],
            num_vulnerable_cases=len(cases),
            num_clean_controls=len(cases),
            metrics=metrics,
            timing=BaselineATiming(
                total_detection_seconds=round(total_time, 4),
                mean_per_case_seconds=round(mean_time, 4),
                median_per_case_seconds=round(median_time, 4),
            ),
            per_case=per_case,
        )


def _finding_evidence(finding: ToolFinding) -> FindingEvidence:
    return FindingEvidence(
        tool=finding.tool,
        rule_id=finding.rule_id,
        severity=finding.severity.value if finding.severity else "",
        confidence=finding.confidence.value if finding.confidence else "",
        message=_redact_text(finding.message),
        file_path=finding.file_path,
        start_line=finding.start_line,
        end_line=finding.end_line,
    )


def _rate(numerator: int, denominator: int) -> float:
    """Return ``numerator / denominator`` rounding to 4 places, ``0.0`` if 0/0."""
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 4)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.evaluation.baseline_a",
        description="Run Baseline A (deterministic scanner-only benchmark).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=_project_root() / DEFAULT_OUTPUT_PATH,
        help="Artifact path (default: evaluation/results/baseline_a.json).",
    )
    parser.add_argument(
        "--case",
        action="append",
        default=None,
        dest="case_ids",
        help="Benchmark case ID to evaluate; repeatable. Default: all cases.",
    )
    parser.add_argument(
        "--tolerance",
        type=int,
        default=DEFAULT_LINE_TOLERANCE,
        help="Line-matching tolerance (default: %(default)s).",
    )
    args = parser.parse_args(argv)

    runner = BaselineARunner(line_tolerance=args.tolerance)
    result = runner.run(case_ids=args.case_ids)

    output = args.out
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )

    m = result.metrics
    t = result.timing
    print(f"Baseline A ({result.benchmark_version}) — {len(result.evaluated_case_ids)} cases")
    print(
        f"  TP={m.tp} FP={m.fp} FN={m.fn} TN={m.true_negative_count} "
        f"precision={m.precision} recall={m.recall}"
    )
    print(f"  total findings={m.total_scanner_findings}")
    print(f"  total detection time={t.total_detection_seconds}s")
    print(f"  wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())