"""Step 27 tests: Baseline A deterministic scanner-only evaluation.

The unit tests never execute real scanners: they inject fake adapters so no
subprocess, network call, or LLM runs inside pytest.  The final benchmark
measurement runs the real deterministic scanner layer via the ``main`` entry
point (see docs/benchmark-design.md, Step 27).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path, PurePosixPath

import pytest

from src.evaluation import baseline_a
from src.evaluation.baseline_a import (
    BASELINE_BENCHMARK_VERSION,
    BaselineAResult,
    BaselineARunner,
    BaselineARuntimeError,
    ScannerAdapter,
    ScanResult,
    ToolFinding,
    classify_finding,
    default_toolchain,
    finding_matches,
    main,
)
from src.evaluation.vulnerability import (
    ALL_VULNERABILITY_CASE_IDS,
    ALL_VULNERABILITY_CASES,
    FAKE_CREDENTIAL_VALUE,
    VULNERABILITY_CATEGORIES,
    VulnerabilityCategory,
    get_vulnerability_case,
)
from src.models.security_finding import Confidence, Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    tool: str,
    rule_id: str,
    *,
    file_path: str = "",
    start_line: int = 7,
    end_line: int = 7,
    message: str = "",
    severity: Severity = Severity.ERROR,
    confidence: Confidence = Confidence.HIGH,
    category: str = "security",
) -> ToolFinding:
    return ToolFinding(
        tool=tool,
        rule_id=rule_id,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        message=message,
        severity=severity,
        confidence=confidence,
        category=category,
    )


def _fake_adapter(
    name: str = "fake-scanner",
    builder: Callable[[Path], list[ToolFinding]] | None = None,
    *,
    available: bool = True,
    reason: str = "",
) -> ScannerAdapter:
    if builder is None:

        def _no_findings(_root: Path) -> list[ToolFinding]:
            return []

        builder = _no_findings

    def scan(repository_path: str | Path) -> ScanResult:
        findings = builder(Path(repository_path))
        return ScanResult(
            tool=name,
            findings=findings,
            status="success",
            findings_count=len(findings),
            tool_version="test-1.0",
        )

    return ScannerAdapter(name, scan, available=available, reason=reason)


def _sql_finding_on(root: Path) -> list[ToolFinding]:
    return [_finding("bandit", "B608", file_path=str(root / "app" / "db.py"), start_line=7)]


def _empty_builder(_root: Path) -> list[ToolFinding]:
    return []


def _fixture_hash(root: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            snapshot[str(PurePosixPath(path.relative_to(root)))] = digest
    return snapshot


class _StepClock:
    def __init__(self, step: float = 1.0) -> None:
        self._value = 0.0
        self._step = step

    def __call__(self) -> float:
        self._value = round(self._value + self._step, 6)
        return self._value


# ---------------------------------------------------------------------------
# Corpus and no-silent-skip guarantees
# ---------------------------------------------------------------------------


def test_all_cases_have_vulnerable_and_clean_fixtures() -> None:
    for case in ALL_VULNERABILITY_CASES:
        assert case.fixture_path().is_dir(), case.case_id
        assert case.clean_fixture_path().is_dir(), case.clean_control_id


def test_run_evaluates_every_case_in_both_variants() -> None:
    runner = BaselineARunner(tools=[_fake_adapter()])
    result = runner.run()
    assert list(result.evaluated_case_ids) == list(ALL_VULNERABILITY_CASE_IDS)
    assert result.num_vulnerable_cases == len(ALL_VULNERABILITY_CASES)
    assert result.num_clean_controls == len(ALL_VULNERABILITY_CASES)
    variants = {(c.case_id, c.variant) for c in result.per_case}
    expected = {
        (case.case_id, variant)
        for case in ALL_VULNERABILITY_CASES
        for variant in ("vulnerable", "clean")
    }
    assert variants == expected


def test_run_aborts_on_missing_fixture_without_silent_skip(tmp_path: Path) -> None:
    harness = tmp_path / "harness"
    harness.mkdir()
    (harness / "sql_injection").mkdir()
    (harness / "sql_injection_clean").mkdir()
    runner = BaselineARunner(tools=[_fake_adapter()])
    with pytest.raises(BaselineARuntimeError, match="fixture directory missing"):
        runner.run(fixtures_root=harness)


def test_run_rejects_unknown_case_id() -> None:
    runner = BaselineARunner(tools=[_fake_adapter()])
    with pytest.raises(BaselineARuntimeError, match="unknown benchmark case"):
        runner.run(case_ids=["not_a_case"])


def _snapshot_corpus() -> dict[str, dict[str, str]]:
    snapshot: dict[str, dict[str, str]] = {}
    for case in ALL_VULNERABILITY_CASES:
        snapshot[case.case_id] = _fixture_hash(case.fixture_path())
        snapshot[case.clean_control_id] = _fixture_hash(case.clean_fixture_path())
    return snapshot


def test_run_does_not_modify_corpus() -> None:
    before = _snapshot_corpus()
    runner = BaselineARunner(tools=[_fake_adapter()])
    runner.run()
    assert _snapshot_corpus() == before


# ---------------------------------------------------------------------------
# Matching policy
# ---------------------------------------------------------------------------


def test_matching_finding_counts_true_positive() -> None:
    runner = BaselineARunner(tools=[_fake_adapter(builder=_sql_finding_on)])
    result = runner.run(case_ids=["sql_injection"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is True
    assert vulnerable.false_negative is False
    assert vulnerable.false_positive_count == 0
    assert len(vulnerable.matched_findings) == 1


def test_unmatched_vulnerable_case_is_false_negative() -> None:
    runner = BaselineARunner(tools=[_fake_adapter(builder=_empty_builder)])
    result = runner.run(case_ids=["xss"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is False
    assert vulnerable.false_negative is True
    assert vulnerable.false_positive_count == 0


def test_any_clean_control_finding_is_false_positive() -> None:
    case = get_vulnerability_case("sql_injection")
    vulnerable = case.fixture_path()
    clean = case.clean_fixture_path()

    def builder(root: Path) -> list[ToolFinding]:
        if root == vulnerable:
            return [
                _finding(
                    "bandit",
                    "B608",
                    file_path=str(root / "app" / "db.py"),
                    start_line=7,
                )
            ]
        if root == clean:
            return [
                _finding(
                    "bandit",
                    "B404",
                    file_path=str(clean / "app" / "db.py"),
                    start_line=1,
                )
            ]
        return []

    runner = BaselineARunner(tools=[_fake_adapter(builder=builder)])
    result = runner.run(case_ids=["sql_injection"])
    clean_case = next(c for c in result.per_case if c.variant == "clean")
    assert clean_case.false_positive_count == 1
    assert clean_case.true_positive is False
    assert clean_case.true_negative is False
    assert clean_case.matched_findings == []
    assert clean_case.duplicate_findings == []
    assert len(clean_case.unmatched_findings) == 1
    vulnerable_case = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable_case.true_positive is True


def test_finding_on_wrong_file_is_false_positive_not_true_positive() -> None:
    def builder(fixture_root: Path) -> list[ToolFinding]:
        return [
            _finding(
                "bandit",
                "B608",
                file_path=str(fixture_root / "app" / "web.py"),
                start_line=7,
            )
        ]

    runner = BaselineARunner(tools=[_fake_adapter(builder=builder)])
    result = runner.run(case_ids=["sql_injection"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is False
    assert vulnerable.false_negative is True
    assert vulnerable.false_positive_count == 1


def test_duplicate_findings_do_not_inflate_true_positive() -> None:
    def builder(fixture_root: Path) -> list[ToolFinding]:
        base = str(fixture_root / "app" / "db.py")
        return [
            _finding("bandit", "B608", file_path=base, start_line=4),
            _finding("bandit", "B608", file_path=base, start_line=8),
        ]

    runner = BaselineARunner(tools=[_fake_adapter(builder=builder)])
    result = runner.run(case_ids=["sql_injection"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is True
    assert len(vulnerable.duplicate_findings) == 1
    assert vulnerable.false_positive_count == 0


def test_multi_finding_docker_case_scores_one_true_positive() -> None:
    def builder(fixture_root: Path) -> list[ToolFinding]:
        base = str(fixture_root / "Dockerfile")
        return [
            _finding(
                "cicd-analyzer",
                "CICD.DOCKER.SECRET_ARG",
                file_path=base,
                start_line=5,
                end_line=5,
            ),
            _finding(
                "cicd-analyzer",
                "CICD.DOCKER.SECRET_ENV",
                file_path=base,
                start_line=6,
                end_line=6,
            ),
            _finding(
                "cicd-analyzer",
                "CICD.DOCKER.ROOT_USER",
                file_path=base,
                start_line=0,
                end_line=0,
            ),
        ]

    runner = BaselineARunner(tools=[_fake_adapter(builder=builder)])
    result = runner.run(case_ids=["docker_misconfiguration"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is True
    assert len(vulnerable.matched_findings) == 1
    assert len(vulnerable.duplicate_findings) == 2
    assert vulnerable.false_positive_count == 0


def test_unlocated_line_zero_finding_matches_by_file_and_category() -> None:
    def builder(fixture_root: Path) -> list[ToolFinding]:
        return [
            _finding(
                "cicd-analyzer",
                "CICD.GHA.UNTRUSTED_INPUT",
                file_path=str(fixture_root / ".github" / "workflows" / "ci.yml"),
                start_line=0,
                end_line=0,
            )
        ]

    runner = BaselineARunner(tools=[_fake_adapter(builder=builder)])
    result = runner.run(case_ids=["insecure_cicd"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is True
    assert vulnerable.false_positive_count == 0


def test_category_mismatch_never_counts_true_positive() -> None:
    def builder(fixture_root: Path) -> list[ToolFinding]:
        return [
            _finding(
                "cicd-analyzer",
                "CICD.GHA.UNTRUSTED_INPUT",
                file_path=str(fixture_root / "app" / "db.py"),
                start_line=7,
            )
        ]

    runner = BaselineARunner(tools=[_fake_adapter(builder=builder)])
    result = runner.run(case_ids=["sql_injection"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is False
    assert vulnerable.false_positive_count == 1


def test_unmapped_rule_never_counts_true_positive() -> None:
    def builder(fixture_root: Path) -> list[ToolFinding]:
        return [
            _finding(
                "bandit",
                "B404",
                file_path=str(fixture_root / "cli" / "tools.py"),
                start_line=5,
            )
        ]

    runner = BaselineARunner(tools=[_fake_adapter(builder=builder)])
    result = runner.run(case_ids=["command_injection"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is False
    assert vulnerable.false_positive_count == 1


def test_line_tolerance_bounds_matching() -> None:
    case = get_vulnerability_case("sql_injection")
    root = case.fixture_path()
    tool = "bandit"
    rule = "B608"

    def at(line: int) -> ToolFinding:
        return _finding(
            tool,
            rule,
            file_path=str(root / "app" / "db.py"),
            start_line=line,
            end_line=line,
        )

    assert finding_matches(root, at(4), case) is True
    assert finding_matches(root, at(10), case) is True
    assert finding_matches(root, at(3), case) is False
    assert finding_matches(root, at(11), case) is False


def test_severity_is_not_required_for_true_positive() -> None:
    case = get_vulnerability_case("sql_injection")
    root = case.fixture_path()
    low = _finding(
        "bandit",
        "B608",
        file_path=str(root / "app" / "db.py"),
        start_line=7,
        severity=Severity.INFO,
        confidence=Confidence.LOW,
    )
    high = _finding("bandit", "B608", file_path=str(root / "app" / "db.py"), start_line=7)
    assert finding_matches(root, low, case) is True
    assert finding_matches(root, high, case) is True


def test_xss_rule_does_not_match_sql_case() -> None:
    # Regression guard: only exact category mappings fire.
    case = get_vulnerability_case("sql_injection")
    root = case.fixture_path()
    xss = _finding(
        "semgrep",
        "python.lang.security.audit.xss-xml-copy",
        file_path=str(root / "app" / "db.py"),
        start_line=7,
    )
    assert finding_matches(root, xss, case) is False


# ---------------------------------------------------------------------------
# classify_finding mapping table
# ---------------------------------------------------------------------------


def test_classify_finding_bandit_explicit_rules() -> None:
    expected: dict[str, VulnerabilityCategory] = {
        "B608": VulnerabilityCategory.SQL_INJECTION,
        "B605.start_process_with_a_shell": VulnerabilityCategory.COMMAND_INJECTION,
        "B105": VulnerabilityCategory.HARDCODED_SECRET,
    }
    for rule_id, category in expected.items():
        assert classify_finding("bandit", rule_id, "") == category
    assert classify_finding("bandit", "B404", "") is None
    assert classify_finding("bandit", "B603", "") is None


def test_classify_finding_cicd_prefixes() -> None:
    expected: dict[str, VulnerabilityCategory] = {
        "CICD.GHA.UNTRUSTED_INPUT": VulnerabilityCategory.INSECURE_CI_CD,
        "CICD.DOCKER.ROOT_USER": VulnerabilityCategory.DOCKER_MISCONFIGURATION,
        "CICD.COMPOSE.SECRET": VulnerabilityCategory.DOCKER_MISCONFIGURATION,
    }
    for rule_id, category in expected.items():
        assert classify_finding("cicd-analyzer", rule_id, "") == category
    assert classify_finding("cicd-analyzer", "CICD.UNKNOWN.RULE", "") is None


def test_classify_finding_dependency_and_keyword_fallback() -> None:
    dependency = classify_finding("dependency-analyzer", "GHSA-xxxx", "")
    assert dependency == VulnerabilityCategory.DEPENDENCY_VULNERABILITY
    expected: dict[str, VulnerabilityCategory] = {
        "java.lang.security.xss.react": VulnerabilityCategory.XSS,
        "python.lang.security.audit.system-call": VulnerabilityCategory.COMMAND_INJECTION,
        "generic.secrets.api-key": VulnerabilityCategory.HARDCODED_SECRET,
    }
    for rule_id, category in expected.items():
        assert classify_finding("semgrep", rule_id, "") == category
    assert classify_finding("some-tool", "M000.NO_KEYWORD", "no signal here") is None


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def test_metrics_math_on_controlled_scenario() -> None:
    sql = get_vulnerability_case("sql_injection")
    clean_root = sql.clean_fixture_path()

    def builder(root: Path) -> list[ToolFinding]:
        if root == clean_root:
            return [_finding("bandit", "B404", file_path=str(root / "app" / "db.py"), start_line=1)]
        if root == sql.fixture_path():
            return _sql_finding_on(root)
        return []

    runner = BaselineARunner(tools=[_fake_adapter(builder=builder)])
    result = runner.run(case_ids=["sql_injection", "xss"])
    assert result.metrics.tp == 1
    assert result.metrics.fp == 1
    assert result.metrics.fn == 1
    assert result.metrics.precision == 0.5
    assert result.metrics.recall == 0.5
    assert result.metrics.total_vulnerable_cases == 2
    assert result.metrics.total_clean_controls == 2
    assert result.metrics.true_negative_count == 1
    assert result.metrics.total_scanner_findings == 2


def test_zero_denominator_produces_zero_rates() -> None:
    runner = BaselineARunner(tools=[_fake_adapter(builder=_empty_builder)])
    result = runner.run(case_ids=["xss"])
    assert result.metrics.tp == 0
    assert result.metrics.fp == 0
    assert result.metrics.fn == 1
    assert result.metrics.precision == 0.0
    assert result.metrics.recall == 0.0


def test_unsupported_categories_reported() -> None:
    runner = BaselineARunner(tools=[_fake_adapter(builder=_sql_finding_on)])
    result = runner.run()
    assert "sql_injection" not in result.metrics.unsupported_categories
    for category in (c.value for c in VULNERABILITY_CATEGORIES if c.value != "sql_injection"):
        assert category in result.metrics.unsupported_categories


def test_metrics_deterministic_for_fixed_mock_output() -> None:
    runner = BaselineARunner(tools=[_fake_adapter(builder=_sql_finding_on)])
    first = runner.run()
    second = runner.run()
    assert first.metrics.model_dump(mode="json") == second.metrics.model_dump(mode="json")
    assert first.num_clean_controls == len(ALL_VULNERABILITY_CASES)


# ---------------------------------------------------------------------------
# Detection time
# ---------------------------------------------------------------------------


def test_timing_is_non_negative_and_populated() -> None:
    runner = BaselineARunner(tools=[_fake_adapter(builder=_sql_finding_on)])
    result = runner.run()
    assert result.timing.total_detection_seconds >= 0.0
    assert result.timing.mean_per_case_seconds >= 0.0
    assert result.timing.median_per_case_seconds >= 0.0
    assert all(c.detection_duration_seconds >= 0.0 for c in result.per_case)


def test_timing_math_with_patched_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _StepClock(step=1.0)
    monkeypatch.setattr(baseline_a, "_PERF_COUNTER", clock)
    runner = BaselineARunner(tools=[_fake_adapter()])
    result = runner.run()
    variants = len(result.per_case)
    assert variants == 2 * len(ALL_VULNERABILITY_CASES)
    assert all(c.detection_duration_seconds == 1.0 for c in result.per_case)
    assert result.timing.total_detection_seconds == variants
    assert result.timing.mean_per_case_seconds == 1.0
    assert result.timing.median_per_case_seconds == 1.0


# ---------------------------------------------------------------------------
# Toolchain integrity
# ---------------------------------------------------------------------------


def test_default_toolchain_marks_offline_tools_unavailable() -> None:
    tools = default_toolchain()
    by_name = {tool.name: tool for tool in tools}
    assert by_name["bandit"].available is True
    assert by_name["cicd-analyzer"].available is True
    assert by_name["semgrep"].available is False
    assert "Semgrep binary not found" in by_name["semgrep"].reason
    assert by_name["dependency-analyzer"].available is False
    assert "OSV" in by_name["dependency-analyzer"].reason


def test_unavailable_adapter_scan_raises() -> None:
    tool = ScannerAdapter("offline", available=False, reason="offline")
    with pytest.raises(BaselineARuntimeError):
        tool.scan(Path("."))


def test_unavailable_tool_contributes_zero_findings() -> None:
    runner = BaselineARunner(tools=[_fake_adapter(builder=_empty_builder, available=False)])
    result = runner.run()
    assert result.metrics.total_scanner_findings == 0
    assert result.tools[0].available is False


def test_module_source_has_no_llm_network_or_subprocess_imports() -> None:
    source = Path(baseline_a.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "import subprocess",
        "import urllib",
        "from urllib",
        "import http",
        "import requests",
        "import socket",
        "src.llm",
        "src.agents",
    ):
        assert forbidden not in source, forbidden


# ---------------------------------------------------------------------------
# Artifact serialization and CLI
# ---------------------------------------------------------------------------


def test_artifact_is_json_serializable_and_contains_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(baseline_a, "default_toolchain", lambda: (_fake_adapter(),))
    result = baseline_a.BaselineARunner().run(case_ids=["sql_injection", "xss"])
    payload = result.model_dump(mode="json")
    assert payload["baseline_id"] == "baseline_a"
    assert payload["benchmark_version"] == BASELINE_BENCHMARK_VERSION
    assert payload["metrics"]["tp"] == result.metrics.tp
    assert payload["metrics"]["fp"] == result.metrics.fp
    json.dumps(payload)  # must not raise


def test_fake_credential_is_redacted_in_artifact() -> None:
    def builder(root: Path) -> list[ToolFinding]:
        return [
            _finding(
                "bandit",
                "B105",
                file_path=str(root / "config" / "settings.py"),
                start_line=2,
                message=f"hardcoded token {FAKE_CREDENTIAL_VALUE} in settings",
            )
        ]

    runner = BaselineARunner(tools=[_fake_adapter(builder=builder)])
    result = runner.run(case_ids=["hardcoded_secret"])
    dumped = json.dumps(result.model_dump(mode="json"))
    assert FAKE_CREDENTIAL_VALUE not in dumped
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is True
    assert any("[REDACTED]" in f.message for f in vulnerable.findings)
    assert vulnerable.evidence == "[REDACTED]"


def test_main_writes_artifact_and_returns_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        baseline_a,
        "default_toolchain",
        lambda: (_fake_adapter(builder=_sql_finding_on),),
    )
    out = tmp_path / "nested" / "baseline_a.json"
    rc = main(["--out", str(out), "--case", "sql_injection", "--case", "xss"])
    assert rc == 0
    assert out.is_file()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["evaluated_case_ids"] == ["sql_injection", "xss"]
    assert data["metrics"]["tp"] == 1
    printed = capsys.readouterr().out
    assert "TP=1" in printed
    assert str(tmp_path) in printed


# ---------------------------------------------------------------------------
# Per-case audit fields
# ---------------------------------------------------------------------------


def test_per_case_audit_fields_populated() -> None:
    runner = BaselineARunner(tools=[_fake_adapter(builder=_empty_builder)])
    result = runner.run(case_ids=["command_injection"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.case_id == "command_injection"
    assert vulnerable.category == VulnerabilityCategory.COMMAND_INJECTION
    assert vulnerable.expected_file == "cli/tools.py"
    assert vulnerable.expected_lines == [5, 5]
    assert isinstance(vulnerable.expected_finding, str)
    assert isinstance(vulnerable.evidence, str)
    assert vulnerable.findings == []
    assert vulnerable.matched_findings == []
    assert vulnerable.unmatched_findings == []
    assert isinstance(result, BaselineAResult)