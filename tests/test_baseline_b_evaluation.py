"""Step 28 tests: Baseline B single-LLM investigation evaluation.

The unit tests never call a real LLM: they inject scripted ``BaselineBProvider``
doubles returning raw JSON text, so no network, no API key, no shell, and no
external process runs inside pytest.  The CLI's ``--dry-run`` mode is an
explicit, clearly-labeled offline pipeline check; it is not an empirical result
(no real provider is configured in this environment).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

import pytest

from src.evaluation import baseline_b
from src.evaluation.baseline_b import (
    BASELINE_B_PROMPT_VERSION,
    BASELINE_B_SYSTEM_PROMPT,
    DEFAULT_EMPTY_RESPONSE,
    BaselineBModelInfo,
    BaselineBProvider,
    BaselineBResponse,
    BaselineBResult,
    BaselineBRunner,
    BaselineBRuntimeError,
    MalformedBaselineBResponseError,
    collect_repository_payload,
    finding_matches,
    ignore_run_key,
    main,
    normalize_category,
    parse_baseline_response,
    sanitized_repo_identifier,
    scripted_dry_run_provider,
)
from src.evaluation.vulnerability import (
    ALL_VULNERABILITY_CASE_IDS,
    ALL_VULNERABILITY_CASES,
    FAKE_CREDENTIAL_VALUE,
    VulnerabilityCategory,
    get_vulnerability_case,
)
from src.models.security_finding import Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raw_finding(
    *,
    category: str = "sql injection",
    title: str = "SQL injection",
    file: str = "app/db.py",
    start_line: int = 7,
    end_line: int = 7,
    finding_id: str = "FIND-1",
    severity: str = "high",
    confidence: float = 0.9,
    description: str = "user input interpolated into a SQL query",
    evidence: list[str] | tuple[str, ...] = ("query = f\"SELECT ...\"",),
    remediation: str = "use parameterized queries",
) -> str:
    finding: dict[str, object] = {
        "finding_id": finding_id,
        "category": category,
        "title": title,
        "file": file,
        "start_line": start_line,
        "end_line": end_line,
        "description": description,
        "evidence": list(evidence),
        "severity": severity,
        "confidence": confidence,
        "remediation": remediation,
    }
    return json.dumps({"findings": [finding]})


def _empty_reply() -> str:
    return DEFAULT_EMPTY_RESPONSE


def _provider(
    script: dict[str, str] | None = None,
    *,
    fallback: str = DEFAULT_EMPTY_RESPONSE,
    provider_name: str = "test-provider",
    model: str = "test-model",
) -> BaselineBProvider:
    script = script or {}
    return BaselineBProvider(
        lambda messages, run_key: script.get(run_key, fallback),
        provider_name=provider_name,
        model=model,
    )


def _recording_provider(
    responses: dict[str, str],
) -> tuple[BaselineBProvider, list[tuple[str, list]]]:
    calls: list[tuple[str, list]] = []

    def raw(messages: object, run_key: str) -> str:
        calls.append((run_key, list(messages)))  # type: ignore[arg-type]
        return responses.get(run_key, DEFAULT_EMPTY_RESPONSE)

    return BaselineBProvider(raw, provider_name="recording", model="m"), calls


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
    runner = BaselineBRunner(_provider())
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
    assert result.metrics.valid_responses == 2 * len(ALL_VULNERABILITY_CASES)
    assert result.metrics.malformed_responses == 0


def test_run_aborts_on_missing_fixture_without_silent_skip(tmp_path: Path) -> None:
    harness = tmp_path / "harness"
    harness.mkdir()
    (harness / "sql_injection").mkdir()
    (harness / "sql_injection_clean").mkdir()
    runner = BaselineBRunner(_provider())
    with pytest.raises(BaselineBRuntimeError, match="fixture directory missing"):
        runner.run(fixtures_root=harness)


def test_run_rejects_unknown_case_id() -> None:
    runner = BaselineBRunner(_provider())
    with pytest.raises(BaselineBRuntimeError, match="unknown benchmark case"):
        runner.run(case_ids=["not_a_case"])


def _snapshot_corpus() -> dict[str, dict[str, str]]:
    snapshot: dict[str, dict[str, str]] = {}
    for case in ALL_VULNERABILITY_CASES:
        snapshot[case.case_id] = _fixture_hash(case.fixture_path())
        snapshot[case.clean_control_id] = _fixture_hash(case.clean_fixture_path())
    return snapshot


def test_run_does_not_modify_corpus() -> None:
    before = _snapshot_corpus()
    runner = BaselineBRunner(_provider())
    runner.run()
    assert _snapshot_corpus() == before


# ---------------------------------------------------------------------------
# Matching policy
# ---------------------------------------------------------------------------


def test_valid_llm_finding_counts_true_positive() -> None:
    runner = BaselineBRunner(
        _provider({"sql_injection:vulnerable": _raw_finding()})
    )
    result = runner.run(case_ids=["sql_injection"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is True
    assert vulnerable.false_negative is False
    assert vulnerable.false_positive_count == 0
    assert len(vulnerable.matched_findings) == 1
    clean = next(c for c in result.per_case if c.variant == "clean")
    assert clean.true_negative is True


def test_vulnerable_case_without_matching_finding_is_false_negative() -> None:
    runner = BaselineBRunner(_provider())
    result = runner.run(case_ids=["xss"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is False
    assert vulnerable.false_negative is True
    assert vulnerable.false_positive_count == 0


def test_any_clean_control_finding_is_false_positive() -> None:
    runner = BaselineBRunner(
        _provider({"sql_injection:clean": _raw_finding()})
    )
    result = runner.run(case_ids=["sql_injection"])
    clean_case = next(c for c in result.per_case if c.variant == "clean")
    assert clean_case.false_positive_count == 1
    assert clean_case.true_positive is False
    assert clean_case.true_negative is False
    assert clean_case.matched_findings == []
    assert clean_case.duplicate_findings == []
    assert len(clean_case.unmatched_findings) == 1
    vulnerable_case = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable_case.true_positive is False


def test_wrong_category_is_not_true_positive() -> None:
    runner = BaselineBRunner(
        _provider(
            {
                "sql_injection:vulnerable": _raw_finding(
                    category="cross-site scripting",
                    title="Stored XSS",
                    file="app/db.py",
                    start_line=7,
                )
            }
        )
    )
    result = runner.run(case_ids=["sql_injection"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is False
    assert vulnerable.false_negative is True
    assert vulnerable.false_positive_count == 1


def test_wrong_file_is_not_true_positive() -> None:
    runner = BaselineBRunner(
        _provider(
            {"sql_injection:vulnerable": _raw_finding(file="app/web.py", start_line=7)}
        )
    )
    result = runner.run(case_ids=["sql_injection"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is False
    assert vulnerable.false_negative is True
    assert vulnerable.false_positive_count == 1


def test_duplicate_findings_do_not_inflate_true_positive() -> None:
    first = json.loads(_raw_finding(start_line=4))
    second = json.loads(_raw_finding(start_line=8, finding_id="FIND-2"))
    reply = json.dumps({"findings": [first["findings"][0], second["findings"][0]]})
    runner = BaselineBRunner(
        _provider({"sql_injection:vulnerable": reply})
    )
    result = runner.run(case_ids=["sql_injection"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is True
    assert len(vulnerable.duplicate_findings) == 1
    assert vulnerable.false_positive_count == 0


def test_multi_finding_docker_case_scores_one_true_positive() -> None:
    docker = json.loads(_raw_finding(
        category="docker misconfiguration",
        title="Docker: secrets baked into image",
        file="Dockerfile",
        start_line=5,
        end_line=6,
        finding_id="FIND-1",
    ))
    payload: dict[str, object] = {"findings": list(
        {**docker["findings"][0], "start_line": line, "finding_id": f"FIND-{i}"}
        for i, line in enumerate((5, 6, 0), start=1)
    )}
    runner = BaselineBRunner(
        _provider({"docker_misconfiguration:vulnerable": json.dumps(payload)})
    )
    result = runner.run(case_ids=["docker_misconfiguration"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is True
    assert len(vulnerable.matched_findings) == 1
    assert len(vulnerable.duplicate_findings) == 2
    assert vulnerable.false_positive_count == 0


def test_unlocated_line_zero_finding_matches_by_file_and_category() -> None:
    runner = BaselineBRunner(
        _provider(
            {
                "insecure_cicd:vulnerable": _raw_finding(
                    category="insecure github action",
                    title="Untrusted PR input in shell",
                    file=".github/workflows/ci.yml",
                    start_line=0,
                    end_line=0,
                )
            }
        )
    )
    result = runner.run(case_ids=["insecure_cicd"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is True
    assert vulnerable.false_positive_count == 0


def test_line_tolerance_bounds_matching() -> None:
    case = get_vulnerability_case("sql_injection")
    root = case.fixture_path()

    def at(line: int):
        return parse_baseline_response(
            _raw_finding(start_line=line, end_line=line)
        ).findings[0]

    assert finding_matches(root, at(4), case) is True
    assert finding_matches(root, at(10), case) is True
    assert finding_matches(root, at(3), case) is False
    assert finding_matches(root, at(11), case) is False


def test_severity_is_not_required_for_true_positive() -> None:
    case = get_vulnerability_case("sql_injection")
    root = case.fixture_path()
    low = parse_baseline_response(
        _raw_finding(severity="info", confidence=0.1)
    ).findings[0]
    high = parse_baseline_response(_raw_finding(severity="high")).findings[0]
    assert finding_matches(root, low, case) is True
    assert finding_matches(root, high, case) is True


def test_unmapped_category_never_counts_true_positive() -> None:
    runner = BaselineBRunner(
        _provider(
            {
                "command_injection:vulnerable": _raw_finding(
                    category="denial of service",
                    title="DoS risk",
                    file="cli/tools.py",
                    start_line=5,
                )
            }
        )
    )
    result = runner.run(case_ids=["command_injection"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is False
    assert vulnerable.false_positive_count == 1


def test_finding_without_file_is_unmatchable_false_positive() -> None:
    runner = BaselineBRunner(
        _provider(
            {"sql_injection:vulnerable": _raw_finding(file="", start_line=0)}
        )
    )
    result = runner.run(case_ids=["sql_injection"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is False
    assert vulnerable.false_positive_count == 1


# ---------------------------------------------------------------------------
# normalize_category table
# ---------------------------------------------------------------------------


def test_normalize_category_mapping() -> None:
    expected: list[tuple[str, VulnerabilityCategory]] = [
        ("SQL injection in query", VulnerabilityCategory.SQL_INJECTION),
        ("cross-site scripting", VulnerabilityCategory.XSS),
        ("command injection via os.system", VulnerabilityCategory.COMMAND_INJECTION),
        ("hardcoded API key", VulnerabilityCategory.HARDCODED_SECRET),
        ("known CVE in dependency", VulnerabilityCategory.DEPENDENCY_VULNERABILITY),
        ("insecure github actions workflow", VulnerabilityCategory.INSECURE_CI_CD),
        ("docker misconfiguration: secret in image", VulnerabilityCategory.DOCKER_MISCONFIGURATION),
    ]
    for text, category in expected:
        assert normalize_category(text) == category, text
    assert normalize_category("unrelated cleanup note") is None
    assert normalize_category("") is None


# ---------------------------------------------------------------------------
# Structured responses and malformed handling
# ---------------------------------------------------------------------------


def test_parse_accepts_bare_finding_and_bare_list() -> None:
    bare = parse_baseline_response(
        json.dumps(
            {
                "finding_id": "F1",
                "category": "SQL injection",
                "file": "app/db.py",
                "start_line": 7,
            }
        )
    )
    assert len(bare.findings) == 1
    listed = parse_baseline_response("[]")
    assert listed.findings == []
    wrapped = parse_baseline_response(_raw_finding())
    assert len(wrapped.findings) == 1
    assert isinstance(wrapped, BaselineBResponse)


def test_parse_empty_findings_is_valid_no_finding_response() -> None:
    response = parse_baseline_response(DEFAULT_EMPTY_RESPONSE)
    assert response.findings == []


def test_parse_malformed_responses_raise() -> None:
    for raw in ("", "not json {", "42", '{"no_findings": []}'):
        with pytest.raises(MalformedBaselineBResponseError):
            parse_baseline_response(raw)


def test_parse_invalid_nested_finding_invalidates_whole_response() -> None:
    raw = json.dumps({"findings": [{"category": "sql", "start_line": -5}]})
    with pytest.raises(MalformedBaselineBResponseError):
        parse_baseline_response(raw)


def test_baseline_finding_coerces_severity_confidence_and_end_line() -> None:
    response = parse_baseline_response(
        _raw_finding(severity="critical", confidence="0.87", end_line=0)
    )
    finding = response.findings[0]
    assert finding.severity == Severity.ERROR
    assert finding.confidence == 0.87
    assert finding.end_line == finding.start_line
    lenient = parse_baseline_response(
        _raw_finding(severity="weird", confidence="not-a-number")
    ).findings[0]
    assert lenient.severity == Severity.UNKNOWN
    assert lenient.confidence == 0.5


def test_malformed_response_is_recorded_and_benchmark_continues() -> None:
    script = {
        "sql_injection:vulnerable": "not json {",
        "command_injection:vulnerable": _raw_finding(
            category="command injection",
            title="Command injection",
            file="cli/tools.py",
            start_line=5,
        ),
    }
    runner = BaselineBRunner(_provider(script))
    result = runner.run(case_ids=["sql_injection", "command_injection"])
    sql = next(
        c
        for c in result.per_case
        if c.case_id == "sql_injection" and c.variant == "vulnerable"
    )
    assert sql.response_ok is False
    assert "malformed response" in sql.response_error
    assert sql.findings == []
    assert sql.true_positive is False
    assert sql.false_negative is True
    command = next(
        c
        for c in result.per_case
        if c.case_id == "command_injection" and c.variant == "vulnerable"
    )
    assert command.true_positive is True
    assert result.metrics.malformed_responses == 1
    assert result.metrics.valid_responses == 3


def test_provider_failure_is_recorded_not_crash() -> None:
    def explode(messages: object, run_key: str) -> str:
        raise ConnectionError("boom")

    runner = BaselineBRunner(
        BaselineBProvider(explode, provider_name="broken", model="none")
    )
    result = runner.run(case_ids=["sql_injection"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.response_ok is False
    assert "provider error" in vulnerable.response_error
    assert vulnerable.false_negative is True


# ---------------------------------------------------------------------------
# Input representation and prompt safety
# ---------------------------------------------------------------------------


def test_payload_includes_all_text_files_no_ground_truth() -> None:
    case = get_vulnerability_case("sql_injection")
    payload = collect_repository_payload(case.fixture_path(), "secureflow-bench/repo-01")
    paths = [f.path for f in payload.files]
    assert "app/db.py" in paths
    assert "app/web.py" in paths
    payload_text = json.dumps(payload.model_dump(mode="json"))
    for forbidden in ("expected_finding", "expected", "clean_control", "vulnerable_label"):
        assert forbidden not in payload_text


def test_payload_and_prompt_leak_no_ground_truth_to_the_llm() -> None:
    case = get_vulnerability_case("sql_injection")
    payload = collect_repository_payload(
        case.fixture_path(), sanitized_repo_identifier(case)
    )
    from src.evaluation.baseline_b import build_messages

    messages = build_messages(payload)
    user_content = messages[-1].content
    all_text = "\n".join(m.content for m in messages)
    for forbidden in (
        "sql_injection",
        "secureflow-bench/sql-injection",
        "expected_finding",
        "expected severity",
        "clean_control",
        "clean control",
        "VulnerabilityCase",
        "benchmark",
        "ground truth",
    ):
        assert forbidden not in all_text, forbidden
    assert case.repo_identifier not in user_content


def test_sanitized_repo_identifier_does_not_leak_category() -> None:
    for case in ALL_VULNERABILITY_CASES:
        identifier = sanitized_repo_identifier(case)
        assert identifier.startswith("secureflow-bench/repo-")
        assert case.category.value not in identifier
        assert identifier == sanitized_repo_identifier(case)
        clean = get_vulnerability_case(case.clean_control_id.replace("_clean", ""))
        assert identifier == sanitized_repo_identifier(clean)


def test_system_prompt_treats_repository_as_untrusted() -> None:
    assert "UNTRUSTED DATA" in BASELINE_B_SYSTEM_PROMPT
    assert "never instructions" in BASELINE_B_SYSTEM_PROMPT.lower()


def test_prompt_contains_no_category_or_severity_leak() -> None:
    lowered = BASELINE_B_SYSTEM_PROMPT.lower()
    for category in (c.value for c in VulnerabilityCategory):
        assert category not in lowered, category
    assert "error|warning|info" not in lowered


def test_payload_reads_text_files_and_skips_binary(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("print(1)\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("hello\n", encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02\xff")
    (tmp_path / "empty.txt").write_text("", encoding="utf-8")
    payload = collect_repository_payload(tmp_path, "repo")
    paths = [f.path for f in payload.files]
    assert "a.py" in paths
    assert "b.txt" in paths
    assert "blob.bin" not in paths
    assert "empty.txt" not in paths


def test_payload_respects_truncation_budget(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x" * 200, encoding="utf-8")
    (tmp_path / "b.py").write_text("y" * 200, encoding="utf-8")
    no_budget = collect_repository_payload(tmp_path, "repo", max_total_chars=0)
    assert no_budget.files == []
    truncated = collect_repository_payload(
        tmp_path, "repo", max_file_chars=5
    )
    assert truncated.files
    for file in truncated.files:
        assert "[truncated" in file.content


def test_ignore_run_key_adapter_passes_messages_only() -> None:
    seen: list[object] = []

    def raw(messages: object) -> str:
        seen.append(messages)
        return DEFAULT_EMPTY_RESPONSE

    provider = BaselineBProvider(ignore_run_key(raw), provider_name="p", model="m")
    response = provider.complete([], run_key="x:vulnerable")
    assert response.findings == []
    assert seen


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def test_metrics_math_on_controlled_scenario() -> None:
    script = {
        "sql_injection:vulnerable": _raw_finding(),
        "xss:clean": _raw_finding(category="xss", title="XSS", file="web/render.py"),
    }
    runner = BaselineBRunner(_provider(script))
    result = runner.run(case_ids=["sql_injection", "xss"])
    assert result.metrics.tp == 1
    assert result.metrics.fp == 1
    assert result.metrics.fn == 1
    assert result.metrics.precision == 0.5
    assert result.metrics.recall == 0.5
    assert result.metrics.total_vulnerable_cases == 2
    assert result.metrics.total_clean_controls == 2
    assert result.metrics.true_negative_count == 1
    assert result.metrics.total_llm_findings == 2


def test_zero_denominator_produces_zero_rates() -> None:
    runner = BaselineBRunner(_provider())
    result = runner.run(case_ids=["xss"])
    assert result.metrics.tp == 0
    assert result.metrics.fp == 0
    assert result.metrics.fn == 1
    assert result.metrics.precision == 0.0
    assert result.metrics.recall == 0.0


def test_metrics_deterministic_for_fixed_scripted_output() -> None:
    runner = BaselineBRunner(
        _provider({"sql_injection:vulnerable": _raw_finding()})
    )
    first = runner.run()
    second = runner.run()
    assert first.metrics.model_dump(mode="json") == second.metrics.model_dump(mode="json")
    assert first.num_clean_controls == len(ALL_VULNERABILITY_CASES)


def test_result_headers_and_model_info() -> None:
    runner = BaselineBRunner(
        _provider(),
        evaluation_status="dry_run",
        note="offline",
    )
    result = runner.run(case_ids=["sql_injection"])
    assert result.baseline_id == "baseline_b"
    assert result.prompt_version == BASELINE_B_PROMPT_VERSION
    assert result.evaluation_status == "dry_run"
    assert result.note == "offline"
    assert isinstance(result.model, BaselineBModelInfo)
    assert result.model.provider == "test-provider"
    assert isinstance(result, BaselineBResult)


# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------


def test_timing_is_non_negative_and_populated() -> None:
    runner = BaselineBRunner(_provider())
    result = runner.run()
    assert result.timing.total_investigation_seconds >= 0.0
    assert result.timing.mean_per_case_seconds >= 0.0
    assert result.timing.median_per_case_seconds >= 0.0
    assert all(c.investigation_duration_seconds >= 0.0 for c in result.per_case)


def test_timing_math_with_patched_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _StepClock(step=1.0)
    monkeypatch.setattr(baseline_b, "_PERF_COUNTER", clock)
    runner = BaselineBRunner(_provider())
    result = runner.run()
    variants = len(result.per_case)
    assert variants == 2 * len(ALL_VULNERABILITY_CASES)
    assert all(c.investigation_duration_seconds == 1.0 for c in result.per_case)
    assert result.timing.total_investigation_seconds == variants
    assert result.timing.mean_per_case_seconds == 1.0
    assert result.timing.median_per_case_seconds == 1.0


# ---------------------------------------------------------------------------
# Architecture: single LLM, no agents, no scanners, no network
# ---------------------------------------------------------------------------


def test_module_source_has_no_agents_tools_network_or_subprocess_imports() -> None:
    source = Path(baseline_b.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "import subprocess",
        "import urllib",
        "from urllib",
        "import http",
        "import requests",
        "import socket",
        "src.agents",
        "src.tools",
        "src.llm.fake",
    ):
        assert forbidden not in source, forbidden


def test_scripted_provider_never_claims_real_performance() -> None:
    provider = scripted_dry_run_provider()
    response = provider.complete([], run_key="x:vulnerable")
    assert response.findings == []
    assert provider.provider_name == "scripted-dry-run"
    assert provider.model == "none"


# ---------------------------------------------------------------------------
# Artifact serialization, redaction, and CLI
# ---------------------------------------------------------------------------


def test_artifact_is_json_serializable_and_contains_counts() -> None:
    runner = BaselineBRunner(
        _provider({"sql_injection:vulnerable": _raw_finding()})
    )
    result = runner.run()
    payload = result.model_dump(mode="json")
    assert payload["baseline_id"] == "baseline_b"
    assert payload["metrics"]["tp"] == 1
    json.dumps(payload)  # must not raise


def test_fake_credential_is_redacted_in_artifact() -> None:
    reply = _raw_finding(
        category="hardcoded secret",
        title="Secret in settings",
        file="config/settings.py",
        start_line=2,
        evidence=(FAKE_CREDENTIAL_VALUE,),
        description=f"token {FAKE_CREDENTIAL_VALUE}",
        remediation="move to env",
    )
    runner = BaselineBRunner(
        _provider({"hardcoded_secret:vulnerable": reply})
    )
    result = runner.run(case_ids=["hardcoded_secret"])
    dumped = json.dumps(result.model_dump(mode="json"))
    assert FAKE_CREDENTIAL_VALUE not in dumped
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.true_positive is True
    assert any("[REDACTED]" in f.evidence[0] for f in vulnerable.findings)


def test_main_defers_without_dry_run_or_script(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = tmp_path / "baseline_b.json"
    rc = main(["--out", str(out)])
    assert rc == 1
    assert not out.exists()
    assert "deferred" in capsys.readouterr().out


def test_main_dry_run_writes_labeled_artifact(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = tmp_path / "nested" / "baseline_b.json"
    rc = main(["--dry-run", "--out", str(out), "--case", "sql_injection"])
    assert rc == 0
    assert out.is_file()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["evaluation_status"] == "dry_run"
    assert data["model"]["provider"] == "scripted-dry-run"
    assert data["metrics"]["fn"] == 1
    assert data["metrics"]["true_negative_count"] == 1
    printed = capsys.readouterr().out
    assert "TP=0" in printed
    assert "dry_run" in printed


def test_main_script_drives_scoring(tmp_path: Path) -> None:
    script = tmp_path / "script.json"
    script.write_text(
        json.dumps({"sql_injection:vulnerable": _raw_finding()}),
        encoding="utf-8",
    )
    out = tmp_path / "baseline_b.json"
    rc = main(["--script", str(script), "--out", str(out), "--case", "sql_injection"])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["evaluation_status"] == "dry_run"
    assert data["metrics"]["tp"] == 1
    assert "not empirical LLM performance" in data["note"]


def test_recording_provider_shows_single_investigation_per_variant() -> None:
    provider, calls = _recording_provider(
        {"sql_injection:vulnerable": _raw_finding()}
    )
    runner = BaselineBRunner(provider)
    runner.run(case_ids=["sql_injection", "command_injection"])
    assert [key for key, _ in calls] == [
        "sql_injection:vulnerable",
        "sql_injection:clean",
        "command_injection:vulnerable",
        "command_injection:clean",
    ]


# ---------------------------------------------------------------------------
# Per-case audit fields
# ---------------------------------------------------------------------------


def test_per_case_audit_fields_populated() -> None:
    runner = BaselineBRunner(_provider())
    result = runner.run(case_ids=["command_injection"])
    vulnerable = next(c for c in result.per_case if c.variant == "vulnerable")
    assert vulnerable.case_id == "command_injection"
    assert vulnerable.category == VulnerabilityCategory.COMMAND_INJECTION
    assert vulnerable.expected_file == "cli/tools.py"
    assert vulnerable.expected_lines == [5, 5]
    assert vulnerable.findings == []
    assert vulnerable.matched_findings == []
    assert vulnerable.unmatched_findings == []
    assert vulnerable.response_ok is True
    assert vulnerable.response_error == ""
    assert isinstance(result, BaselineBResult)