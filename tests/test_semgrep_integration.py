"""Tests for Semgrep integration.

Tests use mocks for subprocess execution to remain deterministic and offline.
One integration test uses the actual Semgrep binary when available.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.models.security_finding import Confidence, ScanResult, SecurityFinding, Severity
from src.tools.semgrep_runner import (
    SemgrepNotInstalledError,
    SemgrepRunner,
    _find_semgrep_binary,
    _map_confidence,
    _map_severity,
    _parse_findings,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VULNERABLE_REPO = Path(__file__).parent / "fixtures" / "vulnerable_repo"

SEMGREP_JSON_NO_FINDINGS = json.dumps({
    "results": [],
    "errors": [],
    "version": "1.75.0",
})

SEMGREP_JSON_TWO_FINDINGS = json.dumps({
    "results": [
        {
            "check_id": "python.lang.security.audit.hardcoded-password",
            "path": "vulnerable.py",
            "start": {"line": 7, "col": 1},
            "end": {"line": 7, "col": 35},
            "extra": {
                "message": "Hardcoded password detected",
                "severity": "WARNING",
                "metadata": {
                    "category": "security",
                    "confidence": "HIGH",
                    "cwe": ["CWE-798"],
                },
                "lines": ["password = \"super_secret_123\""],
            },
        },
        {
            "check_id": "python.lang.security.audit.sql-injection",
            "path": "vulnerable.py",
            "start": {"line": 12, "col": 5},
            "end": {"line": 12, "col": 50},
            "extra": {
                "message": "User input in SQL query",
                "severity": "ERROR",
                "metadata": {"category": "security"},
                "lines": ["query = f\"SELECT * FROM users WHERE id = {user_id}\""],
            },
        },
    ],
    "errors": [],
    "version": "1.75.0",
})


def _mock_subprocess_run(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> MagicMock:
    """Create a mock for subprocess.run that returns fixed output."""
    mock_result = MagicMock()
    mock_result.stdout = stdout
    mock_result.stderr = stderr
    mock_result.returncode = returncode
    return mock_result


# ---------------------------------------------------------------------------
# Test: SecurityFinding model
# ---------------------------------------------------------------------------


class TestSecurityFinding:
    def test_finding_creation(self) -> None:
        f = SecurityFinding(
            tool="semgrep",
            rule_id="test.rule",
            severity=Severity.WARNING,
            message="test message",
            file_path="test.py",
            start_line=1,
            end_line=5,
        )
        assert f.tool == "semgrep"
        assert f.rule_id == "test.rule"
        assert f.severity == Severity.WARNING
        assert f.start_line == 1
        assert f.end_line == 5

    def test_finding_defaults(self) -> None:
        f = SecurityFinding(tool="x", rule_id="y")
        assert f.severity == Severity.UNKNOWN
        assert f.confidence == Confidence.UNKNOWN
        assert f.file_path == ""
        assert f.start_line == 0
        assert f.metadata == {}

    def test_finding_with_metadata(self) -> None:
        meta = {"cwe": "CWE-798", "owasp": "A7"}
        f = SecurityFinding(
            tool="semgrep",
            rule_id="r",
            metadata=meta,
        )
        assert f.metadata["cwe"] == "CWE-798"


class TestScanResult:
    def test_scan_result_defaults(self) -> None:
        r = ScanResult(tool="semgrep")
        assert r.status == "success"
        assert r.findings == []
        assert r.findings_count == 0

    def test_scan_result_with_findings(self) -> None:
        findings = [
            SecurityFinding(tool="semgrep", rule_id="a"),
            SecurityFinding(tool="semgrep", rule_id="b"),
        ]
        r = ScanResult(tool="semgrep", findings=findings, findings_count=2)
        assert len(r.findings) == 2
        assert r.findings_count == 2


# ---------------------------------------------------------------------------
# Test: Severity / Confidence mapping
# ---------------------------------------------------------------------------


class TestMapping:
    def test_severity_error(self) -> None:
        assert _map_severity("ERROR") == Severity.ERROR

    def test_severity_warning(self) -> None:
        assert _map_severity("WARNING") == Severity.WARNING

    def test_severity_info(self) -> None:
        assert _map_severity("INFO") == Severity.INFO

    def test_severity_unknown(self) -> None:
        assert _map_severity("something_else") == Severity.UNKNOWN

    def test_severity_case_insensitive(self) -> None:
        assert _map_severity("error") == Severity.ERROR

    def test_confidence_high(self) -> None:
        assert _map_confidence("HIGH") == Confidence.HIGH

    def test_confidence_medium(self) -> None:
        assert _map_confidence("MEDIUM") == Confidence.MEDIUM

    def test_confidence_low(self) -> None:
        assert _map_confidence("LOW") == Confidence.LOW

    def test_confidence_unknown(self) -> None:
        assert _map_confidence("") == Confidence.UNKNOWN

    def test_confidence_case_insensitive(self) -> None:
        assert _map_confidence("high") == Confidence.HIGH


# ---------------------------------------------------------------------------
# Test: JSON parsing
# ---------------------------------------------------------------------------


class TestParsing:
    def test_parse_empty_results(self) -> None:
        data = json.loads(SEMGREP_JSON_NO_FINDINGS)
        findings = _parse_findings(data)
        assert findings == []

    def test_parse_two_findings(self) -> None:
        data = json.loads(SEMGREP_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert len(findings) == 2

    def test_finding_rule_id(self) -> None:
        data = json.loads(SEMGREP_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].rule_id == "python.lang.security.audit.hardcoded-password"
        assert findings[1].rule_id == "python.lang.security.audit.sql-injection"

    def test_finding_severity_mapped(self) -> None:
        data = json.loads(SEMGREP_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].severity == Severity.WARNING
        assert findings[1].severity == Severity.ERROR

    def test_finding_file_path(self) -> None:
        data = json.loads(SEMGREP_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].file_path == "vulnerable.py"
        assert findings[1].file_path == "vulnerable.py"

    def test_finding_line_numbers(self) -> None:
        data = json.loads(SEMGREP_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].start_line == 7
        assert findings[0].end_line == 7
        assert findings[1].start_line == 12
        assert findings[1].end_line == 12

    def test_finding_columns(self) -> None:
        data = json.loads(SEMGREP_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].start_column == 1
        assert findings[0].end_column == 35

    def test_finding_message(self) -> None:
        data = json.loads(SEMGREP_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].message == "Hardcoded password detected"
        assert findings[1].message == "User input in SQL query"

    def test_finding_code_snippet(self) -> None:
        data = json.loads(SEMGREP_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert "super_secret" in findings[0].code_snippet

    def test_finding_metadata(self) -> None:
        data = json.loads(SEMGREP_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].metadata.get("cwe") == "CWE-798"
        assert findings[0].metadata.get("confidence") == "HIGH"

    def test_finding_category_from_metadata(self) -> None:
        data = json.loads(SEMGREP_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].category == "security"

    def test_finding_tool_is_semgrep(self) -> None:
        data = json.loads(SEMGREP_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].tool == "semgrep"

    def test_parse_malformed_result_gracefully(self) -> None:
        """A result missing expected fields should not crash parsing."""
        data = {"results": [{"check_id": "x"}], "errors": []}
        findings = _parse_findings(data)
        assert len(findings) == 1
        assert findings[0].rule_id == "x"
        assert findings[0].severity == Severity.UNKNOWN


# ---------------------------------------------------------------------------
# Test: Binary resolution
# ---------------------------------------------------------------------------


class TestBinaryResolution:
    def test_explicit_path_valid(self, tmp_path: Path) -> None:
        fake_bin = tmp_path / "semgrep.exe"
        fake_bin.write_text("")
        result = _find_semgrep_binary(str(fake_bin))
        assert result == str(fake_bin)

    def test_explicit_path_invalid(self) -> None:
        with pytest.raises(SemgrepNotInstalledError, match="not found at"):
            _find_semgrep_binary("/nonexistent/semgrep")


# ---------------------------------------------------------------------------
# Test: Runner with mocked subprocess
# ---------------------------------------------------------------------------


class TestRunnerMocked:
    def test_scan_invalid_path(self) -> None:
        runner = SemgrepRunner.__new__(SemgrepRunner)
        runner._binary = "semgrep"
        runner._config = "p/default"
        runner._timeout = 300

        result = runner.scan("/nonexistent/path")
        assert result.status == "error"
        assert "does not exist" in result.error_message
        assert result.findings == []

    def test_scan_success_zero_findings(self, tmp_path: Path) -> None:
        runner = SemgrepRunner.__new__(SemgrepRunner)
        runner._binary = "semgrep"
        runner._config = "p/default"
        runner._timeout = 300

        with patch("src.tools.semgrep_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout=SEMGREP_JSON_NO_FINDINGS,
                returncode=0,
            )
            result = runner.scan(tmp_path)

        assert result.status == "success"
        assert result.findings_count == 0
        assert result.findings == []

    def test_scan_success_with_findings(self, tmp_path: Path) -> None:
        runner = SemgrepRunner.__new__(SemgrepRunner)
        runner._binary = "semgrep"
        runner._config = "p/default"
        runner._timeout = 300

        with patch("src.tools.semgrep_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout=SEMGREP_JSON_TWO_FINDINGS,
                returncode=1,  # Exit code 1 = findings found (not an error)
            )
            result = runner.scan(tmp_path)

        assert result.status == "success"
        assert result.findings_count == 2
        assert result.tool_version == "1.75.0"

    def test_scan_nonzero_exit_code_is_not_error(self, tmp_path: Path) -> None:
        """Exit code 1 from Semgrep means findings were found, not that it failed."""
        runner = SemgrepRunner.__new__(SemgrepRunner)
        runner._binary = "semgrep"
        runner._config = "p/default"
        runner._timeout = 300

        with patch("src.tools.semgrep_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout=SEMGREP_JSON_TWO_FINDINGS,
                returncode=1,
            )
            result = runner.scan(tmp_path)

        assert result.status == "success"
        assert result.findings_count == 2

    def test_scan_high_exit_code_is_error(self, tmp_path: Path) -> None:
        """Exit code >= 2 indicates a real Semgrep failure."""
        runner = SemgrepRunner.__new__(SemgrepRunner)
        runner._binary = "semgrep"
        runner._config = "p/default"
        runner._timeout = 300

        with patch("src.tools.semgrep_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout="",
                stderr="Fatal error",
                returncode=2,
            )
            result = runner.scan(tmp_path)

        assert result.status == "error"
        assert "exited with code 2" in result.error_message

    def test_scan_timeout(self, tmp_path: Path) -> None:
        runner = SemgrepRunner.__new__(SemgrepRunner)
        runner._binary = "semgrep"
        runner._config = "p/default"
        runner._timeout = 300

        with patch("src.tools.semgrep_runner.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="semgrep", timeout=300)
            result = runner.scan(tmp_path)

        assert result.status == "timeout"
        assert "exceeded" in result.error_message

    def test_scan_binary_not_found(self, tmp_path: Path) -> None:
        runner = SemgrepRunner.__new__(SemgrepRunner)
        runner._binary = "semgrep"
        runner._config = "p/default"
        runner._timeout = 300

        with patch("src.tools.semgrep_runner.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("semgrep not found")
            result = runner.scan(tmp_path)

        assert result.status == "error"
        assert "not found" in result.error_message

    def test_scan_os_error(self, tmp_path: Path) -> None:
        runner = SemgrepRunner.__new__(SemgrepRunner)
        runner._binary = "semgrep"
        runner._config = "p/default"
        runner._timeout = 300

        with patch("src.tools.semgrep_runner.subprocess.run") as mock_run:
            mock_run.side_effect = OSError("permission denied")
            result = runner.scan(tmp_path)

        assert result.status == "error"
        assert "Failed to execute" in result.error_message

    def test_scan_invalid_json_output(self, tmp_path: Path) -> None:
        runner = SemgrepRunner.__new__(SemgrepRunner)
        runner._binary = "semgrep"
        runner._config = "p/default"
        runner._timeout = 300

        with patch("src.tools.semgrep_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout="this is not json {{{",
                returncode=0,
            )
            result = runner.scan(tmp_path)

        assert result.status == "error"
        assert "parse" in result.error_message.lower()

    def test_scan_duration_recorded(self, tmp_path: Path) -> None:
        runner = SemgrepRunner.__new__(SemgrepRunner)
        runner._binary = "semgrep"
        runner._config = "p/default"
        runner._timeout = 300

        with patch("src.tools.semgrep_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout=SEMGREP_JSON_NO_FINDINGS,
                returncode=0,
            )
            result = runner.scan(tmp_path)

        assert result.scan_duration_seconds >= 0

    def test_scan_command_recorded(self, tmp_path: Path) -> None:
        runner = SemgrepRunner.__new__(SemgrepRunner)
        runner._binary = "semgrep"
        runner._config = "p/default"
        runner._timeout = 300

        with patch("src.tools.semgrep_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout=SEMGREP_JSON_NO_FINDINGS,
                returncode=0,
            )
            result = runner.scan(tmp_path)

        assert "semgrep" in result.command
        assert "--json" in result.command

    def test_scan_no_shell_execution(self, tmp_path: Path) -> None:
        """Verify shell=False is used — no shell injection possible."""
        runner = SemgrepRunner.__new__(SemgrepRunner)
        runner._binary = "semgrep"
        runner._config = "p/default"
        runner._timeout = 300

        with patch("src.tools.semgrep_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout=SEMGREP_JSON_NO_FINDINGS,
                returncode=0,
            )
            runner.scan(tmp_path)
            _, kwargs = mock_run.call_args
            assert kwargs.get("shell") is False

    def test_runner_init_with_explicit_path(self, tmp_path: Path) -> None:
        fake_bin = tmp_path / "semgrep"
        fake_bin.write_text("")
        runner = SemgrepRunner(semgrep_path=str(fake_bin))
        assert runner.semgrep_path == str(fake_bin)


# ---------------------------------------------------------------------------
# Test: Vulnerable fixture (integration, requires Semgrep on PATH)
# ---------------------------------------------------------------------------


def _is_semgrep_available() -> bool:
    """Check whether semgrep is reachable on this system."""
    try:
        _find_semgrep_binary()
        return True
    except SemgrepNotInstalledError:
        return False


@pytest.mark.skipif(
    not _is_semgrep_available(),
    reason="Semgrep not installed — skipping integration test",
)
class TestIntegration:
    def test_scan_vulnerable_repo(self) -> None:
        runner = SemgrepRunner(config="p/default", timeout=120)
        result = runner.scan(VULNERABLE_REPO)

        assert result.status == "success"
        assert result.findings_count > 0, (
            "Expected Semgrep to find at least one finding in the "
            "vulnerable test fixture"
        )

        # Verify that at least one finding references the vulnerable file.
        paths = {f.file_path for f in result.findings}
        assert any("vulnerable" in p for p in paths), (
            f"Expected a finding in vulnerable.py, got paths: {paths}"
        )

    def test_scan_clean_repo(self, tmp_path: Path) -> None:
        """A directory with no source files should produce zero findings."""
        (tmp_path / "empty.txt").write_text("nothing here")
        runner = SemgrepRunner(config="p/default", timeout=60)
        result = runner.scan(tmp_path)
        assert result.status == "success"
        assert result.findings_count == 0
