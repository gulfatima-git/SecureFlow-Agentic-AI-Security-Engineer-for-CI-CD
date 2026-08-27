"""Tests for Bandit integration.

Tests use mocks for subprocess execution to remain deterministic and offline.
One integration test uses the actual Bandit binary when available.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.models.security_finding import Confidence, ScanResult, SecurityFinding, Severity
from src.tools.bandit_runner import (
    BanditNotInstalledError,
    BanditRunner,
    _find_bandit_binary,
    _has_python_files,
    _map_confidence,
    _map_severity,
    _parse_findings,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VULNERABLE_REPO = Path(__file__).parent / "fixtures" / "vulnerable_repo"

BANDIT_JSON_NO_FINDINGS = json.dumps({
    "results": [],
    "errors": [],
    "metrics": {"_totals": {}},
})

BANDIT_JSON_TWO_FINDINGS = json.dumps({
    "results": [
        {
            "test_id": "B105",
            "test_name": "hardcoded_password_string",
            "filename": "app/config.py",
            "line_number": 10,
            "line_range": [10],
            "issue_text": "Possible hardcoded password: 'secret123'",
            "issue_severity": "LOW",
            "issue_confidence": "MEDIUM",
            "code": "password = 'secret123'\n",
            "col_offset": 0,
            "end_col_offset": 22,
            "issue_cwe": {"id": 259, "link": "https://cwe.mitre.org/data/definitions/259.html"},
            "more_info": "https://bandit.readthedocs.io/en/1.9.4/plugins/b105_hardcoded_password_string.html",
        },
        {
            "test_id": "B602",
            "test_name": "subprocess_popen_with_shell_equals_true",
            "filename": "app/utils.py",
            "line_number": 45,
            "line_range": [45, 46, 47],
            "issue_text": "subprocess call with shell=True identified, security issue.",
            "issue_severity": "HIGH",
            "issue_confidence": "HIGH",
            "code": "import subprocess\nsubprocess.call(user_input, shell=True)\nreturn ''\n",
            "col_offset": 4,
            "end_col_offset": 42,
            "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
            "more_info": "https://bandit.readthedocs.io/en/1.9.4/plugins/b602_subprocess_popen_with_shell_equals_true.html",
        },
    ],
    "errors": [],
    "metrics": {"_totals": {}},
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
# Test: Severity / Confidence mapping
# ---------------------------------------------------------------------------


class TestMapping:
    def test_severity_high(self) -> None:
        assert _map_severity("HIGH") == Severity.ERROR

    def test_severity_medium(self) -> None:
        assert _map_severity("MEDIUM") == Severity.WARNING

    def test_severity_low(self) -> None:
        assert _map_severity("LOW") == Severity.INFO

    def test_severity_unknown(self) -> None:
        assert _map_severity("something_else") == Severity.UNKNOWN

    def test_severity_case_insensitive(self) -> None:
        assert _map_severity("high") == Severity.ERROR

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
        data = json.loads(BANDIT_JSON_NO_FINDINGS)
        findings = _parse_findings(data)
        assert findings == []

    def test_parse_two_findings(self) -> None:
        data = json.loads(BANDIT_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert len(findings) == 2

    def test_finding_rule_id(self) -> None:
        data = json.loads(BANDIT_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].rule_id == "B105.hardcoded_password_string"
        assert findings[1].rule_id == "B602.subprocess_popen_with_shell_equals_true"

    def test_finding_severity_mapped(self) -> None:
        data = json.loads(BANDIT_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].severity == Severity.INFO  # LOW -> INFO
        assert findings[1].severity == Severity.ERROR  # HIGH -> ERROR

    def test_finding_confidence_mapped(self) -> None:
        data = json.loads(BANDIT_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].confidence == Confidence.MEDIUM
        assert findings[1].confidence == Confidence.HIGH

    def test_finding_file_path(self) -> None:
        data = json.loads(BANDIT_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].file_path == "app/config.py"
        assert findings[1].file_path == "app/utils.py"

    def test_finding_line_numbers(self) -> None:
        data = json.loads(BANDIT_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].start_line == 10
        assert findings[0].end_line == 10
        assert findings[1].start_line == 45
        assert findings[1].end_line == 47

    def test_finding_columns(self) -> None:
        data = json.loads(BANDIT_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].start_column == 0
        assert findings[0].end_column == 22
        assert findings[1].start_column == 4
        assert findings[1].end_column == 42

    def test_finding_message(self) -> None:
        data = json.loads(BANDIT_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].message == "Possible hardcoded password: 'secret123'"
        assert findings[1].message == "subprocess call with shell=True identified, security issue."

    def test_finding_code_snippet(self) -> None:
        data = json.loads(BANDIT_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert "secret123" in findings[0].code_snippet
        assert "shell=True" in findings[1].code_snippet

    def test_finding_metadata_cwe(self) -> None:
        data = json.loads(BANDIT_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].metadata["cwe"] == "CWE-259"
        assert findings[0].metadata["cwe_link"] == "https://cwe.mitre.org/data/definitions/259.html"

    def test_finding_metadata_more_info(self) -> None:
        data = json.loads(BANDIT_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert "bandit.readthedocs.io" in findings[0].metadata["more_info"]

    def test_finding_tool_is_bandit(self) -> None:
        data = json.loads(BANDIT_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].tool == "bandit"
        assert findings[1].tool == "bandit"

    def test_finding_category_is_security(self) -> None:
        data = json.loads(BANDIT_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        assert findings[0].category == "security"
        assert findings[1].category == "security"

    def test_parse_malformed_result_gracefully(self) -> None:
        """A result missing expected fields should not crash parsing."""
        data = {"results": [{"test_id": "B999"}], "errors": []}
        findings = _parse_findings(data)
        assert len(findings) == 1
        assert findings[0].rule_id == "B999"
        assert findings[0].severity == Severity.UNKNOWN


# ---------------------------------------------------------------------------
# Test: Python file detection
# ---------------------------------------------------------------------------


class TestPythonFileDetection:
    def test_repo_with_python_files(self) -> None:
        assert _has_python_files(VULNERABLE_REPO) is True

    def test_empty_dir_no_python_files(self, tmp_path: Path) -> None:
        (tmp_path / "readme.txt").write_text("no python here")
        assert _has_python_files(tmp_path) is False

    def test_pycache_excluded(self, tmp_path: Path) -> None:
        cache_dir = tmp_path / "__pycache__"
        cache_dir.mkdir()
        (cache_dir / "cached.py").write_text("# cached")
        assert _has_python_files(tmp_path) is False

    def test_git_dir_excluded(self, tmp_path: Path) -> None:
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "hook.py").write_text("# hook")
        assert _has_python_files(tmp_path) is False

    def test_nested_python_files_detected(self, tmp_path: Path) -> None:
        nested = tmp_path / "src" / "pkg"
        nested.mkdir(parents=True)
        (nested / "mod.py").write_text("# module")
        assert _has_python_files(tmp_path) is True


# ---------------------------------------------------------------------------
# Test: Binary resolution
# ---------------------------------------------------------------------------


class TestBinaryResolution:
    def test_explicit_path_valid(self, tmp_path: Path) -> None:
        fake_bin = tmp_path / "bandit.exe"
        fake_bin.write_text("")
        result = _find_bandit_binary(str(fake_bin))
        assert result == str(fake_bin)

    def test_explicit_path_invalid(self) -> None:
        with pytest.raises(BanditNotInstalledError, match="not found at"):
            _find_bandit_binary("/nonexistent/bandit")


# ---------------------------------------------------------------------------
# Test: Runner with mocked subprocess
# ---------------------------------------------------------------------------


class TestRunnerMocked:
    def test_scan_invalid_path(self) -> None:
        runner = BanditRunner.__new__(BanditRunner)
        runner._binary = "bandit"
        runner._timeout = 300

        result = runner.scan("/nonexistent/path")
        assert result.status == "error"
        assert "does not exist" in result.error_message
        assert result.findings == []

    def test_scan_success_zero_findings(self, tmp_path: Path) -> None:
        runner = BanditRunner.__new__(BanditRunner)
        runner._binary = "bandit"
        runner._timeout = 300
        (tmp_path / "dummy.py").write_text("# placeholder")

        with patch("src.tools.bandit_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout=BANDIT_JSON_NO_FINDINGS,
                returncode=0,
            )
            result = runner.scan(tmp_path)

        assert result.status == "success"
        assert result.findings_count == 0
        assert result.findings == []

    def test_scan_success_with_findings(self, tmp_path: Path) -> None:
        runner = BanditRunner.__new__(BanditRunner)
        runner._binary = "bandit"
        runner._timeout = 300
        (tmp_path / "dummy.py").write_text("# placeholder")

        with patch("src.tools.bandit_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout=BANDIT_JSON_TWO_FINDINGS,
                returncode=0,
            )
            result = runner.scan(tmp_path)

        assert result.status == "success"
        assert result.findings_count == 2

    def test_scan_exit_code_1_with_findings(self, tmp_path: Path) -> None:
        """Exit code 1 from Bandit with --exit-zero should still be success."""
        runner = BanditRunner.__new__(BanditRunner)
        runner._binary = "bandit"
        runner._timeout = 300
        (tmp_path / "dummy.py").write_text("# placeholder")

        with patch("src.tools.bandit_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout=BANDIT_JSON_TWO_FINDINGS,
                returncode=0,
            )
            result = runner.scan(tmp_path)

        assert result.status == "success"
        assert result.findings_count == 2

    def test_scan_high_exit_code_is_error(self, tmp_path: Path) -> None:
        """Exit code >= 2 indicates a real Bandit failure."""
        runner = BanditRunner.__new__(BanditRunner)
        runner._binary = "bandit"
        runner._timeout = 300
        (tmp_path / "dummy.py").write_text("# placeholder")

        with patch("src.tools.bandit_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout="",
                stderr="Fatal error",
                returncode=2,
            )
            result = runner.scan(tmp_path)

        assert result.status == "error"
        assert "exited with code 2" in result.error_message

    def test_scan_timeout(self, tmp_path: Path) -> None:
        runner = BanditRunner.__new__(BanditRunner)
        runner._binary = "bandit"
        runner._timeout = 300
        (tmp_path / "dummy.py").write_text("# placeholder")

        with patch("src.tools.bandit_runner.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="bandit", timeout=300)
            result = runner.scan(tmp_path)

        assert result.status == "timeout"
        assert "exceeded" in result.error_message

    def test_scan_binary_not_found(self, tmp_path: Path) -> None:
        runner = BanditRunner.__new__(BanditRunner)
        runner._binary = "bandit"
        runner._timeout = 300
        (tmp_path / "dummy.py").write_text("# placeholder")

        with patch("src.tools.bandit_runner.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("bandit not found")
            result = runner.scan(tmp_path)

        assert result.status == "error"
        assert "not found" in result.error_message

    def test_scan_os_error(self, tmp_path: Path) -> None:
        runner = BanditRunner.__new__(BanditRunner)
        runner._binary = "bandit"
        runner._timeout = 300
        (tmp_path / "dummy.py").write_text("# placeholder")

        with patch("src.tools.bandit_runner.subprocess.run") as mock_run:
            mock_run.side_effect = OSError("permission denied")
            result = runner.scan(tmp_path)

        assert result.status == "error"
        assert "Failed to execute" in result.error_message

    def test_scan_invalid_json_output(self, tmp_path: Path) -> None:
        runner = BanditRunner.__new__(BanditRunner)
        runner._binary = "bandit"
        runner._timeout = 300
        (tmp_path / "dummy.py").write_text("# placeholder")

        with patch("src.tools.bandit_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout="this is not json {{{",
                returncode=0,
            )
            result = runner.scan(tmp_path)

        assert result.status == "error"
        assert "parse" in result.error_message.lower()

    def test_scan_duration_recorded(self, tmp_path: Path) -> None:
        runner = BanditRunner.__new__(BanditRunner)
        runner._binary = "bandit"
        runner._timeout = 300
        (tmp_path / "dummy.py").write_text("# placeholder")

        with patch("src.tools.bandit_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout=BANDIT_JSON_NO_FINDINGS,
                returncode=0,
            )
            result = runner.scan(tmp_path)

        assert result.scan_duration_seconds >= 0

    def test_scan_command_recorded(self, tmp_path: Path) -> None:
        runner = BanditRunner.__new__(BanditRunner)
        runner._binary = "bandit"
        runner._timeout = 300
        (tmp_path / "dummy.py").write_text("# placeholder")

        with patch("src.tools.bandit_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout=BANDIT_JSON_NO_FINDINGS,
                returncode=0,
            )
            result = runner.scan(tmp_path)

        assert "bandit" in result.command
        assert "-f" in result.command
        assert "json" in result.command

    def test_scan_no_shell_execution(self, tmp_path: Path) -> None:
        """Verify shell=False is used — no shell injection possible."""
        runner = BanditRunner.__new__(BanditRunner)
        runner._binary = "bandit"
        runner._timeout = 300
        (tmp_path / "dummy.py").write_text("# placeholder")

        with patch("src.tools.bandit_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout=BANDIT_JSON_NO_FINDINGS,
                returncode=0,
            )
            runner.scan(tmp_path)
            _, kwargs = mock_run.call_args
            assert kwargs.get("shell") is False

    def test_runner_init_with_explicit_path(self, tmp_path: Path) -> None:
        fake_bin = tmp_path / "bandit"
        fake_bin.write_text("")
        runner = BanditRunner(bandit_path=str(fake_bin))
        assert runner.bandit_path == str(fake_bin)

    def test_no_python_files_skips_scan(self, tmp_path: Path) -> None:
        """When no Python files exist, Bandit should not be invoked."""
        runner = BanditRunner.__new__(BanditRunner)
        runner._binary = "bandit"
        runner._timeout = 300

        (tmp_path / "readme.txt").write_text("no python here")

        with patch("src.tools.bandit_runner.subprocess.run") as mock_run:
            result = runner.scan(tmp_path)

        mock_run.assert_not_called()
        assert result.status == "success"
        assert "skipped" in result.error_message.lower()

    def test_tool_version_recorded(self, tmp_path: Path) -> None:
        runner = BanditRunner.__new__(BanditRunner)
        runner._binary = "bandit"
        runner._timeout = 300
        (tmp_path / "dummy.py").write_text("# placeholder")

        with patch("src.tools.bandit_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout=BANDIT_JSON_NO_FINDINGS,
                returncode=0,
            )
            result = runner.scan(tmp_path)

        assert result.tool_version == "1.9.4"

    def test_stderr_does_not_cause_error(self, tmp_path: Path) -> None:
        """Bandit logs INFO messages to stderr; these should not cause an error."""
        runner = BanditRunner.__new__(BanditRunner)
        runner._binary = "bandit"
        runner._timeout = 300
        (tmp_path / "dummy.py").write_text("# placeholder")

        with patch("src.tools.bandit_runner.subprocess.run") as mock_run:
            mock_run.return_value = _mock_subprocess_run(
                stdout=BANDIT_JSON_NO_FINDINGS,
                stderr="[main]\tINFO\tprofile include tests: None\n",
                returncode=0,
            )
            result = runner.scan(tmp_path)

        assert result.status == "success"


# ---------------------------------------------------------------------------
# Test: Shared normalization interoperability
# ---------------------------------------------------------------------------


class TestSharedNormalization:
    """Verify Bandit findings use the same SecurityFinding model as Semgrep."""

    def test_finding_is_pydantic_model(self) -> None:
        data = json.loads(BANDIT_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        for f in findings:
            assert isinstance(f, SecurityFinding)

    def test_scan_result_is_pydantic_model(self) -> None:
        data = json.loads(BANDIT_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        result = ScanResult(tool="bandit", findings=findings, findings_count=len(findings))
        assert isinstance(result, ScanResult)
        assert result.tool == "bandit"

    def test_findings_serializable_to_dict(self) -> None:
        data = json.loads(BANDIT_JSON_TWO_FINDINGS)
        findings = _parse_findings(data)
        for f in findings:
            d = f.model_dump()
            assert "tool" in d
            assert d["tool"] == "bandit"
            assert "rule_id" in d
            assert "severity" in d


# ---------------------------------------------------------------------------
# Test: Integration (requires Bandit on PATH)
# ---------------------------------------------------------------------------


def _is_bandit_available() -> bool:
    """Check whether bandit is reachable on this system."""
    try:
        _find_bandit_binary()
        return True
    except BanditNotInstalledError:
        return False


@pytest.mark.skipif(
    not _is_bandit_available(),
    reason="Bandit not installed — skipping integration test",
)
class TestIntegration:
    def test_scan_vulnerable_repo(self) -> None:
        runner = BanditRunner(timeout=120)
        result = runner.scan(VULNERABLE_REPO)

        assert result.status == "success"
        assert result.findings_count > 0, (
            "Expected Bandit to find at least one finding in the "
            "vulnerable test fixture"
        )

        paths = {f.file_path for f in result.findings}
        assert any("vulnerable" in p for p in paths), (
            f"Expected a finding in vulnerable.py, got paths: {paths}"
        )

    def test_scan_clean_repo(self, tmp_path: Path) -> None:
        """A directory with no Python files should produce zero findings."""
        (tmp_path / "empty.txt").write_text("nothing here")
        runner = BanditRunner(timeout=60)
        result = runner.scan(tmp_path)
        assert result.status == "success"
        assert result.findings_count == 0
        assert "skipped" in result.error_message.lower()
