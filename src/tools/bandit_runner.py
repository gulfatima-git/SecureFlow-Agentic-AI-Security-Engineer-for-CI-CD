"""Bandit runner: execute Bandit and convert results to SecurityFinding objects."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from src.models.security_finding import (
    Confidence,
    ScanResult,
    SecurityFinding,
    Severity,
)

DEFAULT_TIMEOUT = 300  # seconds
BANDIT_TOOL_NAME = "bandit"


class BanditError(Exception):
    """Raised when Bandit execution fails."""


class BanditNotInstalledError(BanditError):
    """Raised when the Bandit binary is not found."""


class BanditTimeoutError(BanditError):
    """Raised when a Bandit scan exceeds the time limit."""


def _find_bandit_binary(explicit_path: str | None = None) -> str:
    """Locate the Bandit binary.

    Resolution order:
      1. Explicit path provided by caller.
      2. ``shutil.which("bandit")`` — searches PATH.
      3. ``shutil.which("bandit", path=str(scripts_dir))`` — checks common
         pip install locations.

    Returns:
        The absolute path to the Bandit binary.

    Raises:
        BanditNotInstalledError: If no binary is found.
    """
    if explicit_path:
        p = Path(explicit_path)
        if p.is_file():
            return str(p)
        raise BanditNotInstalledError(f"Bandit binary not found at: {explicit_path}")

    found = shutil.which("bandit")
    if found:
        return found

    scripts_dir = Path(sys.prefix) / "Scripts"
    found = shutil.which("bandit", path=str(scripts_dir))
    if found:
        return found

    import site

    for site_dir in site.getusersitepackages():
        user_scripts = Path(site_dir).parent / "Scripts"
        found = shutil.which("bandit", path=str(user_scripts))
        if found:
            return found

    raise BanditNotInstalledError(
        "Bandit is not installed or not on PATH. "
        "Install with: pip install bandit"
    )


def _has_python_files(repository_path: Path) -> bool:
    """Check whether a directory contains any Python source files.

    Excludes common generated/hidden directories to avoid unnecessary scans.
    """
    excluded = {".git", "__pycache__", ".mypy_cache", ".pytest_cache", "node_modules", ".tox"}
    for item in repository_path.rglob("*.py"):
        if not any(part in excluded for part in item.relative_to(repository_path).parts):
            return True
    return False


def _map_severity(raw: str) -> Severity:
    """Map a Bandit severity string to our normalized Severity enum."""
    upper = raw.upper().strip()
    mapping = {
        "HIGH": Severity.ERROR,
        "MEDIUM": Severity.WARNING,
        "LOW": Severity.INFO,
    }
    return mapping.get(upper, Severity.UNKNOWN)


def _map_confidence(raw: str) -> Confidence:
    """Map a Bandit confidence string to our normalized Confidence enum."""
    upper = raw.upper().strip()
    mapping = {
        "HIGH": Confidence.HIGH,
        "MEDIUM": Confidence.MEDIUM,
        "LOW": Confidence.LOW,
    }
    return mapping.get(upper, Confidence.UNKNOWN)


def _stringify_metadata(raw: object) -> dict[str, str]:
    """Convert Bandit metadata to a flat string-valued dict."""
    if not isinstance(raw, dict):
        return {}
    result: dict[str, str] = {}
    for k, v in raw.items():
        if isinstance(v, dict):
            result[str(k)] = json.dumps(v)
        elif isinstance(v, list):
            result[str(k)] = ", ".join(str(item) for item in v)
        else:
            result[str(k)] = str(v)
    return result


def _parse_findings(data: dict[str, Any]) -> list[SecurityFinding]:
    """Parse Bandit JSON output into SecurityFinding objects."""
    findings: list[SecurityFinding] = []
    for result in data.get("results", []):
        test_id = result.get("test_id", "")
        test_name = result.get("test_name", "")
        filename = result.get("filename", "")
        line_number = result.get("line_number", 0)
        issue_text = result.get("issue_text", "")
        raw_severity = result.get("issue_severity", "")
        raw_confidence = result.get("issue_confidence", "")
        code_snippet = result.get("code", "")
        col_offset = result.get("col_offset", 0)
        end_col_offset = result.get("end_col_offset", 0)
        line_range = result.get("line_range", [])

        rule_id = test_id
        if test_name:
            rule_id = f"{test_id}.{test_name}" if test_id else test_name

        end_line = line_number
        if isinstance(line_range, list) and len(line_range) > 1:
            end_line = line_range[-1]

        metadata: dict[str, str] = {}
        cwe = result.get("issue_cwe")
        if isinstance(cwe, dict) and cwe:
            metadata["cwe"] = f"CWE-{cwe.get('id', '')}"
            link = cwe.get("link", "")
            if link:
                metadata["cwe_link"] = link
        more_info = result.get("more_info", "")
        if more_info:
            metadata["more_info"] = more_info
        metadata["test_name"] = test_name

        findings.append(
            SecurityFinding(
                tool=BANDIT_TOOL_NAME,
                rule_id=rule_id,
                severity=_map_severity(raw_severity),
                confidence=_map_confidence(raw_confidence),
                message=issue_text,
                file_path=filename,
                start_line=line_number,
                end_line=end_line,
                start_column=col_offset,
                end_column=end_col_offset,
                code_snippet=code_snippet,
                category="security",
                metadata=metadata,
            )
        )
    return findings


class BanditRunner:
    """Runs Bandit against a repository and returns structured findings.

    Example::

        runner = BanditRunner()
        result = runner.scan("/path/to/repo")
        for finding in result.findings:
            print(finding.rule_id, finding.file_path)
    """

    def __init__(
        self,
        *,
        bandit_path: str | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        """Initialize the runner.

        Args:
            bandit_path: Explicit path to the bandit binary. If None,
                the binary is located automatically.
            timeout: Maximum scan time in seconds.
        """
        self._binary = _find_bandit_binary(bandit_path)
        self._timeout = timeout

    @property
    def bandit_path(self) -> str:
        return self._binary

    def scan(self, repository_path: str | Path) -> ScanResult:
        """Run Bandit against the given repository directory.

        Args:
            repository_path: Path to the repository root to scan.

        Returns:
            A ScanResult containing findings and execution metadata.
        """
        repo_path = Path(repository_path)
        if not repo_path.is_dir():
            return ScanResult(
                tool=BANDIT_TOOL_NAME,
                status="error",
                error_message=f"Repository path does not exist or is not a directory: {repo_path}",
            )

        if not _has_python_files(repo_path):
            return ScanResult(
                tool=BANDIT_TOOL_NAME,
                status="success",
                error_message="No Python files found — Bandit scan skipped",
            )

        cmd = [
            self._binary,
            "-r",
            "-f",
            "json",
            "--exit-zero",
            str(repo_path),
        ]

        start_time = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                shell=False,
            )
        except FileNotFoundError as exc:
            return ScanResult(
                tool=BANDIT_TOOL_NAME,
                status="error",
                error_message=f"Bandit binary not found at {self._binary}: {exc}",
            )
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - start_time
            return ScanResult(
                tool=BANDIT_TOOL_NAME,
                status="timeout",
                error_message=(
                    f"Bandit scan exceeded {self._timeout}s timeout "
                    f"(elapsed: {elapsed:.1f}s)"
                ),
                scan_duration_seconds=elapsed,
                command=" ".join(cmd),
            )
        except OSError as exc:
            return ScanResult(
                tool=BANDIT_TOOL_NAME,
                status="error",
                error_message=f"Failed to execute Bandit: {exc}",
            )

        elapsed = time.monotonic() - start_time
        command_str = " ".join(cmd)

        if proc.returncode > 1:
            return ScanResult(
                tool=BANDIT_TOOL_NAME,
                status="error",
                error_message=(
                    f"Bandit exited with code {proc.returncode}. "
                    f"stderr: {proc.stderr[:2000]}"
                ),
                scan_duration_seconds=elapsed,
                command=command_str,
            )

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return ScanResult(
                tool=BANDIT_TOOL_NAME,
                status="error",
                error_message=f"Failed to parse Bandit JSON output: {exc}",
                scan_duration_seconds=elapsed,
                command=command_str,
            )

        findings = _parse_findings(data)

        return ScanResult(
            tool=BANDIT_TOOL_NAME,
            findings=findings,
            status="success",
            findings_count=len(findings),
            scan_duration_seconds=elapsed,
            command=command_str,
            tool_version="1.9.4",
        )
