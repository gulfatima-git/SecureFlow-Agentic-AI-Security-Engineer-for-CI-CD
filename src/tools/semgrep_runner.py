"""Semgrep runner: execute Semgrep and convert results to SecurityFinding objects."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from src.models.security_finding import (
    Confidence,
    ScanResult,
    SecurityFinding,
    Severity,
)

# Default Semgrep configuration.
DEFAULT_CONFIG = "p/default"
DEFAULT_TIMEOUT = 300  # seconds
SEMGREP_TOOL_NAME = "semgrep"


class SemgrepError(Exception):
    """Raised when Semgrep execution fails."""


class SemgrepNotInstalledError(SemgrepError):
    """Raised when the Semgrep binary is not found."""


class SemgrepTimeoutError(SemgrepError):
    """Raised when a Semgrep scan exceeds the time limit."""


def _find_semgrep_binary(explicit_path: str | None = None) -> str:
    """Locate the semgrep binary.

    Resolution order:
      1. Explicit path provided by caller.
      2. ``shutil.which("semgrep")`` — searches PATH.
      3. ``shutil.which("semgrep", path=str(scripts_dir))`` — checks common
         pip install locations.

    Returns:
        The absolute path to the semgrep binary.

    Raises:
        SemgrepNotInstalledError: If no binary is found.
    """
    if explicit_path:
        p = Path(explicit_path)
        if p.is_file():
            return str(p)
        raise SemgrepNotInstalledError(f"Semgrep binary not found at: {explicit_path}")

    # Search PATH.
    found = shutil.which("semgrep")
    if found:
        return found

    # Check common pip install locations on Windows.
    import sys

    scripts_dir = Path(sys.prefix) / "Scripts"
    found = shutil.which("semgrep", path=str(scripts_dir))
    if found:
        return found

    # Check user-site Scripts directory.
    import site

    for site_dir in site.getusersitepackages():
        user_scripts = Path(site_dir).parent / "Scripts"
        found = shutil.which("semgrep", path=str(user_scripts))
        if found:
            return found

    raise SemgrepNotInstalledError(
        "Semgrep is not installed or not on PATH. "
        "Install with: pip install semgrep"
    )


def _map_severity(raw: str) -> Severity:
    """Map a Semgrep severity string to our normalized Severity enum."""
    upper = raw.upper().strip()
    mapping = {
        "ERROR": Severity.ERROR,
        "WARNING": Severity.WARNING,
        "INFO": Severity.INFO,
    }
    return mapping.get(upper, Severity.UNKNOWN)


def _parse_findings(data: dict[str, Any]) -> list[SecurityFinding]:
    """Parse Semgrep JSON output into SecurityFinding objects."""
    findings: list[SecurityFinding] = []
    for result in data.get("results", []):
        check_id = result.get("check_id", "")
        path = result.get("path", "")
        start = result.get("start", {})
        end = result.get("end", {})
        extra = result.get("extra", {})
        message = extra.get("message", "")
        raw_severity = extra.get("severity", "")
        metadata = extra.get("metadata", {})

        # Build a code snippet from lines/col if available.
        # Semgrep doesn't always provide the snippet in JSON output,
        # but the metadata may contain useful context.
        snippet = ""
        lines = extra.get("lines", [])
        if isinstance(lines, list):
            snippet = "\n".join(str(line) for line in lines)

        # Determine category from metadata or rule ID prefix.
        category = ""
        if isinstance(metadata, dict):
            category = metadata.get("category", "")
        if not category and check_id:
            parts = check_id.split(".")
            if len(parts) >= 3:
                category = parts[2]  # e.g., "security" from "python.lang.security..."

        # Map confidence from metadata if available.
        raw_confidence = ""
        if isinstance(metadata, dict):
            raw_confidence = str(metadata.get("confidence", ""))
        confidence = _map_confidence(raw_confidence)

        findings.append(
            SecurityFinding(
                tool=SEMGREP_TOOL_NAME,
                rule_id=check_id,
                severity=_map_severity(raw_severity),
                confidence=confidence,
                message=message,
                file_path=path,
                start_line=start.get("line", 0),
                end_line=end.get("line", 0),
                start_column=start.get("col", 0),
                end_column=end.get("col", 0),
                code_snippet=snippet,
                category=category,
                metadata=_stringify_metadata(metadata),
            )
        )
    return findings


def _stringify_metadata(raw: object) -> dict[str, str]:
    """Convert Semgrep metadata dict to a flat string-valued dict.

    Lists (like CWE references) are joined with commas.
    """
    if not isinstance(raw, dict):
        return {}
    result: dict[str, str] = {}
    for k, v in raw.items():
        if isinstance(v, list):
            result[str(k)] = ", ".join(str(item) for item in v)
        else:
            result[str(k)] = str(v)
    return result


def _map_confidence(raw: str) -> Confidence:
    """Map a confidence string to our normalized Confidence enum."""
    upper = raw.upper().strip()
    mapping = {
        "HIGH": Confidence.HIGH,
        "MEDIUM": Confidence.MEDIUM,
        "LOW": Confidence.LOW,
    }
    return mapping.get(upper, Confidence.UNKNOWN)


class SemgrepRunner:
    """Runs Semgrep against a repository and returns structured findings.

    Example::

        runner = SemgrepRunner()
        result = runner.scan("/path/to/repo")
        for finding in result.findings:
            print(finding.rule_id, finding.file_path)
    """

    def __init__(
        self,
        *,
        semgrep_path: str | None = None,
        config: str = DEFAULT_CONFIG,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        """Initialize the runner.

        Args:
            semgrep_path: Explicit path to the semgrep binary. If None,
                the binary is located automatically.
            config: Semgrep ruleset configuration (e.g., ``p/default``).
            timeout: Maximum scan time in seconds.
        """
        self._binary = _find_semgrep_binary(semgrep_path)
        self._config = config
        self._timeout = timeout

    @property
    def semgrep_path(self) -> str:
        return self._binary

    def scan(self, repository_path: str | Path) -> ScanResult:
        """Run Semgrep against the given repository directory.

        Args:
            repository_path: Path to the repository root to scan.

        Returns:
            A ScanResult containing findings and execution metadata.

        Raises:
            SemgrepError: If Semgrep cannot execute (not installed,
                invalid path, or unexpected failure).
            SemgrepTimeoutError: If the scan exceeds the configured timeout.
        """
        repo_path = Path(repository_path)
        if not repo_path.is_dir():
            return ScanResult(
                tool=SEMGREP_TOOL_NAME,
                status="error",
                error_message=f"Repository path does not exist or is not a directory: {repo_path}",
            )

        cmd = [
            self._binary,
            "--config",
            self._config,
            "--json",
            "--quiet",
            "--no-git-ignore",
            str(repo_path),
        ]

        start_time = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                cwd=str(repo_path),
                shell=False,
            )
        except FileNotFoundError as exc:
            return ScanResult(
                tool=SEMGREP_TOOL_NAME,
                status="error",
                error_message=f"Semgrep binary not found at {self._binary}: {exc}",
            )
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - start_time
            return ScanResult(
                tool=SEMGREP_TOOL_NAME,
                status="timeout",
                error_message=(
                    f"Semgrep scan exceeded {self._timeout}s timeout "
                    f"(elapsed: {elapsed:.1f}s)"
                ),
                scan_duration_seconds=elapsed,
                command=" ".join(cmd),
            )
        except OSError as exc:
            return ScanResult(
                tool=SEMGREP_TOOL_NAME,
                status="error",
                error_message=f"Failed to execute Semgrep: {exc}",
            )

        elapsed = time.monotonic() - start_time
        command_str = " ".join(cmd)

        # Exit code 0 = no findings, 1 = findings found, 2+ = real error.
        if proc.returncode > 1:
            return ScanResult(
                tool=SEMGREP_TOOL_NAME,
                status="error",
                error_message=(
                    f"Semgrep exited with code {proc.returncode}. "
                    f"stderr: {proc.stderr[:2000]}"
                ),
                scan_duration_seconds=elapsed,
                command=command_str,
            )

        # Parse JSON output.
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return ScanResult(
                tool=SEMGREP_TOOL_NAME,
                status="error",
                error_message=f"Failed to parse Semgrep JSON output: {exc}",
                scan_duration_seconds=elapsed,
                command=command_str,
            )

        findings = _parse_findings(data)

        # Determine tool version from Semgrep output.
        version = ""
        if isinstance(data, dict):
            version = data.get("version", "")
            if not version and "info" in data:
                version = data["info"].get("version", "")

        return ScanResult(
            tool=SEMGREP_TOOL_NAME,
            findings=findings,
            status="success",
            findings_count=len(findings),
            scan_duration_seconds=elapsed,
            command=command_str,
            tool_version=version,
        )
