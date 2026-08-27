"""Dependency analyzer: parse dependency files, query OSV, produce SecurityFinding objects."""

from __future__ import annotations

import time
from pathlib import Path

from src.models.security_finding import (
    Confidence,
    ScanResult,
    SecurityFinding,
    Severity,
)
from src.tools.dependency_parsers import (
    Dependency,
    parse_package_json,
    parse_package_lock,
    parse_pyproject_toml,
    parse_requirements_txt,
)
from src.tools.osv_client import OsvError, OsvVulnerability, query_osv

ANALYZER_TOOL_NAME = "dependency-analyzer"

# Ecosystem mapping: our internal ecosystem names → OSV ecosystem identifiers
_ECOSYSTEM_MAP: dict[str, str] = {
    "PyPI": "PyPI",
    "npm": "npm",
}


def _map_osv_severity(severity_str: str) -> Severity:
    """Map an OSV severity string to our normalized Severity enum."""
    upper = severity_str.upper().strip()
    if "HIGH" in upper or "CRITICAL" in upper:
        return Severity.ERROR
    if "MEDIUM" in upper:
        return Severity.WARNING
    if "LOW" in upper:
        return Severity.INFO
    return Severity.UNKNOWN


def _vulnerability_to_finding(
    vuln: OsvVulnerability,
    dep: Dependency,
) -> SecurityFinding:
    """Convert an OSV vulnerability + dependency into a SecurityFinding."""
    aliases_str = ", ".join(vuln.aliases) if vuln.aliases else ""
    refs_str = ", ".join(vuln.references[:3]) if vuln.references else ""

    rule_id = vuln.vuln_id
    if vuln.aliases:
        rule_id = vuln.aliases[0]

    message = vuln.summary or f"Vulnerability {vuln.vuln_id} in {dep.name}"
    if vuln.fixed_version:
        message += f" (fixed in {vuln.fixed_version})"

    metadata: dict[str, str] = {
        "osv_id": vuln.vuln_id,
        "ecosystem": dep.ecosystem,
        "package_name": dep.name,
        "declared_version": dep.declared_version,
        "resolved_version": dep.resolved_version,
        "dependency_file": dep.dependency_file,
    }
    if aliases_str:
        metadata["aliases"] = aliases_str
    if refs_str:
        metadata["references"] = refs_str
    if vuln.fixed_version:
        metadata["fixed_version"] = vuln.fixed_version
    if dep.source:
        metadata["source"] = dep.source

    return SecurityFinding(
        tool=ANALYZER_TOOL_NAME,
        rule_id=rule_id,
        severity=_map_osv_severity(vuln.severity),
        confidence=Confidence.HIGH if dep.resolved_version else Confidence.MEDIUM,
        message=message,
        file_path=dep.dependency_file,
        category="dependency-vulnerability",
        ecosystem=dep.ecosystem,
        package_name=dep.name,
        declared_version=dep.declared_version,
        resolved_version=dep.resolved_version,
        metadata=metadata,
    )


class DependencyAnalyzer:
    """Analyzes repository dependencies for known vulnerabilities via OSV.

    Example::

        analyzer = DependencyAnalyzer()
        result = analyzer.scan("/path/to/repo")
        for finding in result.findings:
            print(f"{finding.severity}: {finding.package_name} - {finding.message}")
    """

    def __init__(self, *, timeout: int = 30) -> None:
        self._timeout = timeout

    def scan(self, repository_path: str | Path) -> ScanResult:
        """Scan a repository for dependency vulnerabilities.

        Args:
            repository_path: Path to the repository root.

        Returns:
            A ScanResult with vulnerability findings.
        """
        repo_path = Path(repository_path)
        if not repo_path.is_dir():
            return ScanResult(
                tool=ANALYZER_TOOL_NAME,
                status="error",
                error_message=f"Repository path does not exist or is not a directory: {repo_path}",
            )

        start_time = time.monotonic()

        # Discover dependency files
        deps = self._discover_dependencies(repo_path)

        if not deps:
            elapsed = time.monotonic() - start_time
            return ScanResult(
                tool=ANALYZER_TOOL_NAME,
                status="success",
                error_message="No supported dependency files found",
                scan_duration_seconds=elapsed,
                tool_version="0.1.0",
            )

        # Query OSV for each dependency
        findings: list[SecurityFinding] = []
        errors: list[str] = []

        for dep in deps:
            osv_ecosystem = _ECOSYSTEM_MAP.get(dep.ecosystem, dep.ecosystem)
            version = dep.resolved_version or dep.declared_version or None

            try:
                vulns = query_osv(
                    package_name=dep.name,
                    ecosystem=osv_ecosystem,
                    version=version,
                    timeout=self._timeout,
                )
                for vuln in vulns:
                    findings.append(_vulnerability_to_finding(vuln, dep))
            except OsvError as exc:
                errors.append(f"{dep.name}: {exc}")

        elapsed = time.monotonic() - start_time

        status = "success"
        error_message = ""
        if errors and not findings:
            status = "error"
            error_message = "; ".join(errors)
        elif errors:
            error_message = f"Partial results — {len(errors)} query errors: {'; '.join(errors[:3])}"

        return ScanResult(
            tool=ANALYZER_TOOL_NAME,
            findings=findings,
            status=status,
            error_message=error_message,
            findings_count=len(findings),
            scan_duration_seconds=elapsed,
            tool_version="0.1.0",
        )

    def _discover_dependencies(self, repo_path: Path) -> list[Dependency]:
        """Discover and parse all supported dependency files in the repository."""
        deps: list[Dependency] = []

        # Python dependencies
        requirements = repo_path / "requirements.txt"
        deps.extend(parse_requirements_txt(requirements))

        pyproject = repo_path / "pyproject.toml"
        deps.extend(parse_pyproject_toml(pyproject))

        # JavaScript/Node dependencies
        package_json = repo_path / "package.json"
        npm_deps = parse_package_json(package_json)

        # If package-lock.json exists, resolve versions from it
        package_lock = repo_path / "package-lock.json"
        resolved_versions = parse_package_lock(package_lock)

        for dep in npm_deps:
            if dep.name in resolved_versions:
                dep.resolved_version = resolved_versions[dep.name]
            deps.append(dep)

        return deps
