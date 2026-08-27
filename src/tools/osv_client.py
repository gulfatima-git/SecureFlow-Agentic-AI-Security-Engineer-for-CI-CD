"""OSV (Open Source Vulnerabilities) API client using stdlib urllib."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

OSV_API_URL = "https://api.osv.dev/v1/query"
DEFAULT_TIMEOUT = 30  # seconds


class OsvError(Exception):
    """Raised when the OSV API request fails."""


class OsvTimeoutError(OsvError):
    """Raised when the OSV API request times out."""


@dataclass
class OsvVulnerability:
    """A single vulnerability returned by OSV."""

    vuln_id: str
    summary: str = ""
    details: str = ""
    severity: str = ""
    aliases: list[str] = field(default_factory=list)
    affected_package: str = ""
    affected_version: str = ""
    fixed_version: str = ""
    ecosystem: str = ""
    references: list[str] = field(default_factory=list)


def query_osv(
    package_name: str,
    ecosystem: str,
    version: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[OsvVulnerability]:
    """Query the OSV API for vulnerabilities affecting a package.

    Args:
        package_name: Name of the package (e.g., "requests", "lodash").
        ecosystem: Ecosystem identifier (e.g., "PyPI", "npm").
        version: Optional specific version to check. If None, queries for
            all known vulnerabilities of the package.
        timeout: HTTP request timeout in seconds.

    Returns:
        List of OsvVulnerability objects.

    Raises:
        OsvError: If the API request fails or returns invalid data.
        OsvTimeoutError: If the request times out.
    """
    payload: dict[str, Any] = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        },
    }
    if version:
        payload["version"] = version

    data_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OSV_API_URL,
        data=data_bytes,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.URLError as exc:
        raise OsvError(f"OSV API request failed: {exc}") from exc
    except TimeoutError as exc:
        raise OsvTimeoutError(f"OSV API request timed out after {timeout}s") from exc

    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise OsvError(f"Invalid JSON from OSV API: {exc}") from exc

    return _parse_osv_response(data)


def _parse_osv_response(data: dict[str, Any]) -> list[OsvVulnerability]:
    """Parse the OSV API response into OsvVulnerability objects."""
    vulns_raw = data.get("vulns", [])
    if not isinstance(vulns_raw, list):
        return []

    results: list[OsvVulnerability] = []
    for vuln in vulns_raw:
        if not isinstance(vuln, dict):
            continue

        vuln_id = vuln.get("id", "")
        if not vuln_id:
            continue

        summary = vuln.get("summary", "")
        details = vuln.get("details", "")

        # Extract severity from database_specific or severity field
        severity = ""
        severity_list = vuln.get("severity", [])
        if isinstance(severity_list, list) and severity_list:
            first = severity_list[0]
            if isinstance(first, dict):
                severity = str(first.get("score", first.get("type", "")))

        # Extract aliases (CVE, GHSA, etc.)
        aliases_raw = vuln.get("aliases", [])
        aliases = [a for a in aliases_raw if isinstance(a, str)]

        # Extract references
        refs_raw = vuln.get("references", [])
        references: list[str] = []
        for ref in refs_raw:
            if isinstance(ref, dict):
                url = ref.get("url", "")
                if url:
                    references.append(url)

        # Extract affected package info
        affected_list = vuln.get("affected", [])
        affected_package = ""
        affected_version = ""
        fixed_version = ""
        ecosystem = ""

        if isinstance(affected_list, list) and affected_list:
            first_affected = affected_list[0]
            if isinstance(first_affected, dict):
                pkg = first_affected.get("package", {})
                if isinstance(pkg, dict):
                    affected_package = pkg.get("name", "")
                    ecosystem = pkg.get("ecosystem", "")

                # Extract version ranges
                versions_raw = first_affected.get("versions", [])
                if isinstance(versions_raw, list) and versions_raw:
                    affected_version = str(versions_raw[0])

                # Look for fixed version in events/ranges
                ranges_raw = first_affected.get("ranges", [])
                if isinstance(ranges_raw, list):
                    for r in ranges_raw:
                        if not isinstance(r, dict):
                            continue
                        events = r.get("events", [])
                        if isinstance(events, list):
                            for evt in events:
                                if isinstance(evt, dict) and "fixed" in evt:
                                    fixed_version = str(evt["fixed"])
                                    break

        results.append(OsvVulnerability(
            vuln_id=vuln_id,
            summary=summary,
            details=details,
            severity=severity,
            aliases=aliases,
            affected_package=affected_package,
            affected_version=affected_version,
            fixed_version=fixed_version,
            ecosystem=ecosystem,
            references=references,
        ))

    return results
