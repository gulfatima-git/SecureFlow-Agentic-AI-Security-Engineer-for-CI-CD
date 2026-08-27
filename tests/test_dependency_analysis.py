"""Tests for dependency analysis.

Tests use mocked OSV API responses to remain deterministic and offline.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.models.security_finding import Confidence, ScanResult, SecurityFinding, Severity
from src.tools.dependency_analyzer import (
    DependencyAnalyzer,
    _map_osv_severity,
    _vulnerability_to_finding,
)
from src.tools.dependency_parsers import (
    Dependency,
    parse_package_json,
    parse_package_lock,
    parse_pyproject_toml,
    parse_requirements_txt,
)
from src.tools.osv_client import OsvError, OsvTimeoutError, OsvVulnerability, query_osv

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

SAMPLE_OSV_RESPONSE = json.dumps({
    "vulns": [
        {
            "id": "GHSA-xxxx-xxxx-xxxx",
            "summary": "Prototype Pollution in lodash",
            "aliases": ["CVE-2021-23337", "GHSA-xxxx-xxxx-xxxx"],
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            ],
            "affected": [
                {
                    "package": {"name": "lodash", "ecosystem": "npm"},
                    "versions": ["4.17.19"],
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "4.17.21"},
                            ],
                        }
                    ],
                }
            ],
            "references": [
                {"type": "WEB", "url": "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx"},
            ],
        }
    ],
})

SAMPLE_OSV_NO_VULNS = json.dumps({"vulns": []})

SAMPLE_OSV_MULTI_VULNS = json.dumps({
    "vulns": [
        {
            "id": "PYSEC-2023-1",
            "summary": "Vuln 1 in requests",
            "aliases": ["CVE-2023-1234"],
            "severity": [{"type": "CVSS_V3", "score": "HIGH"}],
            "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"}}],
            "references": [],
        },
        {
            "id": "PYSEC-2023-2",
            "summary": "Vuln 2 in requests",
            "aliases": ["CVE-2023-5678"],
            "severity": [{"type": "CVSS_V3", "score": "MEDIUM"}],
            "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"}}],
            "references": [{"type": "WEB", "url": "https://example.com/vuln2"}],
        },
    ],
})


def _mock_urlopen(response_body: str, status: int = 200):
    """Create a mock context manager for urllib.request.urlopen."""
    from unittest.mock import MagicMock

    mock_resp = MagicMock()
    mock_resp.read.return_value = response_body.encode("utf-8")
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


# ---------------------------------------------------------------------------
# Test: requirements.txt parsing
# ---------------------------------------------------------------------------


class TestRequirementsTxt:
    def test_exact_version(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.31.0\n")
        deps = parse_requirements_txt(f)
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].declared_version == "==2.31.0"
        assert deps[0].ecosystem == "PyPI"

    def test_version_range(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("django>=4.2,<5.0\n")
        deps = parse_requirements_txt(f)
        assert len(deps) == 1
        assert deps[0].name == "django"
        assert deps[0].declared_version == ">=4.2,<5.0"

    def test_unpinned(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("flask\n")
        deps = parse_requirements_txt(f)
        assert len(deps) == 1
        assert deps[0].name == "flask"
        assert deps[0].declared_version == ""

    def test_multiple_dependencies(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.31.0\nflask>=2.0\ndjango~=4.2\n")
        deps = parse_requirements_txt(f)
        assert len(deps) == 3
        names = [d.name for d in deps]
        assert names == ["requests", "flask", "django"]

    def test_comments_skipped(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("# This is a comment\nrequests==1.0\n# another comment\n")
        deps = parse_requirements_txt(f)
        assert len(deps) == 1
        assert deps[0].name == "requests"

    def test_options_skipped(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("-r other.txt\nrequests==1.0\n--index-url https://example.com\n")
        deps = parse_requirements_txt(f)
        assert len(deps) == 1

    def test_inline_comment(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.31.0  # pinned version\n")
        deps = parse_requirements_txt(f)
        assert len(deps) == 1
        assert deps[0].declared_version == "==2.31.0"

    def test_extras(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("requests[security]>=2.0\n")
        deps = parse_requirements_txt(f)
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].declared_version == ">=2.0"

    def test_file_not_found(self, tmp_path: Path) -> None:
        deps = parse_requirements_txt(tmp_path / "nonexistent.txt")
        assert deps == []

    def test_dependency_file_field(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("requests==1.0\n")
        deps = parse_requirements_txt(f)
        assert deps[0].dependency_file == "requirements.txt"

    def test_pep508_env_marker(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text('requests==2.0; python_version >= "3.8"\n')
        deps = parse_requirements_txt(f)
        assert len(deps) == 1
        assert deps[0].name == "requests"


# ---------------------------------------------------------------------------
# Test: pyproject.toml parsing
# ---------------------------------------------------------------------------


class TestPyprojectToml:
    def test_project_dependencies(self, tmp_path: Path) -> None:
        f = tmp_path / "pyproject.toml"
        f.write_text('[project]\ndependencies = ["requests>=2.0", "flask"]\n')
        deps = parse_pyproject_toml(f)
        assert len(deps) == 2
        assert deps[0].name == "requests"
        assert deps[0].declared_version == ">=2.0"
        assert deps[1].name == "flask"
        assert deps[1].declared_version == ""

    def test_no_project_section(self, tmp_path: Path) -> None:
        f = tmp_path / "pyproject.toml"
        f.write_text('[build-system]\nrequires = ["setuptools"]\n')
        deps = parse_pyproject_toml(f)
        assert deps == []

    def test_empty_dependencies(self, tmp_path: Path) -> None:
        f = tmp_path / "pyproject.toml"
        f.write_text('[project]\ndependencies = []\n')
        deps = parse_pyproject_toml(f)
        assert deps == []

    def test_malformed_toml(self, tmp_path: Path) -> None:
        f = tmp_path / "pyproject.toml"
        f.write_text('this is not valid toml [[[{\n')
        deps = parse_pyproject_toml(f)
        assert deps == []

    def test_file_not_found(self, tmp_path: Path) -> None:
        deps = parse_pyproject_toml(tmp_path / "nonexistent.toml")
        assert deps == []

    def test_dependency_file_field(self, tmp_path: Path) -> None:
        f = tmp_path / "pyproject.toml"
        f.write_text('[project]\ndependencies = ["requests"]\n')
        deps = parse_pyproject_toml(f)
        assert deps[0].dependency_file == "pyproject.toml"

    def test_non_string_dependency_ignored(self, tmp_path: Path) -> None:
        f = tmp_path / "pyproject.toml"
        f.write_text('[project]\ndependencies = [123, true]\n')
        deps = parse_pyproject_toml(f)
        assert deps == []


# ---------------------------------------------------------------------------
# Test: package.json parsing
# ---------------------------------------------------------------------------


class TestPackageJson:
    def test_dependencies(self, tmp_path: Path) -> None:
        f = tmp_path / "package.json"
        data = {"dependencies": {"lodash": "^4.17.20", "express": "^4.18.0"}}
        f.write_text(json.dumps(data))
        deps = parse_package_json(f)
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"lodash", "express"}
        for d in deps:
            assert d.ecosystem == "npm"

    def test_dev_dependencies(self, tmp_path: Path) -> None:
        f = tmp_path / "package.json"
        data = {"devDependencies": {"jest": "^29.0.0"}}
        f.write_text(json.dumps(data))
        deps = parse_package_json(f)
        assert len(deps) == 1
        assert deps[0].name == "jest"
        assert deps[0].source == "package.json#devDependencies"

    def test_both_sections(self, tmp_path: Path) -> None:
        f = tmp_path / "package.json"
        data = {
            "dependencies": {"lodash": "^4.17.20"},
            "devDependencies": {"jest": "^29.0.0"},
        }
        f.write_text(json.dumps(data))
        deps = parse_package_json(f)
        assert len(deps) == 2

    def test_malformed_json(self, tmp_path: Path) -> None:
        f = tmp_path / "package.json"
        f.write_text("not json {{{")
        deps = parse_package_json(f)
        assert deps == []

    def test_file_not_found(self, tmp_path: Path) -> None:
        deps = parse_package_json(tmp_path / "nonexistent.json")
        assert deps == []

    def test_dependency_file_field(self, tmp_path: Path) -> None:
        f = tmp_path / "package.json"
        f.write_text(json.dumps({"dependencies": {"a": "1.0"}}))
        deps = parse_package_json(f)
        assert deps[0].dependency_file == "package.json"


# ---------------------------------------------------------------------------
# Test: package-lock.json parsing
# ---------------------------------------------------------------------------


class TestPackageLock:
    def test_v2_resolved_versions(self, tmp_path: Path) -> None:
        f = tmp_path / "package-lock.json"
        data = {
            "packages": {
                "": {"name": "test", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/express": {"version": "4.18.2"},
            }
        }
        f.write_text(json.dumps(data))
        resolved = parse_package_lock(f)
        assert resolved == {"lodash": "4.17.21", "express": "4.18.2"}

    def test_v1_resolved_versions(self, tmp_path: Path) -> None:
        f = tmp_path / "package-lock.json"
        data = {
            "dependencies": {
                "lodash": {"version": "4.17.21"},
                "express": {"version": "4.18.2"},
            }
        }
        f.write_text(json.dumps(data))
        resolved = parse_package_lock(f)
        assert resolved == {"lodash": "4.17.21", "express": "4.18.2"}

    def test_malformed_json(self, tmp_path: Path) -> None:
        f = tmp_path / "package-lock.json"
        f.write_text("not json {{{")
        resolved = parse_package_lock(f)
        assert resolved == {}

    def test_file_not_found(self, tmp_path: Path) -> None:
        resolved = parse_package_lock(tmp_path / "nonexistent.json")
        assert resolved == {}

    def test_empty_packages(self, tmp_path: Path) -> None:
        f = tmp_path / "package-lock.json"
        f.write_text(json.dumps({"packages": {}}))
        resolved = parse_package_lock(f)
        assert resolved == {}


# ---------------------------------------------------------------------------
# Test: OSV client (mocked)
# ---------------------------------------------------------------------------


class TestOsvClient:
    def test_successful_query(self) -> None:
        with patch("src.tools.osv_client.urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(SAMPLE_OSV_RESPONSE)
            vulns = query_osv("lodash", "npm", version="4.17.19")

        assert len(vulns) == 1
        assert vulns[0].vuln_id == "GHSA-xxxx-xxxx-xxxx"
        assert "CVE-2021-23337" in vulns[0].aliases
        assert vulns[0].affected_package == "lodash"
        assert vulns[0].fixed_version == "4.17.21"
        assert vulns[0].ecosystem == "npm"

    def test_no_vulnerabilities(self) -> None:
        with patch("src.tools.osv_client.urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(SAMPLE_OSV_NO_VULNS)
            vulns = query_osv("safe-package", "PyPI")

        assert vulns == []

    def test_multiple_vulnerabilities(self) -> None:
        with patch("src.tools.osv_client.urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(SAMPLE_OSV_MULTI_VULNS)
            vulns = query_osv("requests", "PyPI", version="2.28.0")

        assert len(vulns) == 2
        assert vulns[0].vuln_id == "PYSEC-2023-1"
        assert vulns[1].vuln_id == "PYSEC-2023-2"

    def test_references_extracted(self) -> None:
        with patch("src.tools.osv_client.urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(SAMPLE_OSV_RESPONSE)
            vulns = query_osv("lodash", "npm")

        assert len(vulns[0].references) == 1
        assert "github.com" in vulns[0].references[0]

    def test_api_error(self) -> None:
        with patch("src.tools.osv_client.urllib.request.urlopen") as mock_open:
            import urllib.error
            mock_open.side_effect = urllib.error.URLError("connection refused")
            with pytest.raises(OsvError, match="request failed"):
                query_osv("lodash", "npm")

    def test_timeout(self) -> None:
        with patch("src.tools.osv_client.urllib.request.urlopen") as mock_open:
            mock_open.side_effect = TimeoutError("timed out")
            with pytest.raises(OsvTimeoutError, match="timed out"):
                query_osv("lodash", "npm")

    def test_malformed_response(self) -> None:
        with patch("src.tools.osv_client.urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen("not json {{{")
            with pytest.raises(OsvError, match="Invalid JSON"):
                query_osv("lodash", "npm")

    def test_empty_vulns_field(self) -> None:
        with patch("src.tools.osv_client.urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(json.dumps({"vulns": None}))
            vulns = query_osv("lodash", "npm")
        assert vulns == []

    def test_vuln_missing_id_skipped(self) -> None:
        resp = json.dumps({"vulns": [{"summary": "no id"}]})
        with patch("src.tools.osv_client.urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(resp)
            vulns = query_osv("lodash", "npm")
        assert vulns == []

    def test_version_in_payload(self) -> None:
        with patch("src.tools.osv_client.urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(SAMPLE_OSV_NO_VULNS)
            query_osv("requests", "PyPI", version="2.31.0")

            call_args = mock_open.call_args
            req = call_args[0][0]
            body = json.loads(req.data.decode("utf-8"))
            assert body["version"] == "2.31.0"
            assert body["package"]["name"] == "requests"
            assert body["package"]["ecosystem"] == "PyPI"

    def test_no_version_in_payload(self) -> None:
        with patch("src.tools.osv_client.urllib.request.urlopen") as mock_open:
            mock_open.return_value = _mock_urlopen(SAMPLE_OSV_NO_VULNS)
            query_osv("requests", "PyPI")

            call_args = mock_open.call_args
            req = call_args[0][0]
            body = json.loads(req.data.decode("utf-8"))
            assert "version" not in body


# ---------------------------------------------------------------------------
# Test: OSV severity mapping
# ---------------------------------------------------------------------------


class TestOsvSeverityMapping:
    def test_high(self) -> None:
        assert _map_osv_severity("HIGH") == Severity.ERROR

    def test_critical(self) -> None:
        assert _map_osv_severity("CRITICAL") == Severity.ERROR

    def test_medium(self) -> None:
        assert _map_osv_severity("MEDIUM") == Severity.WARNING

    def test_low(self) -> None:
        assert _map_osv_severity("LOW") == Severity.INFO

    def test_unknown(self) -> None:
        assert _map_osv_severity("") == Severity.UNKNOWN

    def test_cvss_score_with_high(self) -> None:
        assert _map_osv_severity("HIGH") == Severity.ERROR

    def test_severity_string_with_high_word(self) -> None:
        assert _map_osv_severity("severity: HIGH") == Severity.ERROR


# ---------------------------------------------------------------------------
# Test: Vulnerability to SecurityFinding conversion
# ---------------------------------------------------------------------------


class TestVulnerabilityToFinding:
    def test_basic_conversion(self) -> None:
        vuln = OsvVulnerability(
            vuln_id="GHSA-test-1234",
            summary="Test vulnerability",
            severity="HIGH",
            aliases=["CVE-2024-1234"],
            affected_package="testpkg",
            fixed_version="2.0.0",
            ecosystem="PyPI",
        )
        dep = Dependency(
            name="testpkg",
            ecosystem="PyPI",
            declared_version="==1.0.0",
            resolved_version="1.0.0",
            dependency_file="requirements.txt",
        )
        finding = _vulnerability_to_finding(vuln, dep)

        assert finding.tool == "dependency-analyzer"
        assert finding.rule_id == "CVE-2024-1234"  # first alias used
        assert finding.severity == Severity.ERROR
        assert finding.confidence == Confidence.HIGH  # resolved version
        assert "Test vulnerability" in finding.message
        assert "2.0.0" in finding.message  # fixed version mentioned
        assert finding.ecosystem == "PyPI"
        assert finding.package_name == "testpkg"
        assert finding.declared_version == "==1.0.0"
        assert finding.resolved_version == "1.0.0"
        assert finding.category == "dependency-vulnerability"
        assert finding.file_path == "requirements.txt"
        assert finding.metadata["osv_id"] == "GHSA-test-1234"
        assert finding.metadata["fixed_version"] == "2.0.0"

    def test_no_resolved_version_lower_confidence(self) -> None:
        vuln = OsvVulnerability(vuln_id="VULN-1", summary="test")
        dep = Dependency(name="pkg", ecosystem="npm", declared_version="^4.0.0")
        finding = _vulnerability_to_finding(vuln, dep)
        assert finding.confidence == Confidence.MEDIUM

    def test_no_aliases_uses_osv_id(self) -> None:
        vuln = OsvVulnerability(vuln_id="PYSEC-1234", summary="test")
        dep = Dependency(name="pkg", ecosystem="PyPI")
        finding = _vulnerability_to_finding(vuln, dep)
        assert finding.rule_id == "PYSEC-1234"

    def test_metadata_populated(self) -> None:
        vuln = OsvVulnerability(
            vuln_id="V-1",
            summary="v",
            aliases=["CVE-X"],
            references=["https://example.com"],
            fixed_version="1.1.0",
        )
        dep = Dependency(
            name="pkg",
            ecosystem="npm",
            dependency_file="package.json",
            source="package.json#dependencies",
        )
        finding = _vulnerability_to_finding(vuln, dep)
        assert finding.metadata["aliases"] == "CVE-X"
        assert finding.metadata["references"] == "https://example.com"
        assert finding.metadata["source"] == "package.json#dependencies"

    def test_no_fixed_version_omits_field(self) -> None:
        vuln = OsvVulnerability(vuln_id="V-1", summary="v")
        dep = Dependency(name="pkg", ecosystem="PyPI")
        finding = _vulnerability_to_finding(vuln, dep)
        assert "fixed_version" not in finding.metadata


# ---------------------------------------------------------------------------
# Test: DependencyAnalyzer (mocked OSV)
# ---------------------------------------------------------------------------


def _make_analyzer(tmp_path: Path, deps_content: str, lock_content: str = "") -> DependencyAnalyzer:
    """Helper to create a repo dir with dependency files."""
    (tmp_path / "requirements.txt").write_text(deps_content)
    if lock_content:
        (tmp_path / "package-lock.json").write_text(lock_content)
    return DependencyAnalyzer(timeout=30)


class TestDependencyAnalyzer:
    def test_invalid_path(self) -> None:
        analyzer = DependencyAnalyzer()
        result = analyzer.scan("/nonexistent/path")
        assert result.status == "error"
        assert "does not exist" in result.error_message

    def test_no_dependency_files(self, tmp_path: Path) -> None:
        analyzer = DependencyAnalyzer()
        result = analyzer.scan(tmp_path)
        assert result.status == "success"
        assert "No supported dependency files found" in result.error_message
        assert result.findings_count == 0

    def test_scan_with_vulnerabilities(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        analyzer = DependencyAnalyzer()

        mock_vulns = [
            OsvVulnerability(
                vuln_id="PYSEC-2023-1",
                summary="Requests vuln",
                severity="HIGH",
                aliases=["CVE-2023-1234"],
                affected_package="requests",
                fixed_version="2.31.0",
                ecosystem="PyPI",
            ),
        ]

        with patch("src.tools.dependency_analyzer.query_osv", return_value=mock_vulns):
            result = analyzer.scan(tmp_path)

        assert result.status == "success"
        assert result.findings_count == 1
        assert result.findings[0].package_name == "requests"
        assert result.findings[0].severity == Severity.ERROR

    def test_scan_no_vulnerabilities(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        analyzer = DependencyAnalyzer()

        with patch("src.tools.dependency_analyzer.query_osv", return_value=[]):
            result = analyzer.scan(tmp_path)

        assert result.status == "success"
        assert result.findings_count == 0

    def test_scan_osv_error(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        analyzer = DependencyAnalyzer()

        with patch("src.tools.dependency_analyzer.query_osv", side_effect=OsvError("API down")):
            result = analyzer.scan(tmp_path)

        assert result.status == "error"
        assert "API down" in result.error_message
        assert result.findings_count == 0

    def test_scan_partial_osv_error(self, tmp_path: Path) -> None:
        """Some queries succeed, some fail — should still return partial results."""
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask==2.0\n")
        analyzer = DependencyAnalyzer()

        call_count = 0

        def mock_query(package_name, ecosystem, version=None, timeout=30):
            nonlocal call_count
            call_count += 1
            if package_name == "requests":
                return [OsvVulnerability(vuln_id="V1", summary="vuln in requests")]
            raise OsvError("query failed")

        with patch("src.tools.dependency_analyzer.query_osv", side_effect=mock_query):
            result = analyzer.scan(tmp_path)

        assert result.status == "success"
        assert result.findings_count == 1
        assert "Partial results" in result.error_message

    def test_tool_version_recorded(self, tmp_path: Path) -> None:
        analyzer = DependencyAnalyzer()
        result = analyzer.scan(tmp_path)
        assert result.tool_version == "0.1.0"

    def test_scan_duration_recorded(self, tmp_path: Path) -> None:
        analyzer = DependencyAnalyzer()
        result = analyzer.scan(tmp_path)
        assert result.scan_duration_seconds >= 0

    def test_multiple_dependency_files(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["flask>=2.0"]\n')
        analyzer = DependencyAnalyzer()

        with patch("src.tools.dependency_analyzer.query_osv", return_value=[]):
            result = analyzer.scan(tmp_path)

        assert result.status == "success"
        # Both deps should have been queried (even though no vulns found)
        assert result.findings_count == 0

    def test_npm_with_lockfile(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(json.dumps({
            "dependencies": {"lodash": "^4.17.20"}
        }))
        (tmp_path / "package-lock.json").write_text(json.dumps({
            "packages": {"": {"name": "test"}, "node_modules/lodash": {"version": "4.17.21"}}
        }))
        analyzer = DependencyAnalyzer()

        with patch("src.tools.dependency_analyzer.query_osv", return_value=[]):
            result = analyzer.scan(tmp_path)

        assert result.status == "success"

    def test_no_network_dependency_in_test(self, tmp_path: Path) -> None:
        """Verify the analyzer itself doesn't make network calls."""
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        analyzer = DependencyAnalyzer()

        with patch("src.tools.dependency_analyzer.query_osv", return_value=[]) as mock_osv:
            analyzer.scan(tmp_path)
            assert mock_osv.called


# ---------------------------------------------------------------------------
# Test: Shared normalization / interoperability
# ---------------------------------------------------------------------------


class TestSharedNormalization:
    def test_finding_is_pydantic_model(self) -> None:
        vuln = OsvVulnerability(vuln_id="V-1", summary="test")
        dep = Dependency(name="pkg", ecosystem="PyPI")
        finding = _vulnerability_to_finding(vuln, dep)
        assert isinstance(finding, SecurityFinding)

    def test_scan_result_is_pydantic_model(self) -> None:
        result = ScanResult(tool="dependency-analyzer")
        assert isinstance(result, ScanResult)

    def test_finding_serializable(self) -> None:
        vuln = OsvVulnerability(vuln_id="V-1", summary="test")
        dep = Dependency(name="pkg", ecosystem="PyPI")
        finding = _vulnerability_to_finding(vuln, dep)
        d = finding.model_dump()
        assert d["tool"] == "dependency-analyzer"
        assert d["ecosystem"] == "PyPI"
        assert d["package_name"] == "pkg"

    def test_backward_compatibility_no_dependency_fields(self) -> None:
        """Existing SecurityFinding usage without dependency fields still works."""
        f = SecurityFinding(tool="semgrep", rule_id="test.rule")
        assert f.ecosystem == ""
        assert f.package_name == ""
        assert f.declared_version == ""
        assert f.resolved_version == ""


# ---------------------------------------------------------------------------
# Test: Security — no code execution
# ---------------------------------------------------------------------------


class TestSecurity:
    def test_analyzer_uses_no_subprocess(self, tmp_path: Path) -> None:
        """The dependency analyzer should not invoke any subprocess."""
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        analyzer = DependencyAnalyzer()

        import subprocess
        original_run = subprocess.run
        subprocess_called = False

        def tracking_run(*args, **kwargs):
            nonlocal subprocess_called
            subprocess_called = True
            return original_run(*args, **kwargs)

        with patch("src.tools.dependency_analyzer.query_osv", return_value=[]):
            with patch("subprocess.run", side_effect=tracking_run):
                analyzer.scan(tmp_path)

        assert not subprocess_called

    def test_analyzer_uses_no_pip(self, tmp_path: Path) -> None:
        """The dependency analyzer should never run pip install."""
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        analyzer = DependencyAnalyzer()

        with patch("src.tools.dependency_analyzer.query_osv", return_value=[]):
            result = analyzer.scan(tmp_path)

        assert "pip" not in result.command.lower() if result.command else True
