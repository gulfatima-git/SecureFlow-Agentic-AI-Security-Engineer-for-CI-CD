"""Tests for the canonical SecurityFinding model (Step 15).

Covers the cross-agent finding contract, validation, serialization, the
deterministic ``CodeFinding → SecurityFinding`` conversion, and compatibility
with the three specialized agents (Steps 11 / 13 / 14).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.agents import (
    CICDSecurityAgent,
    CodeSecurityAgent,
    DependencyAgent,
)
from src.llm.fake import FakeLLM
from src.models.code_finding import CodeFinding
from src.models.finding import (
    AgentName,
    EvidenceItem,
    EvidenceKind,
    FindingCategory,
    SecurityFinding,
)
from src.models.security_finding import Severity

FIXTURES = Path(__file__).parent / "fixtures"
ACTIVE_REPO = FIXTURES / "dep_agent" / "active_repo"
CASE_A = FIXTURES / "cicd_agent" / "case_a"


def code_finding(**overrides: object) -> CodeFinding:
    base = {
        "finding_id": "CODE-001",
        "severity": Severity.ERROR,
        "confidence": 0.85,
        "file": "src/app.py",
        "line": 12,
        "description": "SQL injection via string formatting",
        "evidence": [
            "semgrep: python.lang.security.audit.dangerous-exec",
            "the query is built with f-string interpolation",
        ],
    }
    base.update(overrides)
    return CodeFinding(**base)


def security_finding(**overrides: object) -> SecurityFinding:
    base = {
        "finding_id": "CODE-001",
        "agent": AgentName.CODE_SECURITY,
        "category": FindingCategory.CODE,
        "severity": Severity.ERROR,
        "confidence": 0.85,
        "evidence": [EvidenceItem(kind=EvidenceKind.OBSERVED, content="semgrep: rule-x")],
        "affected_files": ["src/app.py"],
        "recommendation": "Use parameterized queries.",
        "metadata": {"scanner": "semgrep", "scanner_rule": "rule-x"},
        "description": "SQL injection",
        "file": "src/app.py",
        "line": 12,
    }
    base.update(overrides)
    return SecurityFinding(**base)


# ---------------------------------------------------------------------------
# 1. Valid construction / 2. required fields
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_valid_construction(self) -> None:
        f = security_finding()
        assert f.finding_id == "CODE-001"
        assert f.agent == AgentName.CODE_SECURITY
        assert f.category == FindingCategory.CODE
        assert f.severity == Severity.ERROR
        assert 0.0 <= f.confidence <= 1.0
        assert f.affected_files == ["src/app.py"]

    def test_required_fields_present(self) -> None:
        security_finding()
        for field in ("finding_id", "agent", "category", "severity", "confidence",
                      "evidence", "affected_files", "recommendation", "metadata"):
            assert field in SecurityFinding.model_fields

    def test_minimal_construction(self) -> None:
        # Only the truly required fields are mandatory; the rest default.
        f = SecurityFinding(
            finding_id="CICD-007",
            agent=AgentName.CICD,
            category=FindingCategory.CICD,
        )
        assert f.confidence == 0.0
        assert f.evidence == []
        assert f.affected_files == []
        assert f.metadata == {}


# ---------------------------------------------------------------------------
# 3. confidence bounds
# ---------------------------------------------------------------------------


class TestConfidence:
    def test_zero_and_one_allowed(self) -> None:
        assert security_finding(confidence=0.0).confidence == 0.0
        assert security_finding(confidence=1.0).confidence == 1.0

    def test_coerces_numeric_string(self) -> None:
        assert security_finding(confidence="0.6").confidence == 0.6

    def test_below_zero_rejected(self) -> None:
        with pytest.raises(Exception):
            security_finding(confidence=-0.1)

    def test_above_one_rejected(self) -> None:
        with pytest.raises(Exception):
            security_finding(confidence=1.5)


# ---------------------------------------------------------------------------
# 4. invalid severity / 5. invalid or missing agent / 6. empty finding id
# ---------------------------------------------------------------------------


class TestValidation:
    def test_invalid_severity_rejected(self) -> None:
        with pytest.raises(Exception):
            security_finding(severity="not-a-severity")

    def test_invalid_agent_rejected(self) -> None:
        with pytest.raises(Exception):
            security_finding(agent="unknown_agent")

    def test_missing_agent_rejected(self) -> None:
        with pytest.raises(Exception):
            security_finding(agent=None)  # type: ignore[arg-type]

    def test_missing_category_rejected(self) -> None:
        with pytest.raises(Exception):
            security_finding(category=None)  # type: ignore[arg-type]

    def test_empty_finding_id_rejected(self) -> None:
        with pytest.raises(Exception):
            security_finding(finding_id="")

    def test_missing_finding_id_rejected(self) -> None:
        with pytest.raises(Exception):
            SecurityFinding(agent=AgentName.CICD, category=FindingCategory.CICD)


# ---------------------------------------------------------------------------
# 7. multiple affected files / 8. structured evidence / 9. metadata
# ---------------------------------------------------------------------------


class TestStructure:
    def test_multiple_affected_files(self) -> None:
        f = security_finding(affected_files=["a.py", "b.py", "c.py"])
        assert f.affected_files == ["a.py", "b.py", "c.py"]

    def test_affected_files_normalized_to_posix(self) -> None:
        f = security_finding(affected_files=["dir\\sub\\a.py", "dir/sub/b.py"])
        assert f.affected_files == ["dir/sub/a.py", "dir/sub/b.py"]

    def test_structured_evidence_items(self) -> None:
        f = security_finding(
            evidence=[
                EvidenceItem(kind=EvidenceKind.OBSERVED, content="semgrep: rule-x"),
                EvidenceItem(kind=EvidenceKind.INTERPRETATION, content="likely exploitable"),
            ]
        )
        kinds = [e.kind for e in f.evidence]
        assert kinds == [EvidenceKind.OBSERVED, EvidenceKind.INTERPRETATION]

    def test_evidence_is_list_of_validated_items(self) -> None:
        f = security_finding()
        for item in f.evidence:
            assert isinstance(item, EvidenceItem)
        # raw dicts are coerced on construction
        f2 = security_finding(
            evidence=[{"kind": "observed", "content": "tool: x"}]
        )
        assert f2.evidence[0].kind == EvidenceKind.OBSERVED

    def test_metadata_preserved(self) -> None:
        md = {"package": "requests", "version": "2.28.0", "fixed": "2.32.0"}
        f = security_finding(metadata=md)
        assert f.metadata == md


# ---------------------------------------------------------------------------
# 10. serialization / deserialization
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_round_trip_json(self) -> None:
        f = security_finding()
        data = f.model_dump_json()
        restored = SecurityFinding.model_validate_json(data)
        assert restored == f

    def test_all_core_fields_in_serialized(self) -> None:
        f = security_finding()
        obj = json.loads(f.model_dump_json())
        for key in ("finding_id", "agent", "category", "severity", "confidence",
                    "evidence", "affected_files", "recommendation", "metadata"):
            assert key in obj


# ---------------------------------------------------------------------------
# 11. deterministic finding IDs
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_identical_inputs_identical_output(self) -> None:
        a = security_finding()
        b = security_finding()
        assert a.model_dump_json() == b.model_dump_json()

    def test_finding_id_is_not_random(self) -> None:
        # Constructing twice yields the same deterministic id (no UUID churn).
        assert security_finding().finding_id == security_finding().finding_id


# ---------------------------------------------------------------------------
# 12. conversion from CodeFinding (adapter)
# ---------------------------------------------------------------------------


class TestConversion:
    def test_from_code_finding_preserves_core_fields(self) -> None:
        raw = code_finding()
        f = SecurityFinding.from_code_finding(
            raw, agent=AgentName.CODE_SECURITY, category=FindingCategory.CODE
        )
        assert f.finding_id == raw.finding_id
        assert f.severity == raw.severity
        assert f.confidence == raw.confidence
        assert f.file == raw.file
        assert f.line == raw.line
        assert f.description == raw.description

    def test_agent_and_category_stamped(self) -> None:
        raw = code_finding()
        f = SecurityFinding.from_code_finding(
            raw, agent=AgentName.DEPENDENCY, category=FindingCategory.DEPENDENCY
        )
        assert f.agent == AgentName.DEPENDENCY
        assert f.category == FindingCategory.DEPENDENCY

    def test_affected_files_derived(self) -> None:
        f = SecurityFinding.from_code_finding(
            code_finding(), agent=AgentName.CICD, category=FindingCategory.CICD
        )
        assert f.affected_files == ["src/app.py"]

    def test_affected_files_empty_when_no_file(self) -> None:
        f = SecurityFinding.from_code_finding(
            code_finding(file=""), agent=AgentName.CICD, category=FindingCategory.CICD
        )
        assert f.affected_files == []

    def test_evidence_classified_observed_vs_interpretation(self) -> None:
        raw = code_finding(evidence=[
            "semgrep: rule-x",                 # observed (tool prefix)
            "manifest: requirements.txt",       # observed
            "the request is vulnerable",        # interpretation
        ])
        f = SecurityFinding.from_code_finding(
            raw, agent=AgentName.CODE_SECURITY, category=FindingCategory.CODE
        )
        kinds = [e.kind for e in f.evidence]
        assert kinds == [
            EvidenceKind.OBSERVED,
            EvidenceKind.OBSERVED,
            EvidenceKind.INTERPRETATION,
        ]

    def test_conversion_is_deterministic(self) -> None:
        raw = code_finding()
        a = SecurityFinding.from_code_finding(
            raw, agent=AgentName.CODE_SECURITY, category=FindingCategory.CODE
        )
        b = SecurityFinding.from_code_finding(
            raw, agent=AgentName.CODE_SECURITY, category=FindingCategory.CODE
        )
        assert a.model_dump_json() == b.model_dump_json()

    def test_recommendation_passthrough(self) -> None:
        f = SecurityFinding.from_code_finding(
            code_finding(),
            agent=AgentName.CODE_SECURITY,
            category=FindingCategory.CODE,
            recommendation="Use parameterized queries.",
        )
        assert f.recommendation == "Use parameterized queries."

    def test_conversion_ignores_model_fabricated_agent(self) -> None:
        # CodeFinding has no agent/category field, so untrusted model output
        # cannot set them; they are always stamped by the agent.
        raw = code_finding()
        assert "agent" not in CodeFinding.model_fields
        f = SecurityFinding.from_code_finding(
            raw, agent=AgentName.CODE_SECURITY, category=FindingCategory.CODE
        )
        assert f.agent == AgentName.CODE_SECURITY
        assert f.category == FindingCategory.CODE


# ---------------------------------------------------------------------------
# 13-15. Compatibility with the three specialized agents
# ---------------------------------------------------------------------------


class TestAgentIntegration:
    @staticmethod
    def _finding(**overrides: object) -> CodeFinding:
        base = {
            "finding_id": "F-1",
            "severity": Severity.WARNING,
            "confidence": 0.7,
            "file": "src/x.py",
            "line": 3,
            "description": "issue",
            "evidence": ["observed: something", "interpreted: maybe"],
        }
        base.update(overrides)
        return CodeFinding(**base)

    def test_code_security_agent(self) -> None:
        agent = CodeSecurityAgent(FakeLLM([self._finding()]), ACTIVE_REPO)
        result = agent.investigate()
        canonical = agent.to_security_finding(result.finding)
        assert isinstance(canonical, SecurityFinding)
        assert canonical.agent == AgentName.CODE_SECURITY
        assert canonical.category == FindingCategory.CODE
        assert canonical.finding_id == "F-1"

    def test_dependency_agent(self) -> None:
        agent = DependencyAgent(FakeLLM([self._finding()]), ACTIVE_REPO)
        result = agent.investigate()
        canonical = agent.to_security_finding(result.finding)
        assert canonical.agent == AgentName.DEPENDENCY
        assert canonical.category == FindingCategory.DEPENDENCY

    def test_cicd_agent(self) -> None:
        agent = CICDSecurityAgent(FakeLLM([self._finding()]), CASE_A)
        result = agent.investigate()
        canonical = agent.to_security_finding(result.finding)
        assert canonical.agent == AgentName.CICD
        assert canonical.category == FindingCategory.CICD

    def test_all_agents_parse_common_core(self) -> None:
        # A consumer can parse the shared core fields without knowing the agent.
        canonicals = [
            self._canonical(
                CodeSecurityAgent, ACTIVE_REPO, AgentName.CODE_SECURITY
            ),
            self._canonical(
                DependencyAgent, ACTIVE_REPO, AgentName.DEPENDENCY
            ),
            self._canonical(
                CICDSecurityAgent, CASE_A, AgentName.CICD
            ),
        ]
        for f in canonicals:
            assert f.finding_id
            assert f.agent in AgentName
            assert f.category in FindingCategory
            assert f.severity in Severity
            assert 0.0 <= f.confidence <= 1.0

    @staticmethod
    def _canonical(agent_cls, repo: Path, expected: AgentName) -> SecurityFinding:
        agent = agent_cls(FakeLLM([TestAgentIntegration._finding()]), repo)
        result = agent.investigate()
        return agent.to_security_finding(result.finding)
