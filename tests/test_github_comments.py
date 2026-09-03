"""Tests for the GitHub PR comment rendering and API boundary (Step 23).

All tests are offline and deterministic.  They use synthetic structured
models and a fake HTTP client.  No network requests, no shell/subprocess
execution, and no repository modifications are performed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import src.github.comments as comments_module
from src.github.comments import (
    COMMENT_MARKER,
    GitHubCommentClient,
    GitHubCommentConfig,
    GitHubCommenter,
    render_investigation_comment,
)
from src.investigation.models import (
    InvestigationResult,
    RootCauseCandidate,
)
from src.models.finding import EvidenceItem, EvidenceKind
from src.remediation.models import (
    AffectedFile,
    CodeChange,
    RemediationPlan,
)
from src.risk.models import (
    Exploitability,
    RiskAssessment,
    RiskAsset,
    RiskEvidence,
    RiskReasoning,
    RiskSeverity,
)

# -- Helpers ----------------------------------------------------------------


def _investigation(
    *,
    confidence: float = 0.91,
    evidence: list[EvidenceItem] | None = None,
    root_cause: str = "",
) -> InvestigationResult:
    root_causes = []
    if root_cause:
        root_causes = [
            RootCauseCandidate(
                candidate_id="rc-1",
                finding_ids=["CODE-001"],
                component="auth.py",
                explanation=root_cause,
            )
        ]
    return InvestigationResult(
        investigation_id="inv-1",
        repository_name="octocat/hello-world",
        input_finding_ids=["CODE-001"],
        evidence=evidence
        or [
            EvidenceItem(
                kind=EvidenceKind.OBSERVED,
                content="Semgrep finding CODE-001",
                source="semgrep",
            ),
            EvidenceItem(
                kind=EvidenceKind.INTERPRETATION,
                content="Endpoint is publicly accessible",
            ),
        ],
        confidence=confidence,
        root_cause_candidates=root_causes,
    )


def _risk(
    *,
    severity: RiskSeverity = RiskSeverity.HIGH,
    confidence: float = 0.91,
    interpretation: list[str] | None = None,
    risk_evidence: list[RiskEvidence] | None = None,
) -> RiskAssessment:
    return RiskAssessment(
        assessment_id="risk-1",
        investigation_id="inv-1",
        severity=severity,
        confidence=confidence,
        exploitability=Exploitability.LIKELY,
        affected_assets=[RiskAsset(name="auth", kind="endpoint")],
        reasoning=RiskReasoning(
            observed=["Observed input flow"],
            interpretation=interpretation
            or ["Unsanitized user input reaches a SQL query."],
            assumptions=[],
        ),
        evidence=risk_evidence
        or [RiskEvidence(content="auth.py:42", finding_id="CODE-001")],
        finding_ids=["CODE-001"],
    )


def _plan(
    *,
    root_cause: str = "Unsanitized user input reaches a SQL query.",
    recommended_fix: str = "Use parameterized queries.",
    changes: list[CodeChange] | None = None,
) -> RemediationPlan:
    return RemediationPlan(
        remediation_id="rem-1",
        investigation_id="inv-1",
        risk_assessment_id="risk-1",
        root_cause=root_cause,
        recommended_fix=recommended_fix,
        proposed_code_changes=changes
        or [
            CodeChange(
                file="auth.py",
                description="Use parameterized queries",
                finding_id="CODE-001",
            )
        ],
        affected_files=[AffectedFile(path="auth.py", reason="Replace string concat")],
        finding_ids=["CODE-001"],
        severity=RiskSeverity.HIGH,
    )


def _root_cause_line(body: str) -> str:
    lines = body.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "### Root Cause":
            for nxt in lines[i + 1 :]:
                candidate = nxt.strip()
                if candidate and not candidate.startswith("#") and "**" not in candidate:
                    return candidate
    return ""


def _fix_line(body: str) -> str:
    lines = body.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "### Recommended Fix":
            for nxt in lines[i + 1 :]:
                candidate = nxt.strip()
                if candidate and not candidate.startswith("#") and "**" not in candidate:
                    return candidate
    return ""


# -- Renderer: complete result ----------------------------------------------


class TestRendering:
    def test_heading(self):
        body = render_investigation_comment(_investigation(), _risk(), _plan())
        assert "## SecureFlow Security Investigation" in body

    def test_role_marker(self):
        body = render_investigation_comment(_investigation(), _risk(), _plan())
        assert COMMENT_MARKER in body

    def test_risk_line(self):
        body = render_investigation_comment(
            _investigation(), _risk(severity=RiskSeverity.HIGH), _plan()
        )
        assert "**Risk:** HIGH" in body

    def test_confidence_line(self):
        body = render_investigation_comment(_investigation(), _risk(), _plan())
        assert "**Confidence:** 91%" in body

    def test_root_cause_from_plan(self):
        body = render_investigation_comment(_investigation(), _risk(), _plan())
        assert _root_cause_line(body) == "Unsanitized user input reaches a SQL query."

    def test_recommended_fix(self):
        body = render_investigation_comment(_investigation(), _risk(), _plan())
        assert _fix_line(body) == "Use parameterized queries."

    def test_evidence_rendered(self):
        body = render_investigation_comment(_investigation(), _risk(), _plan())
        assert "- Semgrep finding CODE-001" in body
        assert "- Endpoint is publicly accessible" in body
        assert "- auth.py:42" in body

    def test_investigation_link(self):
        body = render_investigation_comment(
            _investigation(),
            _risk(),
            _plan(),
            investigation_link="https://secureflow.example/inv/1",
        )
        assert "[View Investigation](https://secureflow.example/inv/1)" in body

    def test_no_investigation_link_when_omitted(self):
        body = render_investigation_comment(_investigation(), _risk(), _plan())
        assert "View Investigation" not in body


class TestRiskLevels:
    def test_high(self):
        body = render_investigation_comment(
            _investigation(), _risk(severity=RiskSeverity.HIGH), _plan()
        )
        assert "**Risk:** HIGH" in body

    def test_medium(self):
        body = render_investigation_comment(
            _investigation(), _risk(severity=RiskSeverity.MEDIUM), _plan()
        )
        assert "**Risk:** MEDIUM" in body

    def test_low(self):
        body = render_investigation_comment(
            _investigation(), _risk(severity=RiskSeverity.LOW), _plan()
        )
        assert "**Risk:** LOW" in body

    def test_critical(self):
        body = render_investigation_comment(
            _investigation(), _risk(severity=RiskSeverity.CRITICAL), _plan()
        )
        assert "**Risk:** CRITICAL" in body


class TestConfidenceRendering:
    def test_percentage(self):
        body = render_investigation_comment(
            _investigation(confidence=0.91), _risk(confidence=0.91), _plan()
        )
        assert "**Confidence:** 91%" in body

    def test_whole_percent(self):
        body = render_investigation_comment(
            _investigation(), _risk(confidence=1.0), _plan()
        )
        assert "**Confidence:** 100%" in body

    def test_zero_rendered_as_na(self):
        body = render_investigation_comment(
            _investigation(), _risk(confidence=0.0), _plan()
        )
        assert "**Confidence:** N/A" in body

    def test_small_confidence(self):
        body = render_investigation_comment(
            _investigation(), _risk(confidence=0.5), _plan()
        )
        assert "**Confidence:** 50%" in body


class TestMissingOptionalData:
    def test_no_remediation_plan(self):
        body = render_investigation_comment(_investigation(), _risk())
        assert "_No remediation proposed yet._" in body

    def test_no_root_cause(self):
        body = render_investigation_comment(
            _investigation(root_cause=""),
            _risk(),
            _plan(root_cause=""),
        )
        assert "_No root cause could be determined._" in body

    def test_no_evidence(self):
        inv = InvestigationResult(
            investigation_id="inv-1",
            repository_name="octocat/hello-world",
            input_finding_ids=["CODE-001"],
            evidence=[],
        )
        risk = RiskAssessment(assessment_id="risk-1", severity=RiskSeverity.LOW)
        body = render_investigation_comment(inv, risk, _plan())
        assert "### Evidence" not in body

    def test_confidence_unset(self):
        risk = RiskAssessment(assessment_id="risk-1", severity=RiskSeverity.LOW)
        body = render_investigation_comment(
            InvestigationResult(
                investigation_id="inv-1",
                repository_name="r",
                input_finding_ids=[],
            ),
            risk,
        )
        assert "**Confidence:** N/A" in body

    def test_empty_plan_ok(self):
        plan = RemediationPlan(remediation_id="rem-x")
        body = render_investigation_comment(_investigation(), _risk(), plan)
        assert "## SecureFlow Security Investigation" in body


# -- Stable marker ----------------------------------------------------------


class TestStableMarker:
    def test_marker_constant(self):
        assert COMMENT_MARKER == "<!-- secureflow-investigation -->"

    def test_marker_present_at_end(self):
        body = render_investigation_comment(_investigation(), _risk(), _plan())
        assert body.rstrip().endswith(COMMENT_MARKER)

    def test_marker_appears_once(self):
        body = render_investigation_comment(_investigation(), _risk(), _plan())
        assert body.count("<!-- secureflow-investigation -->") == 1


# -- Prevention of fabricated evidence --------------------------------------


class TestNoFabrication:
    def test_evidence_only_from_structured_data(self):
        inv = _investigation(evidence=[EvidenceItem(content="Observed A")])
        risk = _risk(interpretation=["Interpretation B"])
        body = render_investigation_comment(inv, risk, _plan())
        assert "Observed A" in body
        assert "Interpretation B" in body
        assert "0xDEADBEEF" not in body
        assert "https://fake.invalid" not in body

    def test_unknown_finding_ids_not_invented(self):
        inv = InvestigationResult(
            investigation_id="inv-1",
            repository_name="r",
            input_finding_ids=[],
            evidence=[],
        )
        risk = RiskAssessment(
            assessment_id="risk-1",
            severity=RiskSeverity.UNKNOWN,
        )
        body = render_investigation_comment(inv, risk)
        assert "NOT-REAL-001" not in body

    def test_no_duplicate_evidence_lines(self):
        inv = _investigation(
            evidence=[
                EvidenceItem(content="dup"),
                EvidenceItem(content="dup"),
            ]
        )
        body = render_investigation_comment(inv, _risk(), None)
        assert body.count("dup") == 1


# -- Determinism ------------------------------------------------------------


class TestDeterminism:
    def test_same_input_same_output(self):
        inv = _investigation()
        risk = _risk()
        plan = _plan()
        assert render_investigation_comment(inv, risk, plan) == (
            render_investigation_comment(inv, risk, plan)
        )

    def test_marker_stable(self):
        body1 = render_investigation_comment(_investigation(), _risk(), _plan())
        body2 = render_investigation_comment(_investigation(), _risk(), _plan())
        assert body1 == body2


# -- GitHubCommentConfig ----------------------------------------------------


class TestCommentConfig:
    def test_defaults(self):
        cfg = GitHubCommentConfig()
        assert cfg.api_url == "https://api.github.com"
        assert cfg.token == ""

    def test_explicit_values(self):
        cfg = GitHubCommentConfig(token="tok", api_url="https://api.example.com")
        assert cfg.token == "tok"
        assert cfg.api_url == "https://api.example.com"

    def test_validate_missing_token_raises(self):
        cfg = GitHubCommentConfig()
        with pytest.raises(ValueError, match="SECUREFLOW_GITHUB_TOKEN"):
            cfg.validate()

    def test_validate_non_https_api_url_raises(self):
        cfg = GitHubCommentConfig(token="tok", api_url="http://insecure.example.com")
        with pytest.raises(ValueError, match="HTTPS"):
            cfg.validate()

    def test_validate_ok(self):
        cfg = GitHubCommentConfig(token="tok")
        cfg.validate()

    def test_token_from_environment(self, monkeypatch):
        monkeypatch.setenv("SECUREFLOW_GITHUB_TOKEN", "env-token")
        cfg = GitHubCommentConfig()
        assert cfg.token == "env-token"


# -- GitHubCommentClient ----------------------------------------------------


class TestCommentClient:
    def test_invalid_repo_raises(self):
        cfg = GitHubCommentConfig(token="tok")
        client = GitHubCommentClient(cfg)
        with pytest.raises(ValueError):
            client.post_comment("no-slash", 1, "body")

    def test_invalid_config_raises(self):
        cfg = GitHubCommentConfig(token="")
        client = GitHubCommentClient(cfg)
        with pytest.raises(ValueError):
            client.post_comment("owner/repo", 1, "body")

    def test_no_network_in_client_source(self):
        src = Path(comments_module.__file__).read_text(encoding="utf-8")
        assert "import requests" not in src
        assert "import httpx" not in src
        assert "import subprocess" not in src
        assert "from subprocess" not in src
        assert "os.system(" not in src

    def test_no_hardcoded_token_in_source(self):
        src = Path(comments_module.__file__).read_text(encoding="utf-8")
        assert "ghp_" not in src
        assert "gho_" not in src
        assert "github_pat_" not in src
        assert "password" not in src.lower()


# -- GitHubCommenter facade --------------------------------------------------


class FakeClient:
    def post_comment(self, repository_full_name: str, pr_number: int, body: str):
        self.calls.append((repository_full_name, pr_number, body))
        return type(
            "GC",
            (),
            {
                "id": 1,
                "body": body,
                "html_url": "https://github.com/x",
                "created_at": "now",
            },
        )()

    def __init__(self) -> None:
        self.calls: list[tuple[str, int, str]] = []


class TestCommenter:
    def test_posts_rendered_comment(self):
        cfg = GitHubCommentConfig(token="tok")
        client = FakeClient()
        commenter = GitHubCommenter(cfg, client)  # type: ignore[arg-type]
        commenter.post_investigation_comment(
            "octocat/hello-world",
            42,
            _investigation(),
            _risk(),
            _plan(),
        )
        assert len(client.calls) == 1
        repo, pr, body = client.calls[0]
        assert repo == "octocat/hello-world"
        assert pr == 42
        assert COMMENT_MARKER in body
