"""GitHub pull-request comment rendering and API boundary for SecureFlow.

This module has two responsibilities:

1. **Deterministic Markdown comment rendering** — turning the structured output of
   the investigation pipeline (``InvestigationResult``, ``RiskAssessment``,
   ``RemediationPlan``) into a concise, developer-friendly GitHub PR comment.
   Rendering is purely deterministic: no LLM is used and no evidence is
   fabricated. Every line of evidence comes from the structured data already
   produced by SecureFlow.

2. **The GitHub PR comment API boundary** — a minimal HTTP client that posts a
   comment to the GitHub issues/comments endpoint
   (``POST /repos/{owner}/{repo}/issues/{pr}/comments``).

Security properties inherited from the rest of the GitHub boundary:

- Only HTTPS endpoints are accepted (``api.github.com`` by default).
- Tokens are never logged and supplied via configuration/environment only.
- No shell commands or subprocess calls.
- No repository modification, remediation, commits, pushes, merges, or deploys.
- The comment body is composed only from validated, structured data.

Agents must never depend on this module or on raw GitHub API responses.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from src.github.models import GitHubComment
from src.investigation.models import InvestigationResult
from src.remediation.models import RemediationPlan
from src.risk.models import RiskAssessment

#: Stable HTML marker identifying SecureFlow's comment.
#: A future integration can search for this marker to update the existing
#: SecureFlow comment instead of creating duplicates.
COMMENT_MARKER = "<!-- secureflow-investigation -->"

DEFAULT_GITHUB_API_URL = "https://api.github.com"


# -- Comment rendering ------------------------------------------------------


def render_investigation_comment(
    investigation: InvestigationResult,
    risk: RiskAssessment,
    plan: RemediationPlan | None = None,
    investigation_link: str = "",
) -> str:
    """Render a deterministic, Markdown GitHub PR comment.

    Parameters
    ----------
    investigation:
        The completed investigation result (evidence, root causes, confidence).
    risk:
        The risk assessment (overall severity and confidence).
    plan:
        Optional remediation plan (root cause and recommended fix).
    investigation_link:
        Optional URL to the full investigation for the ``[View Investigation]``
        link.

    Returns
    -------
    str
        A Markdown comment suitable for posting to a GitHub PR issue thread.
    """
    severity = risk.severity.value.upper()
    confidence = _format_confidence(risk.confidence)

    root_cause = plan.root_cause if plan and plan.root_cause else ""
    if not root_cause:
        root_cause = _root_cause_from_investigation(investigation)

    evidence_lines = _collect_evidence(investigation, risk)

    recommended_fix = plan.recommended_fix if plan else ""
    if not recommended_fix and plan and plan.proposed_code_changes:
        recommended_fix = plan.proposed_code_changes[0].description

    parts: list[str] = []
    parts.append("## SecureFlow Security Investigation\n")
    parts.append(f"**Risk:** {severity}")
    parts.append(f"**Confidence:** {confidence}\n")

    parts.append("### Root Cause\n")
    if root_cause:
        parts.append(root_cause.strip() + "\n")
    else:
        parts.append("_No root cause could be determined._\n")

    if evidence_lines:
        parts.append("### Evidence\n")
        for line in evidence_lines:
            parts.append(f"- {line}")
        parts.append("")

    parts.append("### Recommended Fix\n")
    if recommended_fix:
        parts.append(recommended_fix.strip() + "\n")
    else:
        parts.append("_No remediation proposed yet._\n")

    if investigation_link:
        parts.append(f"[View Investigation]({investigation_link})\n")

    parts.append(COMMENT_MARKER)
    return "\n".join(parts)


def _format_confidence(value: float) -> str:
    """Format a 0..1 confidence as a percentage string, or 'N/A' if unset."""
    if value <= 0:
        return "N/A"
    return f"{round(value * 100)}%"


def _root_cause_from_investigation(investigation: InvestigationResult) -> str:
    """Derive a root cause from the investigation's structured candidates."""
    if investigation.root_cause_candidates:
        best = investigation.root_cause_candidates[0]
        if best.explanation:
            return best.explanation
        if best.component:
            return best.component
    if investigation.context and investigation.context.reasoning_history:
        # Use the first analytical reasoning entry, if present.
        for entry in investigation.context.reasoning_history:
            if entry.strip():
                return entry
    return ""


def _collect_evidence(
    investigation: InvestigationResult,
    risk: RiskAssessment,
) -> list[str]:
    """Collect evidence lines from structured data only.

    Order is deterministic: risk reasoning interpretation, investigation
    evidence, risk evidence, then finding-derived evidence. Empty and
    duplicate entries are filtered out.
    """
    seen: set[str] = set()
    lines: list[str] = []

    def add(content: str) -> None:
        text = content.strip()
        if text and text not in seen:
            seen.add(text)
            lines.append(text)

    # Risk reasoning interpretation first (most context-dense).
    for interpretation in risk.reasoning.interpretation:
        add(interpretation)

    # Investigation-level structured evidence.
    for evidence_item in investigation.evidence:
        if evidence_item.content:
            add(evidence_item.content)
        elif evidence_item.source:
            add(evidence_item.source)

    # Risk-level evidence.
    for risk_item in risk.evidence:
        if risk_item.content:
            add(risk_item.content)

    return lines


# -- PR comment API boundary ------------------------------------------------


class GitHubCommentConfig:
    """Configuration for posting GitHub PR comments.

    Reads values from the environment.  The token is supplied through
    GitHub Actions secrets / environment variables — never hard-coded.
    """

    def __init__(
        self,
        token: str | None = None,
        api_url: str = DEFAULT_GITHUB_API_URL,
        timeout: int = 30,
    ) -> None:
        self.token = token or os.environ.get("SECUREFLOW_GITHUB_TOKEN", "")
        self.api_url = api_url or DEFAULT_GITHUB_API_URL
        self.timeout = max(1, timeout)

    def validate(self) -> None:
        """Raise ``ValueError`` if the token or endpoint is misconfigured."""
        if not self.token:
            raise ValueError(
                "SECUREFLOW_GITHUB_TOKEN must be configured to post comments"
            )
        if not self.api_url.startswith("https://"):
            raise ValueError("GitHub API URL must use HTTPS")


class GitHubCommentClient:
    """Minimal, application-controlled GitHub PR comment HTTP client.

    Qualifies the repository/PR identity into the comments endpoint and POSTs
    the comment body using a bearer token.  Uses only the standard library; no
    third-party HTTP dependency is introduced.
    """

    def __init__(self, config: GitHubCommentConfig) -> None:
        self._config = config

    def post_comment(
        self,
        repository_full_name: str,
        pr_number: int,
        body: str,
    ) -> GitHubComment:
        """Post *body* as an issue comment on PR *pr_number*.

        Returns
        -------
        GitHubComment
            The parsed comment object as returned by GitHub.

        Raises
        ------
        ValueError
            If configuration is invalid.
        GitHubAPIError
            If the API returns a non-success response.
        """
        self._config.validate()

        owner, _, repo = repository_full_name.partition("/")
        if not owner or not repo:
            raise ValueError(
                f"Invalid repository_full_name: {repository_full_name!r}"
            )

        url = (
            f"{self._config.api_url}/repos/{owner}/{repo}/issues/{pr_number}/comments"
        )
        payload = json.dumps({"body": body}).encode()
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._config.token}",
        }

        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self._config.timeout) as resp:
                status_code = resp.status
                response_body = resp.read().decode()
        except urllib.error.HTTPError as exc:
            raise GitHubAPIError(f"HTTP {exc.code}: {exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise GitHubAPIError(f"GitHub API error: {exc}") from exc

        if not (200 <= status_code < 300):
            raise GitHubAPIError(f"GitHub API returned HTTP {status_code}")

        return _parse_comment(response_body)


class GitHubAPIError(Exception):
    """Raised when the GitHub API returns a failure or invalid response."""


def _parse_comment(body: str) -> GitHubComment:
    """Parse a GitHub issue-comment JSON response into ``GitHubComment``."""
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise GitHubAPIError("Invalid response from GitHub API") from None
    if not isinstance(data, dict):
        raise GitHubAPIError("Invalid response from GitHub API")
    return GitHubComment(
        id=data.get("id", 0),
        body=data.get("body", ""),
        html_url=data.get("html_url", ""),
        created_at=data.get("created_at", ""),
    )


# -- High-level integration -------------------------------------------------


class GitHubCommenter:
    """High-level facade that posts a rendered SecureFlow comment.

    This is the only place that composes rendering + API posting.  A test seam
    is not injected here because the client is easily faked; the facade remains
    thin and deterministic.
    """

    def __init__(
        self,
        config: GitHubCommentConfig,
        client: GitHubCommentClient,
    ) -> None:
        self._config = config
        self._client = client

    def post_investigation_comment(
        self,
        repository_full_name: str,
        pr_number: int,
        investigation: InvestigationResult,
        risk: RiskAssessment,
        plan: RemediationPlan | None = None,
        investigation_link: str = "",
    ) -> GitHubComment:
        """Render and post a SecureFlow investigation comment for a PR."""
        body = render_investigation_comment(
            investigation,
            risk,
            plan=plan,
            investigation_link=investigation_link,
        )
        return self._client.post_comment(repository_full_name, pr_number, body)
