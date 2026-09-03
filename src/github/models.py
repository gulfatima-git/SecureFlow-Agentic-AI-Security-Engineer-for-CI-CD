"""Structured models for GitHub pull-request events.

These models represent the *normalized internal* representation of a
GitHub PR webhook payload.  They are intentionally decoupled from the
raw JSON structure so that downstream code never touches untrusted
GitHub data directly.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class PRAction(StrEnum):
    """Supported pull-request webhook actions.

    Only actions that should trigger a SecureFlow security investigation
    are listed here.  ``closed``, ``labeled``, etc. are deliberately
    excluded.
    """

    OPENED = "opened"
    SYNCHRONIZE = "synchronize"
    REOPENED = "reopened"


class PRFile(BaseModel):
    """A single file changed in the pull request.

    Paths are repository-relative and stored exactly as GitHub reports
    them.  Path-traversal confinement is enforced at parse time rather
    than in the model itself.
    """

    filename: str
    status: str = ""
    additions: int = Field(default=0, ge=0)
    deletions: int = Field(default=0, ge=0)
    changes: int = Field(default=0, ge=0)


class GitHubPREvent(BaseModel):
    """Normalized, validated representation of a GitHub pull-request event.

    This is the single internal model that all downstream code consumes.
    It contains only the fields that are genuinely useful for
    orchestrating a SecureFlow security investigation.
    """

    repository_full_name: str
    repository_owner: str
    repository_name: str
    pr_number: int = Field(ge=1)
    head_sha: str = Field(min_length=1)
    base_sha: str = ""
    action: PRAction
    title: str = ""
    author: str = ""
    changed_files: list[PRFile] = Field(default_factory=list)
    draft: bool = False
    metadata: dict[str, str] = Field(default_factory=dict)


class GitHubComment(BaseModel):
    """A GitHub PR issue comment, as returned by the API.

    ``id`` and ``created_at`` may be empty when only the body is being
    constructed locally (before a POST).  ``html_url`` is populated from the
    API response when available.
    """

    id: int = 0
    body: str = ""
    html_url: str = ""
    created_at: str = ""
