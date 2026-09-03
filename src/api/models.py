"""Structured request and response models for the SecureFlow API boundary.

``SecureFlowRequest`` is the single internal model consumed by the
SecureFlow API.  ``SecureFlowResponse`` captures the minimal result
returned to callers such as the GitHub Action.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class RequestStatus(StrEnum):
    """High-level status of an API request."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class ChangedFile(BaseModel):
    """A file changed in the pull request, as seen by the API."""

    filename: str
    status: str = ""
    additions: int = Field(default=0, ge=0)
    deletions: int = Field(default=0, ge=0)
    changes: int = Field(default=0, ge=0)


class SecureFlowRequest(BaseModel):
    """Structured request sent to the SecureFlow API.

    This model captures the information required to identify and initiate
    a pull-request security investigation.  It is deliberately minimal
    and does not duplicate ``GitHubPREvent`` — an explicit adapter
    converts between the two at the boundary.
    """

    repository: str = Field(min_length=1)
    pr_number: int = Field(ge=1)
    head_sha: str = Field(min_length=1)
    base_sha: str = ""
    changed_files: list[ChangedFile] = Field(default_factory=list)


class SecureFlowResponse(BaseModel):
    """Minimal response returned by the SecureFlow API.

    This is intentionally small: only enough information for callers
    (e.g. the GitHub Action) to determine the outcome and surface a
    bounded log entry.
    """

    status: RequestStatus = RequestStatus.PENDING
    message: str = ""
    request_id: str = ""
