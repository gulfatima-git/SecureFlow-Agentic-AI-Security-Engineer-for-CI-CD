"""GitHub webhook parser and validation boundary.

This module is the **only** place that touches raw GitHub JSON.  Every
other module in SecureFlow receives a validated ``GitHubPREvent``.

Security properties:

- No shell commands, subprocess calls, or network requests.
- No repository cloning, code execution, or file-system modification.
- Unknown / unsupported actions are rejected explicitly.
- Malformed payloads raise ``WebhookPayloadError``.
- Path traversal in filenames is rejected.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from src.github.models import GitHubPREvent, PRAction, PRFile
from src.models.repository import (
    ChangeStatus,
    FileChange,
    RepositoryContext,
)

# -- SHA validation ---------------------------------------------------------

_MIN_SHA_LENGTH = 7


class WebhookPayloadError(Exception):
    """Raised when a webhook payload is invalid or incomplete."""


class UnsupportedActionError(Exception):
    """Raised when a pull-request action should not trigger SecureFlow."""


# -- Path-traversal checks --------------------------------------------------

_DANGEROUS_PATH_COMPONENTS = frozenset({"..", "~"})


def _has_path_traversal(path: str) -> bool:
    """Return ``True`` if *path* contains directory-traversal components."""
    if "\0" in path:
        return True
    if path.startswith("/"):
        return True
    parts = path.replace("\\", "/").split("/")
    return any(p in _DANGEROUS_PATH_COMPONENTS for p in parts)


# -- SHA helpers ------------------------------------------------------------


def _validate_sha(value: object, field_name: str) -> str:
    """Validate and return a Git commit SHA string."""
    if not isinstance(value, str) or not value.strip():
        raise WebhookPayloadError(f"Missing or empty {field_name}")
    trimmed = value.strip()
    if len(trimmed) < _MIN_SHA_LENGTH:
        raise WebhookPayloadError(
            f"{field_name} too short ({len(trimmed)} < {_MIN_SHA_LENGTH})"
        )
    if not all(c in "0123456789abcdefABCDEF" for c in trimmed):
        raise WebhookPayloadError(f"{field_name} contains invalid characters")
    return trimmed.lower()


# -- Deep get helper --------------------------------------------------------


def _deep_get(data: dict[str, Any], *keys: str) -> Any:
    """Safely traverse nested dictionaries."""
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


# -- Core parser ------------------------------------------------------------


def parse_pr_webhook(payload: dict[str, Any]) -> GitHubPREvent:
    """Parse and validate a GitHub pull-request webhook payload.

    Parameters
    ----------
    payload:
        The decoded JSON body of a GitHub ``pull_request`` webhook event.

    Returns
    -------
    GitHubPREvent
        A fully validated, normalized internal representation.

    Raises
    ------
    WebhookPayloadError
        If required fields are missing or malformed.
    UnsupportedActionError
        If the PR action is not one of ``opened``, ``synchronize``,
        ``reopened``.
    """
    if not isinstance(payload, dict):
        raise WebhookPayloadError("Payload must be a JSON object")

    # -- Repository ----------------------------------------------------------
    repo = payload.get("repository")
    if not isinstance(repo, dict):
        raise WebhookPayloadError("Missing repository information")

    repo_full_name = repo.get("full_name", "")
    if not repo_full_name or not isinstance(repo_full_name, str):
        raise WebhookPayloadError("Missing or invalid repository full_name")

    parts = repo_full_name.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise WebhookPayloadError(
            f"Invalid repository full_name format: {repo_full_name!r}"
        )
    repo_owner, repo_name = parts[0], parts[1]

    # -- PR number -----------------------------------------------------------
    pr_number_raw = _deep_get(payload, "pull_request", "number")
    if not isinstance(pr_number_raw, int) or pr_number_raw < 1:
        raise WebhookPayloadError("Missing or invalid pull_request.number")

    # -- Action --------------------------------------------------------------
    action_raw = payload.get("action")
    if not isinstance(action_raw, str):
        raise WebhookPayloadError("Missing action")

    try:
        action = PRAction(action_raw)
    except ValueError:
        raise UnsupportedActionError(
            f"Action {action_raw!r} does not trigger SecureFlow"
        )

    # -- Commit SHAs ---------------------------------------------------------
    head_raw = _deep_get(payload, "pull_request", "head", "sha")
    head_sha = _validate_sha(head_raw, "head SHA")

    base_raw = _deep_get(payload, "pull_request", "base", "sha")
    base_sha = _validate_sha(base_raw, "base SHA") if base_raw else ""

    # -- Metadata ------------------------------------------------------------
    title = _deep_get(payload, "pull_request", "title") or ""
    if not isinstance(title, str):
        title = ""

    author = _deep_get(payload, "pull_request", "user", "login") or ""
    if not isinstance(author, str):
        author = ""

    draft = _deep_get(payload, "pull_request", "draft")
    if not isinstance(draft, bool):
        draft = False

    # -- Changed files -------------------------------------------------------
    raw_files = payload.get("files")
    changed_files: list[PRFile] = []
    if isinstance(raw_files, list):
        for entry in raw_files:
            if not isinstance(entry, dict):
                continue
            filename = entry.get("filename")
            if not isinstance(filename, str) or not filename.strip():
                continue
            if _has_path_traversal(filename):
                continue
            file_status = entry.get("status", "")
            if not isinstance(file_status, str):
                file_status = ""
            changed_files.append(
                PRFile(
                    filename=filename,
                    status=file_status,
                    additions=max(0, int(entry.get("additions", 0) or 0)),
                    deletions=max(0, int(entry.get("deletions", 0) or 0)),
                    changes=max(0, int(entry.get("changes", 0) or 0)),
                )
            )

    # -- Assemble event ------------------------------------------------------
    metadata: dict[str, str] = {
        "source": "github_webhook",
        "action": str(action),
    }

    return GitHubPREvent(
        repository_full_name=repo_full_name,
        repository_owner=repo_owner,
        repository_name=repo_name,
        pr_number=pr_number_raw,
        head_sha=head_sha,
        base_sha=base_sha,
        action=action,
        title=str(title),
        author=str(author),
        changed_files=changed_files,
        draft=draft,
        metadata=metadata,
    )


# -- Webhook handler --------------------------------------------------------


def webhook_handler(
    payload: dict[str, Any],
    *,
    event_type: str = "pull_request",
) -> GitHubPREvent | None:
    """Top-level webhook entry point.

    Parameters
    ----------
    payload:
        Decoded JSON body from the HTTP webhook request.
    event_type:
        The ``X-GitHub-Event`` header value.  Only ``pull_request`` is
        supported.

    Returns
    -------
    GitHubPREvent or None
        The normalized event if the webhook should trigger SecureFlow,
        or ``None`` if the event type is irrelevant.
    """
    if event_type != "pull_request":
        return None
    return parse_pr_webhook(payload)


# -- Signature verification -------------------------------------------------


def verify_signature(
    payload_bytes: bytes,
    signature_header: str,
    secret: str,
) -> bool:
    """Verify a GitHub webhook HMAC-SHA256 signature.

    Parameters
    ----------
    payload_bytes:
        The raw request body bytes.
    signature_header:
        The value of the ``X-Hub-Signature-256`` header.
    secret:
        The webhook secret configured in GitHub.

    Returns
    -------
    bool
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    if not secret or not signature_header:
        return False
    expected = "sha256=" + hmac.new(
        secret.encode(), payload_bytes, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


# -- Adapter: GitHubPREvent -> RepositoryContext ----------------------------


def _map_file_status(status: str) -> ChangeStatus:
    """Map a GitHub file status string to ``ChangeStatus``."""
    mapping = {
        "added": ChangeStatus.ADDED,
        "modified": ChangeStatus.MODIFIED,
        "removed": ChangeStatus.DELETED,
        "renamed": ChangeStatus.RENAMED,
    }
    return mapping.get(status.lower(), ChangeStatus.MODIFIED)


def to_repository_context(event: GitHubPREvent) -> RepositoryContext:
    """Convert a validated ``GitHubPREvent`` into a ``RepositoryContext``.

    This adapter bridges the GitHub integration boundary into
    SecureFlow's existing orchestration architecture.

    The resulting ``RepositoryContext`` carries:

    - ``repository_name`` and ``repository_url`` derived from the PR.
    - ``commit_sha`` set to the PR's ``head_sha``.
    - ``changed_files`` mapped from the PR's file list.
    - ``metadata`` including the PR number and source information.

    Files are **not** classified here because classification requires
    filesystem access (handled by ``RepositoryIngestor``).  Downstream
    consumers that need classified files should pass the context through
    the full ingestion pipeline.

    ``local_path`` is set to an empty string because no checkout is
    performed at the webhook boundary.
    """
    repository_url = f"https://github.com/{event.repository_full_name}.git"

    changed_files = [
        FileChange(
            path=f.filename,
            status=_map_file_status(f.status),
        )
        for f in event.changed_files
    ]

    metadata = {
        **event.metadata,
        "pr_number": str(event.pr_number),
        "head_sha": event.head_sha,
    }
    if event.base_sha:
        metadata["base_sha"] = event.base_sha
    if event.title:
        metadata["pr_title"] = event.title
    if event.author:
        metadata["pr_author"] = event.author

    return RepositoryContext(
        repository_name=event.repository_full_name,
        repository_url=repository_url,
        local_path="",
        commit_sha=event.head_sha,
        changed_files=changed_files,
        metadata=metadata,
    )
