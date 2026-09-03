"""GitHub Action integration layer for SecureFlow.

This module bridges a ``GitHubPREvent`` (from the webhook boundary) into
the ``SecureFlowRequest`` (the API boundary) and invokes the API via an
injected HTTP client.  It is the single entry point for the GitHub Action
workflow.

Agents, the orchestrator, and investigation logic must not depend on
this module.
"""

from __future__ import annotations

import os

from src.api.client import (
    APIError,
    APITimeoutError,
    ConfigurationError,
    HTTPClientProtocol,
)
from src.api.models import ChangedFile, SecureFlowRequest, SecureFlowResponse
from src.github.models import GitHubPREvent


class SecureFlowActionConfig:
    """Configuration for the GitHub Action integration.

    Reads values from the environment.  Secrets and URLs are supplied
    through GitHub Actions environment variables — they are never
    hard-coded.
    """

    def __init__(
        self,
        url: str | None = None,
        token: str | None = None,
        timeout: int = 30,
    ) -> None:
        self.url = url or os.environ.get("SECUREFLOW_API_URL", "")
        self.token = token or os.environ.get("SECUREFLOW_API_TOKEN", "")
        self.timeout = timeout

    def validate(self) -> None:
        """Raise ``ConfigurationError`` if required settings are missing."""
        if not self.url:
            raise ConfigurationError(
                "SECUREFLOW_API_URL must be configured"
            )
        if not self.url.startswith("https://"):
            raise ConfigurationError(
                "SECUREFLOW_API_URL must use HTTPS"
            )


class SecureFlowAction:
    """High-level orchestrator for the GitHub Action integration.

    Constructs a ``SecureFlowRequest`` from a ``GitHubPREvent``, sends
    it via an injected HTTP client, and returns the result.
    """

    def __init__(
        self,
        config: SecureFlowActionConfig,
        client: HTTPClientProtocol,
    ) -> None:
        self._config = config
        self._client = client

    def run(self, event: GitHubPREvent) -> tuple[SecureFlowResponse | None, str | None]:
        """Execute the action for a single pull-request event.

        Returns
        -------
        tuple[SecureFlowResponse | None, str | None]
            A ``(response, None)`` on success, or ``(None, error_message)``
            on failure.
        """
        try:
            self._config.validate()
        except ConfigurationError as exc:
            return None, str(exc)

        request = event_to_request(event)
        try:
            result = self._client.send(self._config.url, request, self._config.token)
        except APITimeoutError as exc:
            return None, f"Request timed out: {exc}"
        except APIError as exc:
            return None, f"API error: {exc}"
        except Exception as exc:
            return None, f"Unexpected error: {exc}"

        return result, None


# -- Adapter: GitHubPREvent -> SecureFlowRequest ----------------------------


def event_to_request(event: GitHubPREvent) -> SecureFlowRequest:
    """Convert a ``GitHubPREvent`` into a ``SecureFlowRequest``.

    This is the explicit adapter between the webhook boundary and the
    API boundary.  It deliberately does not reuse ``GitHubPREvent``
    directly — the API model is minimal and decoupled from webhook
    concerns.
    """
    changed_files = [
        ChangedFile(
            filename=f.filename,
            status=f.status,
            additions=f.additions,
            deletions=f.deletions,
            changes=f.changes,
        )
        for f in event.changed_files
    ]

    return SecureFlowRequest(
        repository=event.repository_full_name,
        pr_number=event.pr_number,
        head_sha=event.head_sha,
        base_sha=event.base_sha,
        changed_files=changed_files,
    )
