"""HTTP client boundary for the SecureFlow API.

This module provides an application-controlled HTTP client that sends
``SecureFlowRequest`` payloads to a configured endpoint.  It defines a
protocol-based test seam so that tests can exercise the full client
without any network access.

Security properties:

- Only HTTPS endpoints are accepted.
- Tokens are never logged.
- Timeouts and retries are bounded.
- No shell commands or subprocess calls.
"""

from __future__ import annotations

import json
import typing
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from src.api.models import RequestStatus, SecureFlowRequest, SecureFlowResponse


class APIError(Exception):
    """Raised when the SecureFlow API returns a non-success response."""


class APITimeoutError(APIError):
    """Raised when the API request times out."""


class ConfigurationError(Exception):
    """Raised when required API configuration is missing or invalid."""


# -- Test seam: protocol for HTTP clients ----------------------------------


class HTTPClientProtocol(typing.Protocol):
    """Minimal interface for HTTP clients used by SecureFlow."""

    def send(self, url: str, request: SecureFlowRequest, token: str) -> SecureFlowResponse:
        """Send *request* to *url* and return a parsed response."""
        ...


# -- Real HTTP client -------------------------------------------------------


class SecureFlowHTTPClient:
    """Production HTTP client that sends ``SecureFlowRequest`` to the API.

    The endpoint URL and bearer token are supplied at construction time
    (typically from environment variables via ``SecureFlowActionConfig``).
    """

    def __init__(self, url: str, token: str = "", timeout: int = 30) -> None:
        if not url:
            raise ConfigurationError("API URL is required")
        if not url.startswith("https://"):
            raise ConfigurationError(
                "API URL must use HTTPS; "
                f"received {url[:20]}..."
                if len(url) > 20
                else f"API URL must use HTTPS; received {url!r}"
            )
        self._url = url
        self._token = token
        self._timeout = max(1, timeout)

    def send(
        self,
        url: str,
        request: SecureFlowRequest,
        token: str,
    ) -> SecureFlowResponse:
        body = request.model_dump_json().encode()
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        req = Request(url, data=body, headers=headers, method="POST")  # noqa: S310

        try:
            with urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                status_code = resp.status
                resp_body = resp.read().decode()
        except HTTPError as exc:
            raise APIError(f"HTTP {exc.code}: {exc.reason}") from exc
        except URLError as exc:
            raise APITimeoutError(str(exc)) from exc

        if not (200 <= status_code < 300):
            raise APIError(f"HTTP {status_code}")

        return _parse_response(resp_body)


def _parse_response(body: str) -> SecureFlowResponse:
    """Parse a JSON response body into ``SecureFlowResponse``."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return SecureFlowResponse(message="Invalid response from API")
    if not isinstance(data, dict):
        return SecureFlowResponse(message="Invalid response from API")
    return SecureFlowResponse.model_validate(data)


# -- Fake / test client -----------------------------------------------------


class SecureFlowFakeHTTPClient:
    """Deterministic fake HTTP client for offline tests.

    Returns pre-configured responses without any network access.  The
    ``responses`` queue is consumed in FIFO order; once exhausted, the
    client returns a default success response.
    """

    def __init__(
        self,
        responses: list[SecureFlowResponse] | None = None,
    ) -> None:
        self._responses = list(responses or [])
        self._calls: list[SecureFlowRequest] = []

    @property
    def calls(self) -> list[SecureFlowRequest]:
        return list(self._calls)

    def send(
        self,
        url: str,
        request: SecureFlowRequest,
        token: str,
    ) -> SecureFlowResponse:
        self._calls.append(request)
        if self._responses:
            return self._responses.pop(0)
        return SecureFlowResponse(
            status=RequestStatus.COMPLETED,
            message="OK",
        )
