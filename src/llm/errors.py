"""Typed errors raised by real LLM providers (Step 29).

These exceptions are what application code observes instead of raw SDK
exceptions. Instances never embed API keys, request headers, or prompt
contents: every message is a sanitized, human-readable summary.

``retryable`` classifies whether retrying the request is safe and useful.
Only transient failures (network, timeouts, rate limits, 5xx) are retryable;
config, authentication, and unexpected failures fail fast so callers never
burning unbounded quota on a permanent error.
"""

from __future__ import annotations


class LLMProviderError(Exception):
    """Base class for provider failures.

    ``category`` is a stable machine-readable label used for observability;
    ``retryable`` indicates whether the operation can be retried.
    """

    category = "provider"
    retryable = False

    def __init__(self, message: str) -> None:
        super().__init__(message)


class LLMConfigurationError(LLMProviderError):
    """Invalid provider configuration or a permanently rejected request."""

    category = "configuration"


class LLMAuthenticationError(LLMProviderError):
    """The provider rejected the supplied credentials or permission."""

    category = "authentication"


class LLMTimeoutError(LLMProviderError):
    """A request exceeded the configured timeout."""

    category = "timeout"
    retryable = True


class LLMRateLimitError(LLMProviderError):
    """The provider rate-limited or quota-limited the request."""

    category = "rate_limit"
    retryable = True


class LLMTransientError(LLMProviderError):
    """A transient network or 5xx failure that may succeed on retry."""

    category = "transient"
    retryable = True


class LLMUnexpectedProviderError(LLMProviderError):
    """An unexpected provider failure that could not be safely categorized."""

    category = "unexpected"