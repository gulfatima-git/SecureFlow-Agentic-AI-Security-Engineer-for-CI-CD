"""OpenAI-backed structured LLM provider (Step 29).

This is the first real, environment-configured LLM provider in SecureFlow.
It integrates with the existing ``StructuredLLMProvider`` abstraction, so
agents keep consuming ``AgentDecision`` objects exactly as they do with
``FakeLLM`` — no agent code was changed.

Design notes:

* Configuration is environment-driven and validated
  (``OPENAI_API_KEY``, ``OPENAI_MODEL`` required; timeouts and retries
  bounded and configurable). The API key is stored as a ``SecretStr`` so it
  never appears in ``str``/``repr``/serialized config.
* The provider transmits the agent's ``Message`` list to the Chat
  Completions API as-is. Repository content remains untrusted data; the
  provider never executes or interprets it.
* Structured output is requested from the API via ``response_format`` JSON
  mode; the existing Pydantic-based ``parse_decision`` remains the sole
  source of truth for validation.
* The official SDK client is built with its built-in retries disabled
  (``max_retries=0``); retries live here so they are bounded, sleep between
  attempts with capped exponential backoff, and only retry transient
  failures (timeout, network, rate limit, 5xx).
* Telemetry (latency via a monotonic clock, reported token usage, retry
  count, deterministic cost estimate) is exposed through ``last_telemetry``
  and never includes credentials or message contents.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from time import perf_counter
from typing import Any

import openai
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from src.llm.base import Message, StructuredLLMProvider
from src.llm.errors import (
    LLMAuthenticationError,
    LLMConfigurationError,
    LLMProviderError,
    LLMRateLimitError,
    LLMTimeoutError,
    LLMTransientError,
    LLMUnexpectedProviderError,
)
from src.llm.telemetry import LLMTelemetry, LLMTokenUsage, estimate_openai_cost

ENV_API_KEY = "OPENAI_API_KEY"
ENV_MODEL = "OPENAI_MODEL"
ENV_TIMEOUT = "OPENAI_TIMEOUT_SECONDS"
ENV_MAX_RETRIES = "OPENAI_MAX_RETRIES"

DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_MAX_RETRIES = 3
MAX_BACKOFF_SECONDS = 30.0
BASE_BACKOFF_SECONDS = 0.5


class OpenAIProviderConfig(BaseModel):
    """Validated OpenAI provider configuration.

    The API key is stored as :class:`pydantic.SecretStr`, so Python
    ``str``/``repr`` and JSON serialization mask it instead of revealing it.

    Attributes:
        api_key: The OpenAI API key.
        model: The model identifier to call (e.g. ``gpt-4o-mini``).
        timeout: Request timeout in seconds (must be > 0).
        max_retries: Maximum number of automatic retries for transient
            failures (must be >= 0).
    """

    model_config = ConfigDict(extra="forbid")

    api_key: SecretStr
    model: str = Field(min_length=1)
    timeout: float = Field(default=DEFAULT_TIMEOUT_SECONDS, gt=0.0)
    max_retries: int = Field(default=DEFAULT_MAX_RETRIES, ge=0)

    def api_key_value(self) -> str:
        """Return the raw API key for use at the SDK boundary only."""
        return self.api_key.get_secret_value()

    @classmethod
    def from_env(cls) -> OpenAIProviderConfig:
        """Build and validate config from environment variables.

        Requires non-empty ``OPENAI_API_KEY`` and ``OPENAI_MODEL``. Optional
        ``OPENAI_TIMEOUT_SECONDS`` and ``OPENAI_MAX_RETRIES`` override the
        defaults. Invalid values raise :class:`LLMConfigurationError`.
        """
        api_key = os.environ.get(ENV_API_KEY, "").strip()
        if not api_key:
            raise LLMConfigurationError(f"Missing required environment variable {ENV_API_KEY}")
        model = os.environ.get(ENV_MODEL, "").strip()
        if not model:
            raise LLMConfigurationError(f"Missing required environment variable {ENV_MODEL}")
        timeout_raw = os.environ.get(ENV_TIMEOUT, str(DEFAULT_TIMEOUT_SECONDS))
        retries_raw = os.environ.get(ENV_MAX_RETRIES, str(DEFAULT_MAX_RETRIES))
        try:
            return cls(
                api_key=SecretStr(api_key),
                model=model,
                timeout=float(timeout_raw),
                max_retries=int(retries_raw),
            )
        except ValueError as exc:
            raise LLMConfigurationError(
                f"Invalid {ENV_TIMEOUT or ENV_MAX_RETRIES} value ({exc})"
            ) from exc
        except ValidationError as exc:
            raise _validation_error(exc) from exc


def _validation_error(exc: ValidationError) -> LLMConfigurationError:
    """Convert a Pydantic validation error into a secret-free config error."""
    details = [
        f"{'.'.join(str(part) for part in err['loc'])}: {err['msg']}"
        for err in exc.errors()
    ]
    return LLMConfigurationError(
        "Invalid OpenAI provider configuration: " + "; ".join(details)
    )


class OpenAIProvider(StructuredLLMProvider):
    """OpenAI Chat Completions provider producing structured ``AgentDecision``.

    Args:
        config: Validated provider configuration.
        client: Optional pre-built client (used by tests). When omitted, the
            client is constructed from ``config``.
        clock: Optional monotonic clock (used by tests); defaults to
            ``perf_counter``.
        sleep: Optional sleep function used between retries (used by tests);
            defaults to ``time.sleep``.
    """

    provider_name = "openai"

    def __init__(
        self,
        config: OpenAIProviderConfig,
        *,
        client: Any | None = None,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self._config = config
        self._client = client if client is not None else _create_sdk_client(config)
        self._clock = clock if clock is not None else perf_counter
        self._sleep = sleep if sleep is not None else time.sleep
        self._last_telemetry: LLMTelemetry | None = None

    @property
    def config(self) -> OpenAIProviderConfig:
        return self._config

    @property
    def model(self) -> str:
        return self._config.model

    @property
    def last_telemetry(self) -> LLMTelemetry | None:
        """Telemetry from the most recent ``complete``/``raw_complete`` call.

        ``None`` until the first request completes or fails classification.
        """
        return self._last_telemetry

    def raw_complete(self, messages: list[Message]) -> str:
        """Send the conversation to OpenAI and return the raw model text.

        Latency is measured with a monotonic clock around the request
        (including any retries); token usage comes only from the API
        response. Message contents and credentials are never logged or
        embedded in telemetry.
        """
        started = self._clock()
        response, attempts = self._post_with_retries(messages)
        latency_seconds = self._clock() - started

        usage = _usage_from_response(response)
        self._last_telemetry = LLMTelemetry(
            provider=self.provider_name,
            model=self._config.model,
            latency_seconds=latency_seconds,
            usage=usage,
            retries=attempts - 1,
            estimated_cost=estimate_openai_cost(self._config.model, usage),
        )
        return _first_content(response)

    def _post_with_retries(self, messages: list[Message]) -> tuple[Any, int]:
        """Post once to the API, retrying transient failures up to the bound.

        Returns the response and the number of attempts made. Non-transient
        failures raise immediately; transient failures are retried with
        capped exponential backoff until the bound is reached, then raise.
        """
        payload = [
            {"role": message.role, "content": message.content}
            for message in messages
        ]
        last_error: LLMProviderError | None = None
        for attempt in range(self._config.max_retries + 1):
            try:
                response = self._client.chat.completions.create(
                    model=self._config.model,
                    messages=payload,
                    response_format={"type": "json_object"},
                )
                return response, attempt + 1
            except Exception as exc:
                error = _translate_error(exc)
                last_error = error
                if error.retryable and attempt < self._config.max_retries:
                    backoff = min(MAX_BACKOFF_SECONDS, BASE_BACKOFF_SECONDS * (2**attempt))
                    self._sleep(backoff)
                    continue
                raise error from exc
        assert last_error is not None
        raise last_error


def _create_sdk_client(config: OpenAIProviderConfig) -> Any:
    """Build the official OpenAI SDK client from validated config.

    ``max_retries=0`` disables the SDK's own retry loop; retries are owned
    by :class:`OpenAIProvider` so they stay bounded and deterministic.
    """
    return openai.OpenAI(
        api_key=config.api_key_value(),
        timeout=config.timeout,
        max_retries=0,
    )


def _first_content(response: Any) -> str:
    """Extract the assistant text from a Chat Completions response.

    Returns an empty string when the response has no usable content; the
    caller's Pydantic parsing then treats it as a malformed response.
    """
    choices = getattr(response, "choices", None)
    if not choices:
        return ""
    message = getattr(choices[0], "message", None)
    content = getattr(message, "content", None)
    return content if isinstance(content, str) else ""


def _usage_from_response(response: Any) -> LLMTokenUsage:
    """Read token usage straight from the API response, without inventing.

    ``total_tokens`` is derived from input + output only when the API
    reported both; absent counts stay ``None``.
    """
    usage = getattr(response, "usage", None)
    if usage is None:
        return LLMTokenUsage()
    input_tokens = _token_count(getattr(usage, "prompt_tokens", None))
    output_tokens = _token_count(getattr(usage, "completion_tokens", None))
    total_tokens = _token_count(getattr(usage, "total_tokens", None))
    if total_tokens is None and input_tokens is not None and output_tokens is not None:
        total_tokens = input_tokens + output_tokens
    return LLMTokenUsage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
    )


def _token_count(value: Any) -> int | None:
    """Return ``value`` only if it is a genuinely reported token count."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _translate_error(exc: Exception) -> LLMProviderError:
    """Map an SDK exception to a sanitized, typed :class:`LLMProviderError`.

    The resulting message never embeds the SDK exception text (which may
    include request headers) nor any credentials.
    """
    if isinstance(exc, LLMProviderError):
        return exc
    if isinstance(exc, openai.APITimeoutError):
        return LLMTimeoutError("OpenAI request timed out")
    if isinstance(exc, openai.RateLimitError):
        return LLMRateLimitError(_status_message("OpenAI rate-limited the request", exc))
    if isinstance(exc, openai.AuthenticationError):
        return LLMAuthenticationError("OpenAI rejected the API credentials")
    if isinstance(exc, openai.PermissionDeniedError):
        return LLMAuthenticationError(_status_message("OpenAI denied permission", exc))
    if isinstance(exc, openai.BadRequestError):
        return LLMConfigurationError(_status_message("OpenAI rejected the request", exc))
    if isinstance(exc, openai.InternalServerError):
        return LLMTransientError(_status_message("OpenAI internal server error", exc))
    if isinstance(exc, openai.APIConnectionError):
        return LLMTransientError("Failed to connect to the OpenAI API")
    if isinstance(exc, openai.APIStatusError):
        if exc.status_code >= 500:
            return LLMTransientError(_status_message("OpenAI server error", exc))
        if exc.status_code == 429:
            return LLMRateLimitError(_status_message("OpenAI rate-limited the request", exc))
        return LLMUnexpectedProviderError(_status_message("OpenAI request failed", exc))
    return LLMUnexpectedProviderError(f"Unexpected OpenAI SDK error: {type(exc).__name__}")


def _status_message(prefix: str, exc: openai.APIStatusError) -> str:
    """A safe, fixed-format status message containing only the HTTP status."""
    return f"{prefix} (status={exc.status_code})"