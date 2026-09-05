"""LLM provider implementations and base abstractions.

Unit tests use the fake provider in :mod:`src.llm.fake`. The real, hosted
OpenAI provider lives in :mod:`src.llm.openai` and implements the same
:class:`src.llm.base.StructuredLLMProvider` contract, so agents are injected
with a provider without depending on any SDK.
"""

from src.llm.base import (
    LLMProvider,
    MalformedLLMResponseError,
    Message,
    StructuredLLMProvider,
    parse_decision,
)
from src.llm.errors import (
    LLMAuthenticationError,
    LLMConfigurationError,
    LLMProviderError,
    LLMRateLimitError,
    LLMTimeoutError,
    LLMTransientError,
    LLMUnexpectedProviderError,
)
from src.llm.openai import OpenAIProvider, OpenAIProviderConfig
from src.llm.telemetry import LLMCost, LLMTelemetry, LLMTokenUsage

__all__ = [
    "LLMAuthenticationError",
    "LLMConfigurationError",
    "LLMCost",
    "LLMProvider",
    "LLMProviderError",
    "LLMRateLimitError",
    "LLMTelemetry",
    "LLMTimeoutError",
    "LLMTokenUsage",
    "LLMTransientError",
    "LLMUnexpectedProviderError",
    "MalformedLLMResponseError",
    "Message",
    "OpenAIProvider",
    "OpenAIProviderConfig",
    "StructuredLLMProvider",
    "parse_decision",
]
