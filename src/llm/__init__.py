"""LLM provider implementations and base abstractions.

Unit tests use the fake provider in :mod:`src.llm.fake`. Real providers should
implement :class:`src.llm.base.LLMProvider` (or
:class:`src.llm.base.StructuredLLMProvider`) and be injected into an agent.
"""

from src.llm.base import (
    LLMProvider,
    MalformedLLMResponseError,
    Message,
    StructuredLLMProvider,
    parse_decision,
)

__all__ = [
    "LLMProvider",
    "MalformedLLMResponseError",
    "Message",
    "StructuredLLMProvider",
    "parse_decision",
]
