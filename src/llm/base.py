"""LLM abstraction for SecureFlow agents.

This module defines a minimal, provider-agnostic interface for language
models. Agents depend on ``LLMProvider`` rather than on any specific SDK,
so tests can substitute a fake and providers can be swapped without touching
agent logic.

The provider is responsible ONLY for turning a conversation into a structured
``AgentDecision``. The application (agent loop) is responsible for executing
any requested tool.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, ValidationError

from src.models.code_finding import AgentDecision


class Message(BaseModel):
    """A single message in the agent conversation."""

    role: str
    content: str


class LLMProvider(ABC):
    """Abstract interface for a language model used by SecureFlow agents.

    Concrete providers implement :meth:`complete`, which accepts the
    conversation history and returns the next ``AgentDecision``. Providers
    may call a hosted API, invoke a local model, or (in tests) return a
    scripted response.
    """

    @abstractmethod
    def complete(self, messages: list[Message]) -> AgentDecision:
        """Return the next structured agent decision for a conversation.

        Args:
            messages: The full conversation history so far.

        Returns:
            An ``AgentDecision``, which either requests a tool call or
            produces a final ``CodeFinding``.
        """
        raise NotImplementedError


class MalformedLLMResponseError(Exception):
    """Raised when an LLM response cannot be parsed into a valid decision."""


class StructuredLLMProvider(LLMProvider):
    """Base helper for providers that parse raw model text into a decision.

    Subclasses override :meth:`raw_complete` to return the model's raw text;
    this class parses it as JSON and validates it into an ``AgentDecision``,
    enforcing our structured-output contract.
    """

    @abstractmethod
    def raw_complete(self, messages: list[Message]) -> str:
        """Return the raw text produced by the model."""
        raise NotImplementedError

    def complete(self, messages: list[Message]) -> AgentDecision:
        raw = self.raw_complete(messages)
        return parse_decision(raw)


def parse_decision(raw: str) -> AgentDecision:
    """Parse raw model text into an ``AgentDecision``.

    The raw text is expected to be a JSON object matching ``AgentDecision``,
    or a bare JSON object of a ``CodeFinding`` (which is wrapped into a final
    decision). Invalid JSON or invalid structure raises
    :class:`MalformedLLMResponseError` so the agent can treat it as a
    controlled failure rather than trusting arbitrary text.

    Args:
        raw: The raw text emitted by the model.

    Returns:
        A validated ``AgentDecision``.

    Raises:
        MalformedLLMResponseError: If the text is not valid JSON or does not
            form a well-structured decision.
    """
    import json

    text = raw.strip()
    if not text:
        raise MalformedLLMResponseError("Empty LLM response")

    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MalformedLLMResponseError(f"LLM response is not valid JSON: {exc.msg}") from exc

    if not isinstance(data, dict):
        raise MalformedLLMResponseError("LLM response must be a JSON object")

    # A bare finding object is interpreted as a final decision.
    if "finding" not in data and set(data.keys()) & {
        "finding_id", "severity", "confidence", "file",
    }:
        data = {"finding": data}

    try:
        return AgentDecision.model_validate(data)
    except ValidationError as exc:
        raise MalformedLLMResponseError(
            f"LLM response failed validation: {exc.errors()}"
        ) from exc
