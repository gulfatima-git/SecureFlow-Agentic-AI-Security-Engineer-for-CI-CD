"""Remediation Agent LLM provider abstraction and fake (Step 20).

The Remediation Agent reasons with a ``RemediationLLMProvider`` rather than the
code-agent ``LLMProvider`` because its output type differs: instead of a tool
call or a ``CodeFinding`` it produces a structured
:class:`~src.remediation.models.RemediationPlan`.

The provider is responsible ONLY for turning the conversation into a structured
``RemediationPlan``; the application (the Remediation Agent) performs grounding
and validation (removing non-existent finding ids, marking affected-file
verification, bounding lists, reclassifying unsupported evidence) and enforces
the safety boundary. The provider never writes to the repository.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from pydantic import ValidationError

from src.llm.base import Message
from src.remediation.models import RemediationPlan


class RemediationLLMProvider(ABC):
    """Abstract interface for the model that drives the Remediation Agent."""

    @abstractmethod
    def complete(self, messages: list[Message]) -> RemediationPlan:
        """Return a structured remediation plan for a conversation.

        Args:
            messages: The conversation, including the remediation system
                instructions and the rendered investigation/risk context.

        Returns:
            A structured :class:`RemediationPlan`.
        """
        raise NotImplementedError


class ParseRemediationPlanError(Exception):
    """Raised when a model response cannot be parsed into a valid plan."""


class FakeRemediationLLM(RemediationLLMProvider):
    """A scriptable, deterministic fake remediation model for tests.

    Args:
        script: An iterable of items returned one per ``complete`` call. Each
            item may be a ``RemediationPlan``, a raw JSON ``str`` (parsed lazily
            so malformed responses are exercised by the agent, not at
            construction), or ``None`` (recorded as a malformed response).
        record: If True, record each call's messages on ``self.calls``.
    """

    def __init__(
        self,
        script: list[RemediationPlan | str | None],
        *,
        record: bool = False,
    ) -> None:
        self._script = list(script)
        self._pointer = 0
        self._record = record
        self.calls: list[list[Message]] = []

    def _resolve(self, item: RemediationPlan | str | None) -> RemediationPlan:
        if isinstance(item, RemediationPlan):
            return item
        if isinstance(item, str):
            return parse_remediation_plan(item)
        raise ParseRemediationPlanError("FakeRemediationLLM returned empty response")

    def complete(self, messages: list[Message]) -> RemediationPlan:
        if self._record:
            self.calls.append(list(messages))
        if self._pointer < len(self._script):
            item = self._script[self._pointer]
            self._pointer += 1
            return self._resolve(item)
        raise ParseRemediationPlanError("FakeRemediationLLM script exhausted")


def parse_remediation_plan(raw: str) -> RemediationPlan:
    """Parse raw model text into a ``RemediationPlan``.

    Invalid JSON, a non-object, or a structurally-invalid plan (including
    out-of-bounds confidence) raises :class:`ParseRemediationPlanError` so the
    Remediation Agent can treat it as a controlled failure rather than trusting
    arbitrary text.

    Args:
        raw: The raw text emitted by the model.

    Returns:
        A validated :class:`RemediationPlan`.

    Raises:
        ParseRemediationPlanError: If the text is not valid JSON or does not form
            a well-structured, in-bounds plan.
    """
    text = raw.strip()
    if not text:
        raise ParseRemediationPlanError("Empty LLM response")

    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseRemediationPlanError(
            f"LLM response is not valid JSON: {exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise ParseRemediationPlanError("LLM response must be a JSON object")

    try:
        return RemediationPlan.model_validate(data)
    except ValidationError as exc:
        raise ParseRemediationPlanError(
            f"LLM response failed validation: {exc.errors()}"
        ) from exc