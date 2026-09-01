"""Risk Agent LLM provider abstraction and fake (Step 19).

The Risk Agent reasons with a ``RiskLLMProvider`` rather than the code-agent
``LLMProvider`` because its output type differs: instead of a tool call or a
``CodeFinding`` it produces a structured :class:`~src.risk.models.RiskAssessment`.

The provider is responsible ONLY for turning the conversation into a structured
``RiskAssessment``; the application (the Risk Agent) performs grounding and
validation (dropping non-existent finding ids, invalidating unsupported attack
paths, bounding evidence) and enforces the safety boundary.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from pydantic import ValidationError

from src.llm.base import Message
from src.risk.models import RiskAssessment


class RiskLLMProvider(ABC):
    """Abstract interface for the model that drives the Risk Agent."""

    @abstractmethod
    def complete(self, messages: list[Message]) -> RiskAssessment:
        """Return a structured risk assessment for a conversation.

        Args:
            messages: The conversation, including the risk system instructions
                and the rendered investigation context.

        Returns:
            A structured :class:`RiskAssessment`.
        """
        raise NotImplementedError


class ParseRiskAssessmentError(Exception):
    """Raised when a model response cannot be parsed into a valid assessment."""


class FakeRiskLLM(RiskLLMProvider):
    """A scriptable, deterministic fake risk model for tests.

    Args:
        script: An iterable of items returned one per ``complete`` call. Each
            item may be a ``RiskAssessment``, a raw JSON ``str`` (parsed lazily
            so malformed responses are exercised by the agent, not at
            construction), or ``None`` (recorded as a malformed response).
        record: If True, record each call's messages on ``self.calls``.
    """

    def __init__(
        self,
        script: list[RiskAssessment | str | None],
        *,
        record: bool = False,
    ) -> None:
        self._script = list(script)
        self._pointer = 0
        self._record = record
        self.calls: list[list[Message]] = []

    def _resolve(self, item: RiskAssessment | str | None) -> RiskAssessment:
        if isinstance(item, RiskAssessment):
            return item
        if isinstance(item, str):
            return parse_risk_assessment(item)
        raise ParseRiskAssessmentError("FakeRiskLLM returned empty response")

    def complete(self, messages: list[Message]) -> RiskAssessment:
        if self._record:
            self.calls.append(list(messages))
        if self._pointer < len(self._script):
            item = self._script[self._pointer]
            self._pointer += 1
            return self._resolve(item)
        raise ParseRiskAssessmentError("FakeRiskLLM script exhausted")


def parse_risk_assessment(raw: str) -> RiskAssessment:
    """Parse raw model text into a ``RiskAssessment``.

    Invalid JSON, a non-object, or a structurally-invalid assessment (including
    out-of-bounds confidence) raises :class:`ParseRiskAssessmentError` so the
    Risk Agent can treat it as a controlled failure rather than trusting
    arbitrary text.

    Args:
        raw: The raw text emitted by the model.

    Returns:
        A validated :class:`RiskAssessment`.

    Raises:
        ParseRiskAssessmentError: If the text is not valid JSON or does not form
            a well-structured, in-bounds assessment.
    """
    text = raw.strip()
    if not text:
        raise ParseRiskAssessmentError("Empty LLM response")

    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseRiskAssessmentError(
            f"LLM response is not valid JSON: {exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise ParseRiskAssessmentError("LLM response must be a JSON object")

    try:
        return RiskAssessment.model_validate(data)
    except ValidationError as exc:
        raise ParseRiskAssessmentError(
            f"LLM response failed validation: {exc.errors()}"
        ) from exc