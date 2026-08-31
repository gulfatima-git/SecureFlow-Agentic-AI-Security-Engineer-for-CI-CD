"""Investigation LLM provider abstraction and fake (Step 17).

The Investigation Agent reasons with an ``InvestigationLLMProvider`` rather than
the code-agent ``LLMProvider`` because its decision type differs: instead of a
tool call or a ``CodeFinding``, each step either requests additional specialist
evidence (an ``InvestigationRequest``) or emits a final :class:`InvestigationOutput`.

The provider is responsible ONLY for turning the conversation into a structured
``InvestigationDecision``; the application (the investigation loop) executes any
specialist request through the controlled ``CollaborationInterface``.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from pydantic import ValidationError

from src.investigation.models import (
    InvestigationDecision,
    InvestigationOutput,
)
from src.llm.base import Message


class InvestigationLLMProvider(ABC):
    """Abstract interface for the model that drives the Investigation Agent."""

    @abstractmethod
    def complete(self, messages: list[Message]) -> InvestigationDecision:
        """Return the next structured investigation decision for a conversation.

        Args:
            messages: The full conversation history so far.

        Returns:
            An ``InvestigationDecision``, which either requests a specialist or
            emits a final ``InvestigationOutput``.
        """
        raise NotImplementedError


class MalformedInvestigationResponseError(Exception):
    """Raised when a model response cannot be parsed into a valid decision."""


class FakeInvestigationLLM(InvestigationLLMProvider):
    """A scriptable, deterministic fake investigation model for tests.

    Args:
        script: An iterable of items returned one per ``complete`` call. Each
            item may be an ``InvestigationDecision``, an ``InvestigationOutput``
            (wrapped as a final decision), a raw JSON ``str`` (parsed lazily so
            malformed responses are exercised by the loop, not at construction),
            or ``None`` (recorded as a malformed response).
        auto_repeat_last: If True, the last scripted decision repeats once the
            script is exhausted.
        record: If True, record each call's messages on ``self.calls``.
    """

    def __init__(
        self,
        script: list[InvestigationDecision | InvestigationOutput | str | None],
        *,
        auto_repeat_last: bool = False,
        record: bool = False,
    ) -> None:
        self._script = list(script)
        self._auto_repeat_last = auto_repeat_last
        self._pointer = 0
        self._record = record
        self.calls: list[list[Message]] = []
        self.message_count = 0

    def _resolve(
        self, item: InvestigationDecision | InvestigationOutput | str | None
    ) -> InvestigationDecision:
        if isinstance(item, InvestigationDecision):
            return item
        if isinstance(item, InvestigationOutput):
            return InvestigationDecision(result=item)
        if isinstance(item, str):
            return parse_investigation_decision(item)
        raise MalformedInvestigationResponseError("FakeInvestigationLLM returned empty response")

    def complete(self, messages: list[Message]) -> InvestigationDecision:
        if self._record:
            self.calls.append(list(messages))
        self.message_count = len(messages)

        if self._pointer < len(self._script):
            item = self._script[self._pointer]
            self._pointer += 1
            return self._resolve(item)

        if self._script and self._auto_repeat_last:
            return self._resolve(self._script[-1])

        raise MalformedInvestigationResponseError("FakeInvestigationLLM script exhausted")


def parse_investigation_decision(raw: str) -> InvestigationDecision:
    """Parse raw model text into an ``InvestigationDecision``.

    Accepts a JSON object matching ``InvestigationDecision``, or a bare JSON
    object of an ``InvestigationOutput`` (wrapped as a final decision). Invalid
    JSON or structure raises :class:`MalformedInvestigationResponseError` so the
    loop can treat it as a controlled failure.
    """
    text = raw.strip()
    if not text:
        raise MalformedInvestigationResponseError("Empty LLM response")

    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MalformedInvestigationResponseError(
            f"LLM response is not valid JSON: {exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise MalformedInvestigationResponseError("LLM response must be a JSON object")

    if "specialist_request" not in data and "result" not in data and any(
        key in data for key in ("relationships", "attack_paths", "root_cause_candidates")
    ):
        data = {"result": data}

    try:
        return InvestigationDecision.model_validate(data)
    except ValidationError as exc:
        raise MalformedInvestigationResponseError(
            f"LLM response failed validation: {exc.errors()}"
        ) from exc
