"""A scriptable fake LLM provider for tests.

This provider requires no API key, network, or external service. It returns
a queue of pre-scripted decisions so tests can exercise the agent loop
deterministically — including tool calls, final findings, and malformed
responses.

Each script item may be:
- an ``AgentDecision`` (returned verbatim),
- a ``CodeFinding`` (wrapped as a final finding decision),
- a raw JSON ``str`` (parsed lazily on each ``complete`` call so malformed
  responses are exercised by the agent loop rather than at construction).
"""

from __future__ import annotations

from src.llm.base import LLMProvider, Message
from src.models.code_finding import AgentDecision, CodeFinding


class FakeLLM(LLMProvider):
    """An in-memory LLM that returns scripted decisions in order.

    Args:
        script: An iterable of items (``AgentDecision``, ``CodeFinding``, or
            raw JSON ``str``) returned one per ``complete`` call.
        auto_repeat_last: If True, the last scripted decision is repeated once
            the script is exhausted.
        record: If True, record each call's messages on ``self.calls``.
    """

    def __init__(
        self,
        script: list[AgentDecision | CodeFinding | str],
        *,
        auto_repeat_last: bool = False,
        record: bool = False,
    ) -> None:
        self._script: list[AgentDecision | CodeFinding | str] = list(script)
        self._auto_repeat_last = auto_repeat_last
        self._pointer = 0
        self._record = record
        self.calls: list[list[Message]] = []
        self.message_count = 0

    def _resolve(self, item: AgentDecision | CodeFinding | str) -> AgentDecision:
        if isinstance(item, str):
            from src.llm.base import parse_decision

            return parse_decision(item)
        if isinstance(item, CodeFinding):
            return AgentDecision(finding=item)
        return item

    def complete(self, messages: list[Message]) -> AgentDecision:
        if self._record:
            self.calls.append(list(messages))
        self.message_count = len(messages)

        if self._pointer < len(self._script):
            item = self._script[self._pointer]
            self._pointer += 1
            return self._resolve(item)

        if self._script and self._auto_repeat_last:
            return self._resolve(self._script[-1])

        from src.llm.base import MalformedLLMResponseError

        raise MalformedLLMResponseError("FakeLLM script exhausted")
