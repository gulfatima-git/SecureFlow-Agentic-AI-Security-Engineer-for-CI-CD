"""Data models for LLM-based security analysis.

This module defines the structured output model used by LLM-driven agents.
It intentionally mirrors the concepts in ``SecurityFinding`` but is a distinct
type because an LLM assessment and a deterministic tool finding represent
different things:

* ``SecurityFinding`` is produced by deterministic tools (Semgrep, Bandit,
  dependency analysis, CI/CD analysis). Its confidence is a categorical
  enum derived from deterministic signals.
* ``CodeFinding`` is the structured output of an LLM agent reasoning over
  evidence. Its confidence is a numeric degree of belief in the range 0-1.

Keeping these separate avoids overloading the deterministic model with
probabilistic semantics while still reusing the shared ``Severity`` enum.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator, model_validator

from src.models.security_finding import Severity


class CodeFinding(BaseModel):
    """A single structured security finding produced by an LLM agent."""

    finding_id: str = Field(min_length=1)
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    file: str = ""
    line: int = Field(default=0, ge=0)
    description: str = ""
    evidence: list[str] = Field(default_factory=list)

    @field_validator("confidence", mode="before")
    @classmethod
    def _coerce_confidence(cls, value: object) -> object:
        # Allow numeric strings ("0.87") and ints to be coerced to float.
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                return value
        return value

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, value: object) -> object:
        # Accept both enum members and strings (case-insensitive). Map the
        # LLM-friendly labels high/medium/low onto the shared Severity values
        # (error/warning/info) so downstream consumers share one vocabulary.
        mapping = {
            "high": Severity.ERROR,
            "medium": Severity.WARNING,
            "low": Severity.INFO,
            "error": Severity.ERROR,
            "warning": Severity.WARNING,
            "info": Severity.INFO,
            "unknown": Severity.UNKNOWN,
        }
        if isinstance(value, str):
            lowered = value.strip().lower()
            matched = mapping.get(lowered)
            if matched is not None:
                return matched
        return value

    @model_validator(mode="after")
    def _line_ge_one_when_file_set(self) -> CodeFinding:
        # A finding with a target file should usually carry a line, but 0 is
        # acceptable for file-level or diff-level findings. Leave as-is.
        return self


class ToolCall(BaseModel):
    """A tool invocation requested by an LLM agent.

    The agent requests the tool; the application executes it.
    """

    name: str
    arguments: dict[str, str] = Field(default_factory=dict)


class ToolResult(BaseModel):
    """The structured result of an application-executed tool call."""

    name: str
    ok: bool = True
    error: str = ""
    content: str = ""


class AgentDecision(BaseModel):
    """The structured decision returned by an LLM in each loop iteration.

    Exactly one of ``tool_call`` or ``finding`` is normally populated.
    """

    reasoning: str = ""
    tool_call: ToolCall | None = None
    finding: CodeFinding | None = None

    @model_validator(mode="after")
    def _at_most_one_destination(self) -> AgentDecision:
        if self.tool_call is not None and self.finding is not None:
            raise ValueError("AgentDecision cannot have both tool_call and finding")
        return self


class CodeAgentResult(BaseModel):
    """The final output of the Code Security Agent."""

    finding: CodeFinding
    tool_calls_used: int = 0
    iterations_used: int = 0
    timed_out: bool = False
