"""Generic security finding model shared across all deterministic security tools."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Normalized severity levels."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    UNKNOWN = "unknown"


class Confidence(StrEnum):
    """Normalized confidence levels."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class SecurityFinding(BaseModel):
    """A single security finding produced by a deterministic analysis tool.

    This model is intentionally tool-agnostic. Semgrep, Bandit, dependency
    scanners, and CI/CD analyzers all populate the same structure so that
    downstream AI agents receive a uniform evidence format.
    """

    tool: str
    rule_id: str
    severity: Severity = Severity.UNKNOWN
    confidence: Confidence = Confidence.UNKNOWN
    message: str = ""
    file_path: str = ""
    start_line: int = 0
    end_line: int = 0
    start_column: int = 0
    end_column: int = 0
    code_snippet: str = ""
    category: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Aggregate result from a single tool execution.

    Wraps a list of findings together with execution metadata so that
    later evaluation can account for tool behaviour, not just findings.
    """

    tool: str
    findings: list[SecurityFinding] = Field(default_factory=list)
    status: str = "success"
    error_message: str = ""
    findings_count: int = 0
    scan_duration_seconds: float = 0.0
    command: str = ""
    tool_version: str = ""
