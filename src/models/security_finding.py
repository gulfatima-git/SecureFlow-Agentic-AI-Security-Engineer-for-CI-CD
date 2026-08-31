"""Deterministic tool-evidence model shared across all security tools.

Step 15 renamed this model from ``SecurityFinding`` to ``ToolFinding`` so that
the name ``SecurityFinding`` could be reclaimed by the canonical cross-agent
finding (see ``src/models/code_finding.py``). A backward-compatible alias is
kept so existing tool-layer code (Steps 7–10) and its tests continue to work
unchanged.
"""

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


class ToolFinding(BaseModel):
    """A single security finding produced by a deterministic analysis tool.

    This model is intentionally tool-agnostic. Semgrep, Bandit, dependency
    scanners, and CI/CD analyzers all populate the same structure so that
    downstream AI agents receive a uniform evidence format.

    This is the deterministic *tool-evidence* record. The canonical cross-agent
    ``SecurityFinding`` (Step 15) is a distinct, richer model produced by
    specialized agents; agents may aggregate ``ToolFinding`` evidence into it.
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

    # Dependency-analysis fields (populated by dependency analyzer, optional for other tools).
    ecosystem: str = ""
    package_name: str = ""
    declared_version: str = ""
    resolved_version: str = ""


# Backward-compatible alias: Steps 7–10 tool layers and tests still refer to
# this model as ``SecurityFinding``. New code should use ``ToolFinding``.
SecurityFinding = ToolFinding


class ScanResult(BaseModel):
    """Aggregate result from a single tool execution.

    Wraps a list of findings together with execution metadata so that
    later evaluation can account for tool behaviour, not just findings.
    """

    tool: str
    findings: list[ToolFinding] = Field(default_factory=list)
    status: str = "success"
    error_message: str = ""
    findings_count: int = 0
    scan_duration_seconds: float = 0.0
    command: str = ""
    tool_version: str = ""
