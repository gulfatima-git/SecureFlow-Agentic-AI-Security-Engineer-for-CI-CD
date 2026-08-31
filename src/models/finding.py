"""Canonical, cross-agent security finding model (Step 15).

Step 15 standardizes the output contract of the specialized agents so that a
finding produced by ANY agent can be parsed by ANY other downstream component
(orchestrator, investigation/risk/remediation agents) without knowing which
specialized agent produced it.

This module defines the single canonical representation that all three
specialized agents produce:

* ``SecurityFinding`` — the canonical, cross-agent finding.
* ``AgentName`` — the constrained set of producing agents.
* ``FindingCategory`` — the standardized security category (spans all agents).
* ``EvidenceItem`` — structured evidence that preserves the distinction
  between *observed evidence* and *agent interpretation*.

Relationship to the other finding models:

* ``src.models.security_finding.ToolFinding`` (renamed from ``SecurityFinding``)
  is the deterministic *tool-evidence* record produced by Semgrep, Bandit, the
  dependency analyzer, and the CI/CD analyzer. It is the raw input an agent
  reasons over.
* ``src.models.code_finding.CodeFinding`` is the LLM agent's *raw structured
  output* (what a provider emits). It is intentionally minimal and stays
  unchanged so Steps 11–14 and evaluation keep working.
* ``SecurityFinding`` (here) is the canonical cross-agent model. It carries
  everything ``CodeFinding`` has plus ``agent``, ``category``, structured
  evidence, multiple affected files, a recommendation, and extensible metadata.

The one-directional, deterministic conversion ``CodeFinding → SecurityFinding``
(:meth:`SecurityFinding.from_code_finding`) is the only migration path from the
internal model to the canonical one, keeping the two from drifting apart.

All finding fields and evidence are treated as **untrusted data** — never as
commands. This module performs no execution.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, field_validator

from src.models.code_finding import CodeFinding
from src.models.security_finding import Severity


class AgentName(StrEnum):
    """Constrained set of specialized agents that produce findings."""

    CODE_SECURITY = "code_security"
    DEPENDENCY = "dependency"
    CICD = "cicd"


class FindingCategory(StrEnum):
    """Standardized security category spanning all three agents.

    Each specialized agent maps to one domain category. Finer sub-categories
    are deferred to later investigation/risk steps; these coarse categories
    guarantee every current agent has a valid category.
    """

    CODE = "code"
    DEPENDENCY = "dependency"
    CICD = "cicd"


class EvidenceKind(StrEnum):
    """Whether an evidence entry is observed or an agent interpretation."""

    OBSERVED = "observed"
    INTERPRETATION = "interpretation"


# Prefixes that mark an evidence string as *observed* (from a tool/manifest/
# config/source) rather than the agent's own reasoning. Classification is
# deterministic and case-insensitive; unknown labels are interpretation.
_OBSERVED_PREFIXES = (
    "analyzer:",
    "scanner:",
    "manifest:",
    "config:",
    "source:",
    "tool:",
    "observed:",
    "semgrep:",
    "bandit:",
    "dependency:",
    "cicd-analyzer:",
    "dependency-analyzer:",
)


class EvidenceItem(BaseModel):
    """A single, structured evidence entry.

    ``content`` holds the evidence text. ``kind`` records whether the entry is
    *observed* (deterministic tool/manifest/config/source output) or the
    agent's *interpretation*. ``source`` optionally names the tool/scanner that
    produced an observed entry (e.g. ``semgrep``, ``dependency-analyzer``).
    """

    kind: EvidenceKind = EvidenceKind.OBSERVED
    content: str = ""
    source: str = ""


class SecurityFinding(BaseModel):
    """The canonical, cross-agent security finding.

    This is the single representation passed between agents and, later, to an
    orchestrator/investigation/risk/remediation layer. Its core fields are
    agent-agnostic; agent-specific detail lives in ``metadata``.

    All fields are untrusted data (potentially from repository content). They
    are validated for shape but never executed.
    """

    finding_id: str = Field(min_length=1)
    agent: AgentName
    category: FindingCategory
    severity: Severity = Severity.UNKNOWN
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    affected_files: list[str] = Field(default_factory=list)
    recommendation: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)
    description: str = ""
    file: str = ""
    line: int = Field(default=0, ge=0)

    @field_validator("confidence", mode="before")
    @classmethod
    def _coerce_confidence(cls, value: object) -> object:
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
        # Accept both Severity members and the shared LLM labels
        # high/medium/low, mapped onto error/warning/info.
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
            if lowered in mapping:
                return mapping[lowered]
        return value

    @field_validator("file", "affected_files")
    @classmethod
    def _normalize_repo_relative(cls, value: object) -> object:
        # Paths are repository-relative data. Normalize separators to forward
        # slashes for stability but never resolve/execute anything.
        if isinstance(value, str):
            return value.replace("\\", "/")
        if isinstance(value, list):
            return [v.replace("\\", "/") for v in value if isinstance(v, str)]
        return value

    @classmethod
    def from_code_finding(
        cls,
        finding: CodeFinding,
        *,
        agent: AgentName,
        category: FindingCategory,
        recommendation: str = "",
    ) -> SecurityFinding:
        """Deterministically convert an agent's raw ``CodeFinding`` to canonical form.

        This is the single, one-directional migration from the internal LLM
        output to the canonical cross-agent model. ``agent`` and ``category``
        are stamped by the producing agent (never taken from the model), and
        the observed/interpretation split is derived deterministically from the
        evidence labels.

        Args:
            finding: The ``CodeFinding`` produced by a specialized agent.
            agent: The constrained producing-agent name.
            category: The standardized security category.
            recommendation: Optional remediation recommendation (default empty;
                agents populate when available).

        Returns:
            A canonical ``SecurityFinding``.
        """
        evidence = [
            EvidenceItem(kind=_classify_evidence(item), content=item)
            for item in finding.evidence
        ]
        affected_files = [finding.file] if finding.file else []
        return cls(
            finding_id=finding.finding_id,
            agent=agent,
            category=category,
            severity=finding.severity,
            confidence=finding.confidence,
            evidence=evidence,
            affected_files=affected_files,
            recommendation=recommendation,
            metadata={},
            description=finding.description,
            file=finding.file,
            line=finding.line,
        )


def _classify_evidence(content: str) -> EvidenceKind:
    """Classify an evidence string as observed or interpretation."""
    lowered = content.strip().lower()
    for prefix in _OBSERVED_PREFIXES:
        if lowered.startswith(prefix):
            return EvidenceKind.OBSERVED
    return EvidenceKind.INTERPRETATION
