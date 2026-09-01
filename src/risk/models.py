"""Data models for the SecureFlow Risk Agent (Step 19).

Step 19 builds the Risk Agent: the component that consumes the structured result
of the Investigation Agent (an :class:`~src.investigation.models.InvestigationResult`)
and produces an evidence-backed, contextual risk assessment that answers:

* how severe the investigated issue is;
* how confident we are in that severity judgment;
* how exploitable the issue is under the available evidence;
* which affected assets are involved;
* which attack path (if any) supports the judgment;
* why that risk level was assigned; and
* what evidence supports the decision.

The Risk Agent must NOT simply repeat scanner severity labels. It reasons over
the investigation evidence and produces a contextual ``RiskAssessment``.

This module defines the risk domain's structured contract:

* ``RiskSeverity`` — a risk-oriented severity scale (critical/high/medium/low/
  informational/unknown), distinct from the tool-oriented ``Severity``
  (error/warning/info/unknown) and with a documented relationship to it.
* ``Exploitability`` — how exploitable the issue is under the available evidence.
* ``RiskReasoning`` — structured reasoning that distinguishes *observed
  evidence* from *interpretation* from *assumptions*.
* ``RiskEvidence`` — an evidence entry that explicitly references investigation
  evidence / findings.
* ``RiskAsset`` — a structured affected asset/component.
* ``RiskAttackPath`` — an attack-path reference that must be grounded in the
  investigation (never invented) and that is clearly labelled as direct or as
  interpretation when derived.
* ``RiskAssessment`` — the complete, application-assembled output.
* ``RiskStats`` — light bounded-execution statistics.

Trust model: the LLM produces the *analytical interpretation* (severity,
confidence, exploitability, reasoning, affected assets) while the application
computes the grounding bookkeeping (assessment id, investigation id, validated
finding ids, validated attack-path reference, dropped/invalidated evidence) and
enforces the safety boundary. All investigation content is untrusted data — it
is reasoned over but never executed and never treated as instructions.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from src.models.finding import EvidenceKind
from src.models.security_finding import Severity


class RiskSeverity(StrEnum):
    """Contextual risk severity scale.

    The shared tool ``Severity`` (``error``/``warning``/``info``/``unknown``) is
    a deterministic scanner/analyzer label. Risk assessment needs a richer,
    contextual scale that is not tied to a single tool's label, so this enum
    introduces the smallest justified abstraction and documents its relationship
    to the shared ``Severity``.

    Relationship to the tool ``Severity`` (a coarse, non-binding mapping; the
    Risk Agent reasons over evidence and may depart from it):

    * ``CRITICAL`` — not directly represented by a tool label.
    * ``HIGH`` — plausibly maps onto tool ``error``.
    * ``MEDIUM`` — plausibly maps onto tool ``error``/``warning`` boundary.
    * ``LOW`` — plausibly maps onto tool ``warning``/``info``.
    * ``INFORMATIONAL`` — plausibly maps onto tool ``info``.
    * ``UNKNOWN`` — maps onto tool ``unknown``.

    Crucially, risk severity must be *contextual*: an ``ERROR`` finding may be
    ``LOW`` or ``UNKNOWN`` if the vulnerable component is unused/unreachable, and
    the agent must never silently map every ``ERROR`` to ``CRITICAL``.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"

    @classmethod
    def from_tool_severity(cls, severity: Severity) -> RiskSeverity:
        """Coarse, non-binding mapping from a tool ``Severity`` to ``RiskSeverity``.

        This is provided only as a *starting hint* for how a scanner label might
        map onto the risk scale. The Risk Agent must reason over evidence and may
        (and often should) depart from it; it is never an automatic assignment.
        """
        return _TOOL_TO_RISK.get(severity, RiskSeverity.UNKNOWN)


# Coarse, non-binding hint mapping. Never an automatic assignment.
_TOOL_TO_RISK: dict[Severity, RiskSeverity] = {
    Severity.ERROR: RiskSeverity.HIGH,
    Severity.WARNING: RiskSeverity.MEDIUM,
    Severity.INFO: RiskSeverity.LOW,
    Severity.UNKNOWN: RiskSeverity.UNKNOWN,
}


class Exploitability(StrEnum):
    """How exploitable the issue is judged to be under the available evidence.

    Terminology reflects the research methodology: ``possible`` precedes
    ``likely``; ``unlikely``/``not_exploitable`` reflect evidence that the issue
    is hard or impossible to reach; ``unknown`` reflects insufficient evidence.
    """

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    UNLIKELY = "unlikely"
    NOT_EXPLOITABLE = "not_exploitable"
    UNKNOWN = "unknown"


class RiskReasoning(BaseModel):
    """Structured reasoning behind the risk judgment.

    Reasoning must distinguish *observed evidence* (what tools/specialists
    deterministically reported), *interpretation* (the agent's contextual reading
    of that evidence), and *assumptions* (claims that are unsupported by the
    input, which the agent must never present as facts).
    """

    observed: list[str] = Field(default_factory=list)
    interpretation: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)


class RiskEvidence(BaseModel):
    """A single evidence entry supporting the risk assessment.

    ``finding_id`` explicitly ties the evidence to an existing investigation
    finding. ``attack_path_id`` optionally ties it to an existing investigation
    attack path. ``kind`` records whether the entry is observed or interpretation
    (reusing ``EvidenceKind``). Evidence must reference real investigation
    findings/issues; unsupported references are rejected or treated as
    interpretation by the Risk Agent, never silently converted into confidence.
    """

    kind: EvidenceKind = EvidenceKind.OBSERVED
    content: str = ""
    finding_id: str | None = None
    attack_path_id: str | None = None


class RiskAsset(BaseModel):
    """A structured affected asset/component.

    Examples: ``authentication endpoint``, ``package/library``, ``GitHub Actions
    workflow``, ``container runtime``, ``credential``, ``deployment environment``.
    ``kind`` is a coarse classifier of the asset; ``finding_id`` ties it back to
    the underlying finding when applicable.
    """

    name: str = ""
    kind: str = ""
    finding_id: str | None = None


class RiskStats(BaseModel):
    """Light bounded-execution statistics for a risk assessment."""

    evidence_items: int = 0
    findings_cited: int = 0
    findings_rejected: int = 0
    attack_path_rejected: int = 0
    max_evidence_items: int = 0


class RiskAttackPath(BaseModel):
    """An attack-path reference used to support the risk judgment.

    ``attack_path_id`` MUST reference an existing attack path in the
    investigation result; the Risk Agent rejects invented ids. ``steps`` records
    the ordered steps of that path. ``source`` labels whether the path is taken
    directly from the investigation (``investigation``) or is a clearly-labelled
    interpretation the agent derived from it (``interpretation``). The agent never
    invents a new attack path unsupported by investigation evidence.
    """

    attack_path_id: str = Field(min_length=1)
    steps: list[str] = Field(default_factory=list)
    source: str = "investigation"


class RiskAssessment(BaseModel):
    """The complete, application-assembled output of the Risk Agent.

    ``severity``/``exploitability``/``reasoning``/``affected_assets`` are the
    contextual analytical content. ``finding_ids`` and ``attack_path`` are
    application-grounded (only ids that exist in the investigation are retained;
    non-existent references are dropped or invalidated). ``evidence`` references
    investigation findings/evidence. ``confidence`` is the agent's confidence in
    its assessment (0.0-1.0), distinct from exploitability and from scanner
    certainty.

    ``completed`` records whether a valid assessment was produced (True) or an
    error occurred (False); ``termination_reason`` explains non-completion.
    """

    assessment_id: str = Field(min_length=1)
    investigation_id: str = ""
    severity: RiskSeverity = RiskSeverity.UNKNOWN
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    exploitability: Exploitability = Exploitability.UNKNOWN
    affected_assets: list[RiskAsset] = Field(default_factory=list)
    attack_path: RiskAttackPath | None = None
    reasoning: RiskReasoning = Field(default_factory=RiskReasoning)
    evidence: list[RiskEvidence] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)
    completed: bool = True
    termination_reason: str = ""
    stats: RiskStats = Field(default_factory=RiskStats)