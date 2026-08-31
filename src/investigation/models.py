"""Data models for the SecureFlow Investigation Agent (Step 17).

Step 17 builds the Investigation Agent, the first component that performs
actual agent collaboration. It receives the canonical ``SecurityFinding``
objects produced by the Code, Dependency, and CI/CD agents, determines whether
apparently separate findings are related, and — when the existing findings are
insufficient — requests additional evidence from specialist agents through an
application-controlled collaboration interface.

This module defines the investigation domain's structured contract:

* ``RelationshipType`` — the (deliberately small) taxonomy of relationships.
* ``FindingRelationship`` — a single, evidence-supported link between findings.
* ``AttackPath`` — an ordered chain of evidence-supported steps.
* ``RootCauseCandidate`` — a candidate underlying cause spanning findings.
* ``InvestigationRequest`` — a structured request to a specialist agent.
* ``SpecialistResponse`` — the structured response of a specialist capability.
* ``InvestigationOutput`` — the LLM-produced analytical content (relationships,
  attack paths, root causes, evidence, confidence).
* ``InvestigationDecision`` — the LLM's per-step decision (either request more
  specialist evidence or emit a final ``InvestigationOutput``).
* ``DelegationStep`` — a single, traceable request/response pairing with the
  reasoning that produced it (Step 18).
* ``InvestigationContext`` — the investigation agent's explicit, in-progress
  state: original findings, prior delegation steps, accumulated evidence and
  reasoning history (Step 18).
* ``InvestigationResult`` — the complete, application-assembled output.

Per the project's architecture principle, the LLM produces the *analysis*
(relationships, attack paths, root causes, supporting evidence) while the
application computes the bookkeeping (investigation id, repository identity,
input finding ids, recorded requests/responses, completion state, termination
reason, and bounded-execution statistics).

Step 18 extends Step 17 so that the investigator conducts a *sequential,
dependent* delegated investigation: a later specialist request may depend on an
earlier specialist response. Traceability is explicit: each request is paired
with its response and the reasoning that produced it in a :class:`DelegationStep`,
and the running :class:`InvestigationContext` is passed to every subsequent LLM
decision so that earlier responses are available to later reasoning.

All finding-derived and evidence content is untrusted data — it is validated for
shape but never executed and never treated as an instruction.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, model_validator

from src.models.finding import EvidenceItem, SecurityFinding


class RelationshipType(StrEnum):
    """Relationship taxonomy used to link findings.

    Deliberately small: it must be possible to ground every relationship type
    in concrete evidence without over-engineering the taxonomy.
    """

    SHARED_COMPONENT = "shared_component"
    SHARED_DEPENDENCY = "shared_dependency"
    ENABLES = "enables"
    DEPENDS_ON = "depends_on"
    AMPLIFIES = "amplifies"
    ATTACK_PATH = "attack_path"
    UNRELATED = "unrelated"
    UNKNOWN = "unknown"


class FindingRelationship(BaseModel):
    """A single, evidence-supported relationship between two or more findings.

    ``evidence`` references observed evidence / specialist responses that
    support the relationship. A relationship must never be asserted merely
    because two findings exist.
    """

    relationship_id: str = Field(min_length=1)
    finding_ids: list[str]
    relationship_type: RelationshipType
    explanation: str = ""
    evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class AttackPath(BaseModel):
    """An ordered, evidence-supported attack path across findings.

    ``ordered_steps`` references existing finding ids or explicit evidence
    strings. Steps must correspond to real findings/evidence — never invented
    vulnerabilities.
    """

    attack_path_id: str = Field(min_length=1)
    finding_ids: list[str]
    ordered_steps: list[str]
    explanation: str = ""
    evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class RootCauseCandidate(BaseModel):
    """A candidate underlying cause shared by one or more findings."""

    candidate_id: str = Field(min_length=1)
    finding_ids: list[str]
    component: str = ""
    explanation: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class InvestigationRequest(BaseModel):
    """A structured request from the Investigation Agent to a specialist.

    ``target_agent`` and ``request_type`` are free strings that MUST be
    validated against an application-controlled allow-list by the collaboration
    layer before any specialist capability is invoked. Arbitrary tool names and
    arbitrary Python execution are never permitted through this interface.
    """

    request_id: str = Field(min_length=1)
    target_agent: str
    request_type: str
    reason: str = ""
    context_finding_ids: list[str] = Field(default_factory=list)
    query: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)


class SpecialistResponse(BaseModel):
    """The structured response of a specialist capability.

    On failure ``success`` is False and ``failure_reason`` carries the explicit
    reason; no fabricated evidence is ever returned on failure.
    """

    request_id: str = Field(min_length=1)
    agent: str
    success: bool = True
    evidence: list[EvidenceItem] = Field(default_factory=list)
    related_finding_ids: list[str] = Field(default_factory=list)
    explanation: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)
    failure_reason: str = ""


class DelegationStep(BaseModel):
    """A single, traceable delegation: request paired with its response.

    ``step_index`` is the zero-based position in the investigation. ``reasoning``
    is the investigator's reasoning that led to this delegation, so a reviewer
    can follow: request #N -> response #N -> (reasoning) -> request #N+1 -> ...
    """

    step_index: int = Field(ge=0)
    reasoning: str = ""
    request: InvestigationRequest
    response: SpecialistResponse


class InvestigationContext(BaseModel):
    """The investigation agent's explicit, in-progress state (Step 18).

    Maintained by the application across the whole investigation and rendered to
    the LLM on every iteration so that a later decision structurally receives all
    earlier findings, delegation steps, and accumulated evidence. It is also
    exposed on the final :class:`InvestigationResult` for traceability.

    ``accumulated_evidence`` collects the *observed* specialist evidence obtained
    through delegation. ``reasoning_history`` preserves each LLM decision's
    reasoning in order.
    """

    findings: list[SecurityFinding] = Field(default_factory=list)
    delegation_steps: list[DelegationStep] = Field(default_factory=list)
    accumulated_evidence: list[EvidenceItem] = Field(default_factory=list)
    reasoning_history: list[str] = Field(default_factory=list)


class InvestigationOutput(BaseModel):
    """The LLM-produced analytical content of a completed investigation.

    Only analytical content lives here; application bookkeeping is added when
    the full ``InvestigationResult`` is assembled.
    """

    relationships: list[FindingRelationship] = Field(default_factory=list)
    attack_paths: list[AttackPath] = Field(default_factory=list)
    root_cause_candidates: list[RootCauseCandidate] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class InvestigationDecision(BaseModel):
    """A single step of the Investigation Agent.

    Exactly one of ``specialist_request`` or ``result`` is normally populated:
    the agent either requests additional specialist evidence or emits its final
    ``InvestigationOutput``.
    """

    reasoning: str = ""
    specialist_request: InvestigationRequest | None = None
    result: InvestigationOutput | None = None

    @model_validator(mode="after")
    def _at_most_one_destination(self) -> InvestigationDecision:
        if self.specialist_request is not None and self.result is not None:
            raise ValueError(
                "InvestigationDecision cannot have both specialist_request and result"
            )
        return self


class InvestigationStatus(StrEnum):
    """How the investigation ended."""

    COMPLETED = "completed"
    TERMINATED = "terminated"
    FAILED = "failed"


class InvestigationStats(BaseModel):
    """Bounded-execution statistics for an investigation."""

    iterations_used: int = 0
    specialist_requests_used: int = 0
    findings_processed: int = 0
    relationships: int = 0
    attack_paths: int = 0
    max_iterations: int = 0
    max_specialist_requests: int = 0
    max_findings: int = 0
    max_evidence_items: int = 0


class InvestigationResult(BaseModel):
    """The complete output of an investigation.

    ``completed`` records whether the agent produced a final analytical output
    (True) or was terminated by a bound/error (False). ``termination_reason``
    explains non-completion. ``specialist_requests`` / ``specialist_responses``
    are the application-recorded collaboration transcript.
    """

    investigation_id: str
    repository_name: str
    input_finding_ids: list[str]
    status: InvestigationStatus = InvestigationStatus.COMPLETED
    completed: bool = True
    termination_reason: str = ""
    relationships: list[FindingRelationship] = Field(default_factory=list)
    attack_paths: list[AttackPath] = Field(default_factory=list)
    root_cause_candidates: list[RootCauseCandidate] = Field(default_factory=list)
    specialist_requests: list[InvestigationRequest] = Field(default_factory=list)
    specialist_responses: list[SpecialistResponse] = Field(default_factory=list)
    delegation_steps: list[DelegationStep] = Field(default_factory=list)
    context: InvestigationContext | None = None
    evidence: list[EvidenceItem] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    stats: InvestigationStats = Field(default_factory=InvestigationStats)
