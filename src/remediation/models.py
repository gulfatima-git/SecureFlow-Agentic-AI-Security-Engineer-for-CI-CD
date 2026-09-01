"""Data models for the SecureFlow Remediation Agent (Step 20).

Step 20 builds the Remediation Agent: the component that is downstream of the
Risk Agent. It receives the final investigation/risk context and produces a
structured ``RemediationPlan`` containing the root cause, a recommended fix,
proposed code changes, tests to add, configuration changes, affected files, and
validation steps.

The Remediation Agent produces a *proposal only*. It NEVER modifies repository
files, writes patches into the repository, commits, pushes, creates pull
requests, executes shell commands, executes generated code, or deploys
anything. Any future patch/application workflow must require explicit human
approval, and is deliberately out of scope for this step.

This module defines the remediation domain's structured contract:

* ``RemediationStatus`` — how the remediation planning run ended.
* ``ChangeKind`` — the (small) taxonomy of proposed changes.
* ``AffectedFile`` — a structured affected file, with a ``verified`` flag set by
  the application indicating whether the path is known from the investigation.
* ``CodeChange`` — a single proposed code change (text/snippet, never applied).
* ``TestToAdd`` — a single proposed test.
* ``ConfigChange`` — a single proposed configuration change.
* ``ValidationStep`` — a single advisory validation step (never executed).
* ``RemediationEvidence`` — an evidence entry that distinguishes *observed
  evidence* from *recommended interpretation* and references existing findings.
* ``ValidationKind`` — the coarse validator category for an advisory step.
* ``RemediationStats`` — bounded-execution statistics.
* ``RemediationPlan`` — the complete, application-assembled output.

Trust model: the LLM produces the *analytical remediation reasoning* (root
cause, recommended fix, proposed changes, tests, configuration, validation
steps, evidence, confidence) while the application computes the grounding
bookkeeping (remediation id, investigation id, risk-assessment id, validated
finding ids, verified affected files, bounding of lists) and enforces the safety
boundary. No proposed change is ever executed. All investigation/risk content is
untrusted data — it is reasoned over but never executed and never treated as an
instruction.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from src.models.finding import EvidenceKind
from src.risk.models import RiskSeverity


class RemediationStatus(StrEnum):
    """How the remediation-planning run ended."""

    COMPLETED = "completed"
    FAILED = "failed"
    TERMINATED = "terminated"


class ChangeKind(StrEnum):
    """Small taxonomy of proposed changes.

    A proposed change is always advisory text/snippet content — it is never
    applied by the Remediation Agent.
    """

    CODE = "code"
    DEPENDENCY = "dependency"
    CONFIG = "config"
    TEST = "test"
    DOCUMENTATION = "documentation"


class ValidationKind(StrEnum):
    """Coarse category for an advisory validation step.

    Validation steps describe what a human or a future CI pipeline SHOULD do to
    confirm the remediation; the Remediation Agent never executes them.
    """

    BUILD = "build"
    TEST = "test"
    LINT = "lint"
    SCAN = "scan"
    MANUAL = "manual"


class AffectedFile(BaseModel):
    """A structured affected file named in the remediation plan.

    ``path`` is a repository-relative path string. ``verified`` is set by the
    application: True when the path is known from the investigation findings
    (``file``/``affected_files``), False otherwise. An unverified file is NOT
    automatically treated as a real repository file — it is carried as advisory
    text only.
    """

    path: str = ""
    change_type: str = "modify"
    reason: str = ""
    finding_id: str | None = None
    verified: bool = False


class CodeChange(BaseModel):
    """A single proposed code change.

    ``snippet`` holds the proposed change as advisory text (e.g. a before/after
    sketch). It is never written to the repository. ``change_kind`` classifies
    the change; ``finding_id`` links it back to an existing finding when
    applicable.
    """

    file: str = ""
    change_kind: ChangeKind = ChangeKind.CODE
    description: str = ""
    snippet: str = ""
    finding_id: str | None = None


class TestToAdd(BaseModel):
    """A single proposed test to add.

    ``file`` is the proposed test location (advisory); the agent never creates
    the file. ``kind`` is the coarse test category.

    The ``__test__ = False`` marker prevents pytest's ``Test*`` collector from
    treating this model (whose name collides with pytest's test class pattern)
    as a test suite.
    """

    __test__ = False

    file: str = ""
    description: str = ""
    kind: str = "unit"
    finding_id: str | None = None


class ConfigChange(BaseModel):
    """A single proposed configuration change.

    ``file``/``component``/``current``/``proposed`` describe the change in
    advisory text. The agent never edits configuration.
    """

    file: str = ""
    component: str = ""
    current: str = ""
    proposed: str = ""
    finding_id: str | None = None


class ValidationStep(BaseModel):
    """A single advisory validation step.

    ``description`` describes what should be done to confirm the remediation.
    ``kind`` is the coarse validator category. The Remediation Agent never
    executes validation — this is a description a human or a future CI pipeline
    may act on.
    """

    description: str = ""
    kind: ValidationKind = ValidationKind.MANUAL


class RemediationEvidence(BaseModel):
    """A single evidence entry supporting a remediation recommendation.

    ``kind`` distinguishes *observed evidence* (what tools/specialists
    deterministically reported) from *recommended interpretation* (the agent's
    own reasoning). ``finding_id``/``attack_path_id`` link the entry to existing
    investigation data when applicable. The application reclassifies entries that
    reference non-existent findings as interpretation so the model's assertions
    are never automatically treated as observed evidence.
    """

    kind: EvidenceKind = EvidenceKind.OBSERVED
    content: str = ""
    finding_id: str | None = None
    attack_path_id: str | None = None


class RemediationStats(BaseModel):
    """Bounded-execution statistics for a remediation plan."""

    iterations_used: int = 0
    max_iterations: int = 1
    findings_cited: int = 0
    findings_rejected: int = 0
    code_changes: int = 0
    tests_to_add: int = 0
    config_changes: int = 0
    affected_files: int = 0
    evidence_items: int = 0
    max_code_changes: int = 0
    max_tests: int = 0
    max_config_changes: int = 0
    max_affected_files: int = 0
    max_evidence_items: int = 0
    max_validation_steps: int = 0


class RemediationPlan(BaseModel):
    """The complete, application-assembled output of the Remediation Agent.

    A **proposal** only: no field here is applied to the repository. ``severity``
    carries the contextual risk severity from the supplied ``RiskAssessment``
    (informational context). ``confidence`` is the agent's confidence in the
    remediation *recommendation* (how likely the proposed fix addresses the root
    cause), NOT exploitability, scanner certainty, or the probability the
    vulnerability exists.

    ``completed`` records whether a valid plan was produced (True) or an error
    occurred (False); ``termination_reason`` explains non-completion.
    """

    remediation_id: str = Field(min_length=1)
    investigation_id: str = ""
    risk_assessment_id: str = ""
    root_cause: str = ""
    recommended_fix: str = ""
    proposed_code_changes: list[CodeChange] = Field(default_factory=list)
    tests_to_add: list[TestToAdd] = Field(default_factory=list)
    configuration_changes: list[ConfigChange] = Field(default_factory=list)
    affected_files: list[AffectedFile] = Field(default_factory=list)
    validation_steps: list[ValidationStep] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    severity: RiskSeverity | None = None
    evidence: list[RemediationEvidence] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata: dict[str, str] = Field(default_factory=dict)
    status: RemediationStatus = RemediationStatus.COMPLETED
    completed: bool = True
    termination_reason: str = ""
    stats: RemediationStats = Field(default_factory=RemediationStats)