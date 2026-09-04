"""Step 25 adversarial benchmark — evaluation-result representation.

A structured, provider-independent record of one system's response to one
benchmark case. It captures everything needed by the deterministic scoring
layer (:mod:`src.evaluation.adversarial_scoring`) without coupling to any LLM
provider, agent wiring, or reasoning implementation.

Repository content stays untrusted data: recording a malicious instruction does
not execute it, and these records never perform shell/network actions.
"""

from __future__ import annotations

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

from src.evaluation.prompt_injection import (
    OUTCOME_REPORT_LEGITIMATE_FINDING,
    OUTCOME_REPORT_NO_FINDING,
)

# Sentinel for a case where the system produced no analysable security
# conclusion (e.g. it terminated or errored before concluding).
OUTCOME_NO_CONCLUSION = "no_conclusion"

VALID_OUTCOMES: frozenset[str] = frozenset(
    {
        OUTCOME_REPORT_LEGITIMATE_FINDING,
        OUTCOME_REPORT_NO_FINDING,
        OUTCOME_NO_CONCLUSION,
    }
)


class AdversarialResponse(BaseModel):
    """A single system response to a single adversarial benchmark case.

    Attributes:
        case_id: Benchmark case id (a Step 24 case id for this benchmark).
        system_name: Identifier of the system/baseline (Traditional Tools,
            LLM Baseline, SecureFlow, or any deterministic mock used in tests).
        is_adversarial: True when this is the adversarial (injected) variant;
            False for a clean control response.
        expected_security_outcome: The benchmark's expected outcome for this
            case (``report_legitimate_finding`` or ``report_no_finding``).
        observed_security_outcome: The system's actual conclusion. May be
            ``OUTCOME_NO_CONCLUSION`` when no conclusion was reached.
        injection_followed: True if the system acted on the malicious
            repository instruction (attack succeeded). Must be False on clean
            controls and may not be True together with ``injection_rejected``.
        injection_rejected: True if the system treated the malicious content as
            untrusted data and did not act on it. Must be False on clean
            controls and mutually exclusive with ``injection_followed``.
        evidence_expected: The legitimate evidence the benchmark expects the
            system to identify (derived from the case's security artifact).
        evidence_identified: The legitimate evidence the system actually
            surfaced.
        notes: Free-text reasoning/metadata for auditing.
    """

    model_config = ConfigDict(frozen=True)

    case_id: str
    system_name: str
    is_adversarial: bool
    expected_security_outcome: str
    observed_security_outcome: str = OUTCOME_NO_CONCLUSION
    injection_followed: bool = False
    injection_rejected: bool = False
    evidence_expected: list[str] = Field(default_factory=list)
    evidence_identified: list[str] = Field(default_factory=list)
    notes: str = ""

    @field_validator("observed_security_outcome", "expected_security_outcome")
    @classmethod
    def _validate_outcome(cls, value: str) -> str:
        if value not in VALID_OUTCOMES:
            raise ValueError(f"invalid security outcome: {value!r}")
        return value

    @field_validator("injection_rejected")
    @classmethod
    def _validate_rejection(cls, value: bool, info: ValidationInfo) -> bool:
        followed = info.data.get("injection_followed", False)
        if followed and value:
            raise ValueError(
                "injection_followed and injection_rejected cannot both be True"
            )
        return value

    @model_validator(mode="after")
    def _validate_clean_controls(self) -> AdversarialResponse:
        # A clean control has no injection to follow or reject.
        if not self.is_adversarial and (
            self.injection_followed or self.injection_rejected
        ):
            raise ValueError(
                "clean controls must not mark injection as followed or rejected"
            )
        return self

    @property
    def has_conclusion(self) -> bool:
        return self.observed_security_outcome != OUTCOME_NO_CONCLUSION

    @property
    def correct_conclusion(self) -> bool:
        return (
            self.has_conclusion
            and self.observed_security_outcome
            == self.expected_security_outcome
        )

    @property
    def false_conclusion(self) -> bool:
        return (
            self.has_conclusion
            and self.observed_security_outcome
            != self.expected_security_outcome
        )

    @property
    def evidence_preserved(self) -> bool:
        """True when every expected legitimate evidence entry was identified."""
        if not self.evidence_expected:
            return bool(self.evidence_identified)
        return set(self.evidence_expected).issubset(set(self.evidence_identified))
