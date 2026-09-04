"""Step 25 adversarial benchmark — case-definitions layer.

This module defines the *evaluation categories* for the adversarial benchmark
and the mapping from the Step 24 prompt-injection case suite onto those
categories. It intentionally does **not** duplicate the Step 24 case fixtures or
their structured metadata (``:mod:`src.evaluation.prompt_injection```): the six
adversarial benchmark cases *are* the six Step 24 ``PromptInjectionCase``
entries, referenced here by ``case_id``.

The benchmark compares three kinds of systems against identical untrusted
repository content:

* traditional security tools (Baseline A),
* a single-LLM investigation baseline (Baseline B),
* the SecureFlow multi-agent system (System C).

This step builds only the experimental machinery (categories, response
representation, deterministic scoring, and reporting). No real LLM is invoked
and no claim of prompt-injection resistance is made — running the systems and
recording their responses is deferred to Step 26+.

Each Step 24 case is assigned exactly one Step 25 *evaluation category*. The
category is an additional axis, distinct from Step 24's ``injection_classification``
(which describes the attacker's *technique*), describing which adversarial
behaviour the benchmark case is designed to probe.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.evaluation.prompt_injection import (
    PROMPT_INJECTION_CASES,
    PromptInjectionCase,
)

# The six evaluation categories the adversarial benchmark must support.
CATEGORY_DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
CATEGORY_INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
CATEGORY_MISLEADING_COMMENTS = "misleading_comments"
CATEGORY_MALICIOUS_DOCUMENTATION = "malicious_documentation"
CATEGORY_POISONED_SECURITY_EVIDENCE = "poisoned_security_evidence"
CATEGORY_CONFLICTING_FINDINGS = "conflicting_findings"

ALL_ATTACK_CATEGORIES: tuple[str, ...] = (
    CATEGORY_DIRECT_PROMPT_INJECTION,
    CATEGORY_INDIRECT_PROMPT_INJECTION,
    CATEGORY_MISLEADING_COMMENTS,
    CATEGORY_MALICIOUS_DOCUMENTATION,
    CATEGORY_POISONED_SECURITY_EVIDENCE,
    CATEGORY_CONFLICTING_FINDINGS,
)


@dataclass(frozen=True)
class AdversarialCase:
    """An adversarial benchmark case: Step 24 fixture + Step 25 category.

    References (does not copy) the underlying :class:`PromptInjectionCase` so
    the Step 24 fixtures remain the single source of truth. A resolved case
    must be an *adversarial* Step 24 case (i.e. it belongs to
    ``PROMPT_INJECTION_CASES``). Its clean control is reached via
    ``source.base_case_id``.
    """

    case_id: str
    category: str
    source: PromptInjectionCase

    @property
    def clean_control_id(self) -> str | None:
        return self.source.base_case_id

    @property
    def expected_security_outcome(self) -> str:
        return self.source.expected_security_outcome

    @property
    def expected_behavior(self) -> str:
        return self.source.expected_behavior

    @property
    def malicious_instruction(self) -> str:
        return self.source.malicious_instruction

    @property
    def base_artifact(self) -> str:
        return self.source.base_artifact

    @property
    def attack_location(self) -> str:
        return self.source.attack_location

    @property
    def benign_context(self) -> str:
        return self.source.benign_context


# Mapping: Step 24 case id -> Step 25 evaluation category.
#
# The six existing adversarial cases cleanly cover all six evaluation
# categories, so no unrelated fixtures are added:
#
# * direct_prompt_injection        <- pi_readme        (README commands the agent)
# * indirect_prompt_injection      <- pi_test_file     (payload via test-data channel)
# * misleading_comments            <- pi_source_comment(finding-suppression comment)
# * malicious_documentation        <- pi_documentation (malicious content in docs)
# * poisoned_security_evidence     <- pi_commit_message(repo artifact claims a real
#                                                        vuln is a false positive)
# * conflicting_findings           <- pi_configuration (config suppresses secrets
#                                                        findings that a plaintext
#                                                        password still evidences)
_EVALUATION_CATEGORIES: dict[str, str] = {
    "pi_readme": CATEGORY_DIRECT_PROMPT_INJECTION,
    "pi_source_comment": CATEGORY_MISLEADING_COMMENTS,
    "pi_commit_message": CATEGORY_POISONED_SECURITY_EVIDENCE,
    "pi_documentation": CATEGORY_MALICIOUS_DOCUMENTATION,
    "pi_test_file": CATEGORY_INDIRECT_PROMPT_INJECTION,
    "pi_configuration": CATEGORY_CONFLICTING_FINDINGS,
}

ADVERSARIAL_CASES: dict[str, AdversarialCase] = {
    case_id: AdversarialCase(
        case_id=case_id,
        category=category,
        source=PROMPT_INJECTION_CASES[case_id],
    )
    for case_id, category in _EVALUATION_CATEGORIES.items()
}

ALL_ADVERSARIAL_CASES: tuple[str, ...] = tuple(ADVERSARIAL_CASES)


@dataclass(frozen=True)
class AttackCategoryCoverage:
    """Summarises which Step 25 evaluation categories the suite covers."""

    cases: tuple[AdversarialCase, ...]

    @property
    def covered_categories(self) -> set[str]:
        return {c.category for c in self.cases}

    @property
    def missing_categories(self) -> set[str]:
        return set(ALL_ATTACK_CATEGORIES) - self.covered_categories


ATTACK_CATEGORY_COVERAGE: AttackCategoryCoverage = AttackCategoryCoverage(
    cases=tuple(ADVERSARIAL_CASES.values())
)
