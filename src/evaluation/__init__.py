"""Step 12 evaluation package.

Evaluates the existing :class:`CodeSecurityAgent` against controlled,
intentionally vulnerable fixtures, separating deterministic protocol tests
(from a ``FakeLLM``) from real-LLM evaluation of detection and hallucination
behaviour (documented; run via :mod:`src.evaluation.run` when a provider is
available).

Step 24 additionally defines structured prompt-injection benchmark cases
(:mod:`src.evaluation.prompt_injection`) spanning six attack locations
(README, source comments, commit messages, documentation, test files, and
configuration files) so that the LLM baseline, the multi-agent system, and
traditional tooling can later be evaluated against identical untrusted content
for RQ6.

Step 25 builds the reproducible adversarial **evaluation machinery** on top of
those cases: attack categories (:mod:`src.evaluation.adversarial`), a
provider-independent response representation
(:mod:`src.evaluation.adversarial_result`), and deterministic metric/report
functions (:mod:`src.evaluation.adversarial_scoring`). It invokes no LLM and
makes no claim of prompt-injection resistance; running the systems is deferred
to later steps.

Step 26 defines a **vulnerability benchmark with explicit ground truth**
(:mod:`src.evaluation.vulnerability`): seven controlled cases (SQL injection,
command injection, XSS, hardcoded secrets, dependency vulnerabilities, insecure
GitHub Actions, and Docker misconfiguration), each paired with a clean control.
Like Steps 24-25 this is a case-definition layer only; executing the compared
systems against these fixtures is out of scope for Step 26.
"""

from src.evaluation.adversarial import (
    ADVERSARIAL_CASES,
    ALL_ADVERSARIAL_CASES,
    ALL_ATTACK_CATEGORIES,
    ATTACK_CATEGORY_COVERAGE,
    AdversarialCase,
    AttackCategoryCoverage,
)
from src.evaluation.adversarial_result import (
    OUTCOME_NO_CONCLUSION,
    AdversarialResponse,
)
from src.evaluation.adversarial_scoring import (
    AdversarialBenchmarkReport,
    AggregateMetricSet,
    MetricSet,
    attack_success_rate,
    build_report,
    correct_rejection_rate,
    evidence_preservation_rate,
    false_conclusion_rate,
    no_conclusion_rate,
)
from src.evaluation.ground_truth import (
    ALL_CASE_NAMES,
    EVAL_CASES,
    GroundTruth,
)
from src.evaluation.harness import (
    EvaluationError,
    build_context,
    collect_tool_output,
    optional_tool_output,
    run_evaluation,
)
from src.evaluation.prompt_injection import (
    ALL_ATTACK_LOCATIONS,
    ALL_INJECTION_CATEGORIES,
    ALL_PROMPT_INJECTION_CASES,
    PROMPT_INJECTION_CASES,
    PROMPT_INJECTION_COVERAGE,
    PromptInjectionCase,
    PromptInjectionCoverage,
)
from src.evaluation.scoring import (
    EvaluationResult,
    collect_corpus,
    combined_finding_text,
    detected_target,
    is_evidence_grounded,
    is_hallucination,
    is_localized,
    is_severity_ok,
    score_case,
)
from src.evaluation.vulnerability import (
    ALL_VULNERABILITY_CASE_IDS,
    ALL_VULNERABILITY_CASES,
    FAKE_CREDENTIAL_VALUE,
    VULNERABILITY_CASES,
    VULNERABILITY_CATEGORIES,
    VulnerabilityCase,
    VulnerabilityCategory,
    cases_for_category,
    get_vulnerability_case,
)

__all__ = [
    "ADVERSARIAL_CASES",
    "ALL_ADVERSARIAL_CASES",
    "ALL_ATTACK_CATEGORIES",
    "ALL_ATTACK_LOCATIONS",
    "ALL_CASE_NAMES",
    "ALL_INJECTION_CATEGORIES",
    "ALL_PROMPT_INJECTION_CASES",
    "ALL_VULNERABILITY_CASE_IDS",
    "ALL_VULNERABILITY_CASES",
    "ATTACK_CATEGORY_COVERAGE",
    "AdversarialBenchmarkReport",
    "AdversarialCase",
    "AdversarialResponse",
    "AggregateMetricSet",
    "AttackCategoryCoverage",
    "EVAL_CASES",
    "EvaluationError",
    "EvaluationResult",
    "FAKE_CREDENTIAL_VALUE",
    "GroundTruth",
    "MetricSet",
    "OUTCOME_NO_CONCLUSION",
    "PROMPT_INJECTION_CASES",
    "PROMPT_INJECTION_COVERAGE",
    "PromptInjectionCase",
    "PromptInjectionCoverage",
    "VULNERABILITY_CASES",
    "VULNERABILITY_CATEGORIES",
    "VulnerabilityCase",
    "VulnerabilityCategory",
    "attack_success_rate",
    "build_context",
    "build_report",
    "cases_for_category",
    "collect_corpus",
    "collect_tool_output",
    "combined_finding_text",
    "correct_rejection_rate",
    "detected_target",
    "evidence_preservation_rate",
    "false_conclusion_rate",
    "get_vulnerability_case",
    "is_evidence_grounded",
    "is_hallucination",
    "is_localized",
    "is_severity_ok",
    "no_conclusion_rate",
    "optional_tool_output",
    "run_evaluation",
    "score_case",
]
