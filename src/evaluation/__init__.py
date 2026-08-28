"""Step 12 evaluation package.

Evaluates the existing :class:`CodeSecurityAgent` against controlled,
intentionally vulnerable fixtures, separating deterministic protocol tests
(from a ``FakeLLM``) from real-LLM evaluation of detection and hallucination
behaviour (documented; run via :mod:`src.evaluation.run` when a provider is
available).
"""

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

__all__ = [
    "ALL_CASE_NAMES",
    "EVAL_CASES",
    "EvaluationError",
    "EvaluationResult",
    "GroundTruth",
    "build_context",
    "collect_corpus",
    "collect_tool_output",
    "combined_finding_text",
    "detected_target",
    "is_evidence_grounded",
    "is_hallucination",
    "is_localized",
    "is_severity_ok",
    "optional_tool_output",
    "run_evaluation",
    "score_case",
]
