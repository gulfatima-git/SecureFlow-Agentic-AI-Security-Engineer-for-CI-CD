"""Risk Agent package (Step 19).

The Risk Agent converts an evidence-backed investigation into a structured,
contextual risk assessment. It consumes the :class:`~src.investigation.models.InvestigationResult`
produced by the Investigation Agent and emits a :class:`~src.risk.models.RiskAssessment`
that answers how severe the issue is, how confident we are, how exploitable it is
under the available evidence, which assets are affected, which attack path (if
any) is supported, why that risk was assigned, and what evidence supports it.

The Risk Agent does NOT re-run the specialist agents and does NOT delegate to
specialists. Its input is the completed investigation.

Exposed surface (all pure in-process, offline-friendly):

* :class:`RiskAgent` — the single-call, grounding risk assessment agent.
* :class:`RiskLLMProvider` / :class:`FakeRiskLLM` — LLM abstraction and
  deterministic test fake.
* :mod:`src.risk.models` — the risk domain models (``RiskAssessment``,
  ``RiskSeverity``, ``Exploitability``, ``RiskReasoning``, ``RiskEvidence``,
  ``RiskAsset``, ``RiskAttackPath``).

The risk package performs no shell, subprocess, network, or arbitrary-code
execution: it reasons over investigation output in-process and only the
application performs grounding/validation.
"""

from __future__ import annotations

from src.risk.agent import RiskAgent
from src.risk.llm import (
    FakeRiskLLM,
    ParseRiskAssessmentError,
    RiskLLMProvider,
    parse_risk_assessment,
)
from src.risk.models import (
    Exploitability,
    RiskAssessment,
    RiskAsset,
    RiskAttackPath,
    RiskEvidence,
    RiskReasoning,
    RiskSeverity,
    RiskStats,
)

__all__ = [
    "Exploitability",
    "FakeRiskLLM",
    "ParseRiskAssessmentError",
    "RiskAgent",
    "RiskAssessment",
    "RiskAsset",
    "RiskAttackPath",
    "RiskEvidence",
    "RiskLLMProvider",
    "RiskReasoning",
    "RiskSeverity",
    "RiskStats",
    "parse_risk_assessment",
]