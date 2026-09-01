"""Remediation Agent package (Step 20).

The Remediation Agent is downstream of the Risk Agent. It receives the final
investigation/risk context (an :class:`~src.investigation.models.InvestigationResult`
and an optional :class:`~src.risk.models.RiskAssessment`) and produces a
structured :class:`~src.remediation.models.RemediationPlan` — a *proposal only*.

The agent NEVER modifies the repository, writes patches, commits, pushes,
creates pull requests, executes shell commands, executes generated code, or
deploys anything. A future patch/application workflow must require explicit
human approval and is deliberately out of scope here.

Exposed surface (all pure in-process, offline-friendly):

* :class:`RemediationAgent` — the single-call, grounding remediation agent.
* :class:`RemediationLLMProvider` / :class:`FakeRemediationLLM` — LLM abstraction
  and deterministic test fake.
* :mod:`src.remediation.models` — the remediation domain models
  (``RemediationPlan``, ``AffectedFile``, ``CodeChange``, ``TestToAdd``,
  ``ConfigChange``, ``ValidationStep``, ``RemediationEvidence``).

The remediation package performs no shell, subprocess, network, arbitrary-code,
or repository-write execution: it reasons over investigation/risk output
in-process and only the application performs grounding/validation.
"""

from __future__ import annotations

from src.remediation.agent import RemediationAgent
from src.remediation.llm import (
    FakeRemediationLLM,
    ParseRemediationPlanError,
    RemediationLLMProvider,
    parse_remediation_plan,
)
from src.remediation.models import (
    AffectedFile,
    ChangeKind,
    CodeChange,
    ConfigChange,
    RemediationEvidence,
    RemediationPlan,
    RemediationStats,
    RemediationStatus,
    TestToAdd,
    ValidationKind,
    ValidationStep,
)

__all__ = [
    "AffectedFile",
    "ChangeKind",
    "CodeChange",
    "ConfigChange",
    "FakeRemediationLLM",
    "ParseRemediationPlanError",
    "RemediationAgent",
    "RemediationEvidence",
    "RemediationLLMProvider",
    "RemediationPlan",
    "RemediationStats",
    "RemediationStatus",
    "TestToAdd",
    "ValidationKind",
    "ValidationStep",
    "parse_remediation_plan",
]