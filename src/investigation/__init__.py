"""Investigation Agent package (Steps 17-18).

The Investigation Agent is the first component that performs actual agent
collaboration. It receives the canonical :class:`SecurityFinding` objects from
the specialized agents, determines relationships, and — when needed — requests
additional specialist evidence through the application-controlled
:class:`CollaborationInterface`.

Step 18 extends Step 17 so the investigator conducts a *sequential, dependent
delegated investigation*: a later specialist request may depend on an earlier
specialist response. The agent maintains an explicit :class:`InvestigationContext`
that is rendered to the LLM on every iteration and exposed on the result, and it
records traceable :class:`DelegationStep` object (request + response + reasoning).

Exposed surface (all pure in-process, offline-friendly):

* :class:`InvestigationAgent` — the bounded investigation loop.
* :class:`CollaborationInterface` — validated specialist-collaboration gate.
* :mod:`src.investigation.models` — investigation domain models (including
  :class:`DelegationStep` and :class:`InvestigationContext`).
* :class:`InvestigationLLMProvider` / :class:`FakeInvestigationLLM` — LLM
  abstraction and deterministic test fake.

The investigation package performs no shell, subprocess, network, or
arbitrary-code execution: specialist capabilities are the existing safe tool
layers, invoked and validated in-process.
"""

from __future__ import annotations

from src.investigation.agent import InvestigationAgent
from src.investigation.collaboration import (
    ALLOWED_REQUEST_TYPES,
    CollaborationInterface,
    SpecialistRegistry,
)
from src.investigation.handlers import build_default_registry
from src.investigation.llm import (
    FakeInvestigationLLM,
    InvestigationLLMProvider,
    parse_investigation_decision,
)
from src.investigation.models import DelegationStep, InvestigationContext

__all__ = [
    "ALLOWED_REQUEST_TYPES",
    "CollaborationInterface",
    "DelegationStep",
    "FakeInvestigationLLM",
    "InvestigationAgent",
    "InvestigationContext",
    "InvestigationLLMProvider",
    "SpecialistRegistry",
    "build_default_registry",
    "parse_investigation_decision",
]
