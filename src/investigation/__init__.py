"""Investigation Agent package (Step 17).

The Investigation Agent is the first component that performs actual agent
collaboration. It receives the canonical :class:`SecurityFinding` objects from
the specialized agents, determines relationships, and — when needed — requests
additional specialist evidence through the application-controlled
:class:`CollaborationInterface`.

Exposed surface (all pure in-process, offline-friendly):

* :class:`InvestigationAgent` — the bounded investigation loop.
* :class:`CollaborationInterface` — validated specialist-collaboration gate.
* :mod:`src.investigation.models` — investigation domain models.
* :class:`InvestigationLLMProvider` / :class:`FakeInvestigationLLM` — LLM
  abstraction and deterministic test fake.

No ambient AgentType beyond the ``Models`` and ``Core`` that the code agent
already uses is introduced here. The investigation package performs no shell,
subprocess, network, or arbitrary-code execution: specialist capabilities are
the existing safe tool layers, invoked and validated in-process.
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

__all__ = [
    "ALLOWED_REQUEST_TYPES",
    "CollaborationInterface",
    "FakeInvestigationLLM",
    "InvestigationAgent",
    "InvestigationLLMProvider",
    "SpecialistRegistry",
    "build_default_registry",
    "parse_investigation_decision",
]
