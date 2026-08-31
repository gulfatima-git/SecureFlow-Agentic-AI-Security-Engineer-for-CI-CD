"""Data models for the SecureFlow orchestrator (Step 16).

Step 16 builds the orchestrator: the application component that receives a
``RepositoryContext``, routes to the relevant specialized agents, executes only
the selected agents, and aggregates their canonical ``SecurityFinding`` outputs
into a single structured ``OrchestrationResult``.

This module defines the orchestrator's own output contract:

* ``AgentRunStatus`` — the status of a single agent run.
* ``OrchestrationStatus`` — the aggregate status of the whole run.
* ``AgentRunRecord`` — the per-agent result, including whether the agent was
  routed to, its status, the canonical finding it produced (if any), and usage
  metadata.
* ``OrchestrationResult`` — the top-level result combining routing, per-agent
  records, the collected canonical findings, and the bounded-execution limits
  that were applied.

These models only describe output shape. The routing and execution logic lives
in :mod:`src.orchestration.orchestrator`. No execution, subprocess, or network
is performed here.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from src.models.finding import AgentName, SecurityFinding


class AgentRunStatus(StrEnum):
    """Per-agent run status.

    ``NOT_RUN`` covers agents selected by routing but not executed because an
    explicit bound (max agents / max executions) was reached.
    """

    SUCCESS = "success"
    NO_FINDING = "no_finding"
    FAILED = "failed"
    NOT_RUN = "not_run"


class OrchestrationStatus(StrEnum):
    """Aggregate status of an orchestration run."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    EMPTY = "empty"
    FAILED = "failed"


class AgentRunRecord(BaseModel):
    """The result of routing and (optionally) running a single agent.

    ``selected`` records whether routing chose this agent. ``status`` records
    the outcome: an executed agent that produced a finding is ``SUCCESS``; one
    that ran to a controlled termination without a finding is ``NO_FINDING``;
    an unhandled failure is ``FAILED``; and one that was not run because of a
    bound is ``NOT_RUN``. ``note`` carries a human-readable reason.
    """

    agent: AgentName
    selected: bool = True
    status: AgentRunStatus = AgentRunStatus.NOT_RUN
    finding: SecurityFinding | None = None
    note: str = ""
    tool_calls_used: int = 0
    iterations_used: int = 0


class OrchestrationResult(BaseModel):
    """Top-level result of an orchestrator run.

    ``selected_agents`` is the ordered set of agents chosen by routing (before
    any execution bound). ``runs`` holds one ``AgentRunRecord`` per selected
    agent, in execution order. ``findings`` aggregates the canonical
    ``SecurityFinding`` objects produced by the agents that actually ran, in
    execution order. ``status`` summarizes the run and ``limits`` records the
    bounded-execution configuration that was applied.
    """

    repository_name: str = ""
    selected_agents: list[AgentName] = Field(default_factory=list)
    runs: list[AgentRunRecord] = Field(default_factory=list)
    findings: list[SecurityFinding] = Field(default_factory=list)
    status: OrchestrationStatus = OrchestrationStatus.COMPLETED
    agent_order: list[AgentName] = Field(default_factory=list)
    passes_run: int = 0
    limits: dict[str, int] = Field(default_factory=dict)
