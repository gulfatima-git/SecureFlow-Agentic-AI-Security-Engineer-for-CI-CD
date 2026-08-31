# Orchestrator (Step 16)

The orchestrator is the coordination layer of SecureFlow. It receives a
`RepositoryContext` (produced by repository ingestion), routes to the relevant
specialized agents, executes **only** the selected agents, records each agent's
outcome, and aggregates the canonical `SecurityFinding` outputs into a single
structured `OrchestrationResult`.

This step builds the application-controlled orchestrator. It does **not**
implement agent-to-agent delegation, iterative follow-up passes, or separate
investigation/risk/remediation/reporting agents. Those are deferred to later
steps.

## Why an orchestrator

SecureFlow's core hypothesis is that decomposing security investigation into
specialized agents improves quality. Specialization only pays off if a system
can decide *which* agents are relevant to a given repository and run just those
— running every agent against every repository would waste tokens, add latency,
and surface irrelevant findings (the very alert fatigue the project targets).

The orchestrator is the component that:

* selects the relevant agents deterministically from repository contents;
* executes only what was selected, in a stable order;
* bounds execution so a single pull request cannot trigger unbounded work; and
* tolerates individual agent failures without losing the whole run.

## Architecture principle

Per the project's design principle — *LLMs reason over evidence, not replace
the tools that produce it* — the orchestrator **only coordinates**. It:

* does **not** perform vulnerability analysis;
* does **not** move security logic out of the agents;
* does **not** modify agent investigation behavior;
* never executes code, shell, subprocesses, Docker/kubectl/cloud CLIs, or
  network calls.

Routing, ordering, and failure handling are the only responsibilities here.

## Routing

Routing is a **deterministic function of `RepositoryContext`**, using the
ingestor's categorized file lists — never hard-coded fixture or repository
names.

| Repository contents | Selected agent(s) |
| --- | --- |
| `source_files` (`.py`, `.js`, ...) | Code Security Agent |
| `dependency_files` (`requirements.txt`, `pyproject.toml`, `package.json`, locks, ...) | Dependency Agent |
| `cicd_files` (`.github/workflows/**`, `Dockerfile`, `docker-compose.yml`, `.gitlab-ci`, ...) | CI/CD Security Agent |
| Deployment/container config among `config_files` (e.g. `deploy/*.yaml`, `k8s/*.yaml`) | CI/CD Security Agent |
| Documentation only | *(no agent)* |
| Empty repository | *(no agent)* |
| Non-deployment config only (e.g. `.eslintrc.json`) | *(no agent)* |

Multiple agents are selected independently, so any combination is possible. A
repository with source, manifests, and workflows selects all three.

### Documentation and unrelated configuration never trigger agents

The routing logic deliberately distinguishes security-relevant artifact files
from documentation: a README, `.md`, or `.rst` file never selects an agent on
its own, and a repository that contains documentation *and* source still routes
only on the source. Similarly, arbitrary non-deployment configuration (an
eslintrc, a `ruff.toml`) does not route the CI/CD agent; only deployment/
container manifests do.

### Deployment-config detection

The ingestor classifies `.yaml`/`.yml` files as CONFIG. Most of these are
unrelated tooling config, but deployment/container manifests (Kubernetes,
compose-in-`deploy/`, helm charts) are security-relevant to the CI/CD agent. The
orchestrator recognizes deployment config by deterministic path tokens
(`k8s`, `deploy`, `deployment(s)`, `manifests`, `helm`, `charts`, `infra`) among
`config_files`. Paths are compared as strings only — never resolved, read, or
executed.

## Execution order

Selected agents run in a fixed, deterministic order — **Code → Dependency →
CI/CD** (`DEFAULT_AGENT_ORDER`). This is an initial policy, not claimed to be
optimal; it is a one-line configuration change, not a redesign, so later steps
can evaluate reordering without changing the architecture.

## Bounded execution

An explicit limit is applied so a repository cannot trigger unbounded work:

* `max_agents` — the maximum number of distinct agents executed in one run.
* `max_executions` — the maximum total agent executions across a run (for later
  iterative passes; with a single pass it equals `max_agents`).
* `max_passes` — reserved for future iterative follow-up passes. Step 16
  performs a single deterministic pass; this bound is recorded for later steps.

Selected agents beyond a bound are recorded as `NOT_RUN` (with a reason) rather
than silently dropped.

## Failure handling

The run never crashes because one agent misbehaved. Every selected agent is
recorded with a status:

* `SUCCESS` — the agent produced a canonical `SecurityFinding`.
* `NO_FINDING` — the agent ran but terminated without a finding (e.g.
  `AgentTerminatedError`, malformed output).
* `FAILED` — an unhandled construction or investigation error.
* `NOT_RUN` — selected but not executed because an execution bound was reached.

Failures are surfaced in the result (`note` carries the reason), and the other
agents still run. The aggregate status is:

* `EMPTY` — no agents selected (documentation-only or empty repository).
* `COMPLETED` — every selected agent ran and none failed.
* `PARTIAL` — some selected agents were not run (bound hit).
* `FAILED` — at least one selected agent failed.

## Canonical output

Execution collects the canonical `SecurityFinding` from each agent that actually
ran, via the agent's `to_security_finding()` method (Step 15). `findings` in the
result is the flattened, ordered list of those findings, ready for a later
investigation/risk/reporting layer without translation.

## Test seam

The orchestrator depends on an `agent_factory` (a callable mapping an
`AgentName` to an agent instance). This keeps orchestration logic independent of
the concrete agent classes and lets tests inject fakes + `FakeLLM`. A default
factory builds the real agents when an `LLMProvider` and repository path are
supplied.

## What Step 16 establishes

* Deterministic, content-based routing and selective execution.
* Stable execution order and bounded execution.
* Per-agent outcome records and aggregate status.
* Aggregation of canonical `SecurityFinding` outputs.

## What Step 16 does not establish

* Agent-to-agent delegation and messaging.
* Iterative follow-up passes (the `max_passes` bound is reserved).
* Investigation, risk-assessment, remediation, or final-reporting agents.
* Any claim about optimal ordering.

## Files

* Created: `src/orchestration/orchestrator.py`,
  `src/orchestration/models.py`, `tests/test_orchestrator.py`,
  `docs/orchestrator.md`, and fixtures under
  `tests/fixtures/orchestrator/` (never executed).
* Modified: `src/orchestration/__init__.py` (exports the orchestration API).
