# Investigation Agent (Step 17)

The **Investigation Agent** is the first component in SecureFlow that performs
actual agent collaboration. It receives the canonical
[`SecurityFinding`](./security-finding.md) objects produced by the Code,
Dependency, and CI/CD agents and determines whether apparently separate findings
are related. Where existing evidence is insufficient, it requests additional
specialist evidence through an application-controlled collaboration layer.

## Why this step

After Steps 15/16, SecureFlow can collect canonical findings from multiple
specialist agents. A single vulnerability is often reported as several separate
findings — e.g. a source-file gap plus the outdated dependency that makes it
exploitable plus the CI/CD workflow that deploys it. Before any risk scoring or
remediation, the project needs a component that reasons *across* findings: this
is Step 17.

Step 17 deliberately focuses on **collaboration mechanics and a bounded,
application-controlled specialist interface**. It does not yet add risk scoring,
remediation planning, or a final remediation report — those remain later steps.

## Architecture principle

> "LLMs reason over evidence, not replace tools that produce it."

The Investigation Agent follows the same rule as the specialist agents. It
produces *analysis* (relationships, attack paths, root-cause candidates,
supporting evidence, confidence) while the application computes all bookkeeping
and enforces the safety boundary.

Crucially, the Investigation Agent **never instantiates or executes another
agent** and never passes arbitrary tool names or repository-derived text into an
agent. All specialist collaboration flows through the
`CollaborationInterface`, which:

* validates the request's `target_agent` against the known specialist agents;
* validates `request_type` against a strict per-agent allow-list;
* invokes a bound capability (never an arbitrary tool name or subprocess);
* returns a structured `SpecialistResponse` — success or explicit failure,
  never fabricated evidence;
* records the request/response transcript; and
* bounds the number of evidence items returned per response.

```
Canonical SecurityFindings
        |
        v
Investigation Agent (LLM loop)
        |                                    \
        | (needs more evidence)              | (final output)
        v                                    v
CollaborationInterface             InvestigationResult (COMPLETED)
        | (validated request)
        v
Specialist capability (existing safe tool layers)
```

## Components

### `src/investigation/models.py`
Structured contracts:
* `RelationshipType` — deliberately small taxonomy
  (`shared_component`, `shared_dependency`, `enables`, `depends_on`,
  `amplifies`, `attack_path`, `unrelated`, `unknown`).
* `FindingRelationship` — a single, evidence-supported link between findings.
* `AttackPath` — an ordered, evidence-supported chain across findings.
* `RootCauseCandidate` — a candidate shared underlying cause.
* `InvestigationRequest` — the structured per-step specialist request.
* `SpecialistResponse` — the structured response (success or explicit failure).
* `InvestigationOutput` — the LLM-produced analytical content.
* `InvestigationDecision` — one step (specialist request **or** final output,
  never both).
* `InvestigationResult` — the application-assembled output with completion
  state, termination reason, transcript, and stats.
* `InvestigationStats` — bounded-execution statistics.

### `src/investigation/llm.py`
`InvestigationLLMProvider` (mirrors the code agent's `LLMProvider` but returns
`InvestigationDecision`) plus `parse_investigation_decision` and the scripted
`FakeInvestigationLLM` for deterministic, offline tests.

### `src/investigation/collaboration.py`
`CollaborationInterface` — the application-controlled gate. Exposes the strict
per-agent `ALLOWED_REQUEST_TYPES` allow-list and `SpecialistRegistry`.

### `src/investigation/handlers.py`
The default (real) specialist capabilities, which reuse the existing confined
tool layers (`AgentTools`, `DependencyAgentTools`, `CICDSecurityAgentTools`).
They read/search repository *data* in-process — no execution, no network.

### `src/investigation/agent.py`
`InvestigationAgent` — the bounded LLM loop that calls the collaborator and
assembles `InvestigationResult`.

## Behaviour

* **Selective specialist use**: the agent requests additional evidence only when
  a decision genuinely needs it; a single final result needs no collaboration.
* **Deterministic bounded execution**: `max_iterations`,
  `max_specialist_requests`, `max_findings`, `max_evidence_items` are hard
  ceilings recorded on `InvestigationStats`.
* **Completion states**: `COMPLETED` (final analytical output produced),
  `TERMINATED` (a bound was hit), `FAILED` (malformed LLM response or an
  undefined step). `InvestigationResult.completed` reflects the state.
* **No silent failure**: every specialist request is recorded, including
  rejected/failed ones; failures never crash the run and never fabricate
  evidence.

## Security

* Findings and evidence are **untrusted data** — shown to the model as data,
  never executed and never treated as instructions.
* Specialist requests are validated against the allow-list; arbitrary tool
  names, subprocesses, and network access are never permitted.
* The default capabilities reuse the existing tool layers, which already confine
  reads/searches to the repository root.

## What Step 17 does / does not establish

* **Yes**: cross-finding analysis, first specialist-collaboration mechanism,
  bounded execution, deterministic offline tests.
* **Not yet**: risk scoring, remediation planning, a final remediation report,
  or orchestrator-driven iterative follow-up loops.

## Tests

`tests/test_investigation.py` (32 tests) covers: allow-list routing
validation, request logging, evidence bounding, the default registry over
on-disk fixture repositories (source/dependency/CI-CD), a full collaboration
transcript, completion/termination/failure states, bound enforcement, findings
bounding, the empty-findings case, decision parsing (including rejecting a
decision that requests a specialist *and* emits a result), and prompt-injection
resistance.

Fixtures live under `tests/fixtures/investigation/`. They are read as data and
are never executed; the source fixture contains a prompt-injection marker to
verify untrusted repository text is not treated as an instruction.
