# Investigation Agent (Steps 17–18)

The **Investigation Agent** is the first component in SecureFlow that performs
actual agent collaboration. It receives the canonical
[`SecurityFinding`](./security-finding.md) objects produced by the Code,
Dependency, and CI/CD agents and determines whether apparently separate findings
are related. Where existing evidence is insufficient, it requests additional
specialist evidence through an application-controlled collaboration layer.

Step 17 gives the investigator the ability to **request specialist information**.
Step 18 extends it so the investigator can conduct a **sequential, dependent
delegated investigation**: a later specialist request may depend on an earlier
specialist response.

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

---

# Step 18 — Agent-to-agent sequential delegation

Step 17 established *single* specialist delegation: an investigator could ask
one specialist for evidence. That was intentionally limited — each request was
independent in the sense that the loop simply passed responses back as text.

Step 18 makes the investigation **sequentially dependent**:

> *Step 17:* "Investigator can request specialist information."
>
> *Step 18:* "Investigator can conduct a sequential delegated investigation in
> which later specialist requests depend on earlier specialist responses."

The investigator maintains an **explicit investigation context**
(`InvestigationContext`) that is re-rendered to the LLM on every iteration, so
each decision structurally receives all earlier findings, specialist requests,
specialist responses, and accumulated evidence. A follow-up request (e.g. "the
package is imported, now is it reachable from the public endpoint?") can
therefore be produced *from* the previous response.

```
Initial Findings
      |
      v
Investigator
      |
      | delegation request #1
      v
Dependency Agent
      |
      | structured response
      v
Investigator
      |
      | delegation request #2
      v
Code Agent
      |
      | structured response
      v
Investigator
      |
      v
Attack Path / Root Cause
```

## What changed from Step 17

* New models in `src/investigation/models.py`:
  * `DelegationStep` — a single traceable request/response pairing plus the
    reasoning that produced it (`step_index`, `reasoning`, `request`,
    `response`).
  * `InvestigationContext` — the agent's explicit in-progress state:
    `findings`, `delegation_steps`, `accumulated_evidence`, `reasoning_history`.
  * `InvestigationResult` gains `delegation_steps` and `context` (additive; the
    Step 17 `specialist_requests` / `specialist_responses` transcript is kept
    for backwards compatibility).
* `InvestigationAgent` loop refactored to rebuild its messages from
  `InvestigationContext` each iteration. The previous append-only message list
  is replaced so that every decision provably sees the full accumulated state.
* New allow-listed request type `reachability` on the code agent (a cross-agent
  reachability question). Dependency-side "is it used?" reuses the existing
  `dependency_usage` request type.
* `tests/test_investigation_delegation.py` add a separate, complementary suite.

## Delegation flow (exact)

The conceptual loop is:

```
while within bounds:
    LLM receives InvestigationContext (findings + prior steps + evidence)
    LLM returns InvestigationDecision
    if delegate:
        validate target_agent / request_type / payload via CollaborationInterface
        execute approved specialist capability
        validate SpecialistResponse
        append request + response (+ reasoning) to context
        accumulate observed evidence (bounded)
        continue
    if complete:
        build final InvestigationOutput / InvestigationResult
        stop
    if malformed/invalid:
        terminate safely per Step 17 semantics
```

This is **not** "run all specialists in parallel then merge". Delegation is
sequential: request #2 is emitted only after response #1 is in context, and the
decision that emits request #2 has already received response #1.

## Bounds and allow-list enforcement

* `max_specialist_requests` caps the total number of delegations per run.
* `max_iterations` caps total LLM calls.
* `max_findings` caps input findings, `max_evidence_items` bounds evidence.
* `target_agent` is validated against the known specialist agents.
* `request_type` is validated against the per-agent `ALLOWED_REQUEST_TYPES`
  allow-list.
* Request payloads are structured; unsupported agents/request types are rejected
  cleanly as `success=False` responses (never executed, never a crash).

## Structured request/response protocol

Each delegation is a structured `InvestigationRequest` (target agent, request
type, reason, `context_finding_ids`, query) answered by a structured
`SpecialistResponse` (success/failure, structured evidence, related finding ids,
explanation). Every step is recorded as a `DelegationStep`, giving a reviewer a
clear chain: request #1 → response #1 → reasoning → request #2 → response #2 →
final conclusion.

## Failure handling

A failed or rejected specialist request is recorded explicitly (success=False,
with a `failure_reason`) in the context and transcript. It never crashes the
run and never produces fabricated evidence — the investigator may terminate or
continue according to the bounded policy.

## Prompt-injection handling

Specialist evidence and findings are **untrusted data**. They are rendered to
the model as data and never executed. The trust boundary remains:

```
LLM decision
    ↓
application validation
    ↓
CollaborationInterface
    ↓
approved specialist handler
    ↓
structured response
    ↓
Investigator context
```

The LLM never directly executes a specialist or arbitrary tool — it only
*requests* delegation, and the application validates and executes it.

## What Step 18 does NOT prove

* It does not prove correctness of attack-path *semantics* — only that paths are
  constructed from accumulated (non-fabricated) evidence. Specialist responses
  in tests are fake but structured.
* It does not add unrestricted autonomous orchestration, risk scoring, or
  remediation planning — those remain later steps.
* It does not reason over live/networked data; everything is in-process and
  offline.

## Tests (Step 18)

`tests/test_investigation_delegation.py` (16 tests) proves:

1. Single delegation still works.
2. Two-step sequential delegation (Dependency → Code → final) works.
3. The second LLM decision actually receives the first specialist response
   (verified via the recorded message history).
4. The second request can depend on the first specialist's response.
5. Specialist responses are preserved in the investigation context and result.
6. Delegation is bounded by `max_specialist_requests`.
7. Delegation is bounded by `max_iterations`.
8. Unsupported target agents are rejected.
9. Unsupported request types are rejected.
10. Malformed specialist responses do not become fabricated evidence.
11. Specialist failure is represented explicitly and does not crash the process.
12. Prompt-injection inside specialist evidence is treated as data.
13. The investigator cannot directly invoke arbitrary tools or shell commands.
14. Final attack-path construction uses accumulated evidence, not hard-coded
    fixture knowledge.
15. Existing Step 17 tests remain unchanged and pass.
16. The full test suite passes.
