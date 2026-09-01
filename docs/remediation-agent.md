# Remediation Agent (Step 20)

The **Remediation Agent** is downstream of the [Risk Agent](./risk-agent.md). It
receives the final investigation/risk context and produces a structured
**`RemediationPlan`** — a **proposal** for how to fix the investigated issue.

> The Remediation Agent produces a proposed remediation plan. It does **not**
> modify the repository. It does **not** apply anything.

## Purpose

After Steps 17–19, SecureFlow can investigate findings and produce a contextual
risk assessment. Step 20 adds the concise, evidence-grounded **remediation
planning** step: given the `InvestigationResult` and the `RiskAssessment`, it
recommends *what* to fix, *where*, and *how to verify* — explicitly as a document
awaiting human review, not as an automatic change.

## Data flow

```
InvestigationResult
      ↓
RiskAgent                          (Step 19)
      ↓
RiskAssessment
      ↓
RemediationAgent                   (Step 20)
      ↓
RemediationPlan (PROPOSAL ONLY)
      ↓
[HUMAN APPROVAL]                   (future; not implemented)
      ↓
Future Patch / Application System  (future; not implemented)
```

The Remediation Agent does **not** re-run the investigation or risk analysis. It
consumes the already-completed `InvestigationResult` and `RiskAssessment`.

## Architecture

```
InvestigationResult + RiskAssessment
      ↓
Remediation Agent (single bounded structured call)
      ↓  application input/reference/bounds validation
      ↓   - finding-id grounding
      ↓   - affected-file verification
      ↓   - evidence reclassification
      ↓   - list bounding
RemediationPlan (proposal; verified=False files are not real repo files)
```

Like the Investigation and Risk agents, the **LLM produces analytical remediation
reasoning** (root cause, recommended fix, proposed changes, tests, configuration,
validation, evidence, confidence) while the **application** performs input
validation, reference validation, bounds, structured-output parsing, grounding,
status/bookkeeping, and safety enforcement.

## Components

* `src/remediation/models.py` — the remediation domain contract
  (`RemediationPlan`, `AffectedFile`, `CodeChange`, `TestToAdd`,
  `ConfigChange`, `ValidationStep`, `RemediationEvidence`, `RemediationStats`,
  and the `RemediationStatus` / `ChangeKind` / `ValidationKind` enums).
* `src/remediation/llm.py` — `RemediationLLMProvider`,
  `parse_remediation_plan`, `ParseRemediationPlanError`, and the scripted
  `FakeRemediationLLM` for deterministic offline tests.
* `src/remediation/agent.py` — `RemediationAgent` (single bounded call, grounding,
  bounds, safe failure).

## Inputs

The Remediation Agent receives:

* an `InvestigationResult` (findings, relationships, attack paths, specialist
  evidence, context); and
* an optional `RiskAssessment` (contextual severity, exploitability, affected
  assets, reasoning).

It never re-runs investigation or risk analysis and never re-runs the specialist
agents.

## Outputs — `RemediationPlan` schema

| Field | Type | Semantics |
|---|---|---|
| `remediation_id` | `str` (required) | Stable id (application-assigned) |
| `investigation_id` | `str` | Source investigation id |
| `risk_assessment_id` | `str` | Source risk-assessment id |
| `root_cause` | `str` | Root cause, grounded in evidence |
| `recommended_fix` | `str` | Recommended fix |
| `proposed_code_changes` | `list[CodeChange]` | Advisory code changes (text/snippets) |
| `tests_to_add` | `list[TestToAdd]` | Proposed tests |
| `configuration_changes` | `list[ConfigChange]` | Proposed config changes |
| `affected_files` | `list[AffectedFile]` | Affected files, with `verified` flag |
| `validation_steps` | `list[ValidationStep]` | Advisory validation steps |
| `finding_ids` | `list[str]` | Grounded finding ids |
| `severity` | `RiskSeverity \| None` | Contextual severity from the risk assessment |
| `evidence` | `list[RemediationEvidence]` | Evidence supporting the recommendation |
| `confidence` | `float` 0.0–1.0 | Confidence in the recommendation |
| `metadata` | `dict[str, str]` | Bookkeeping |
| `status` / `completed` / `termination_reason` | — | Completion state |
| `stats` | `RemediationStats` | Bounded-execution stats |

### `AffectedFile` and verification

`AffectedFile.path` is advisory repository-relative text. The application sets
`verified = True` only when the path appears among the investigation findings'
`file`/`affected_files`. An **unverified** path is carried as advisory text and is
**never treated as a real repository file** — this prevents the model from
turning its own words into ground truth about repository contents.

## Grounding rules

* **Finding ids** not present in the investigation are **removed** from
  `finding_ids` and counted in `stats.findings_rejected`.
* **Code/tests/config changes** that link an unknown finding id have that link
  **nulled**.
* **Evidence** referencing a non-existent finding is **reclassified as
  `interpretation`** (and unlinked), never as observed. This ensures the model's
  assertions are not auto-promoted to "observed evidence".
* **Affected files** are verified against the investigation's known repository
  paths as above.

## Confidence semantics

`confidence` (0.0–1.0) is confidence in the **remediation recommendation** — how
likely the proposed fix addresses the root cause. It is **NOT**:
* exploitability;
* scanner certainty; or
* the probability that the vulnerability exists.

If evidence is insufficient, confidence should be low rather than fabricated.

## Safety boundary

The Remediation Agent **never**:

* modifies repository files;
* writes patches into the repository;
* commits or pushes changes;
* creates pull requests;
* executes arbitrary shell commands;
* executes generated code;
* deploys anything.

There is **no mechanism** — no tool and no method — for the agent to write to
the repository. All proposed changes exist only as advisory text/snippets in the
`RemediationPlan`. No subprocess, shell, Docker, kubectl, cloud, or network
capability is exposed.

## Human approval boundary

The output is a **proposal** that sits behind an explicit approval gate:

```
Remediation Agent
      ↓
Proposed Remediation
      ↓
[HUMAN APPROVAL]            ← explicit, required before anything is applied
      ↓
Future Patch / Application System   ← not implemented
```

Step 20 implements the proposal upstream of this boundary. The approval/
application system itself is deliberately **not** implement here; it would be a
later, separately validated step.

## Prompt-injection handling

Investigation evidence, finding descriptions, source snippets, CI/CD
configuration, dependency metadata, and other repository-derived content are
**untrusted data**. A malicious repository file must not be able to instruct the
Remediation Agent to modify files, reveal secrets, execute commands, bypass
approval, change system instructions, or treat attacker-controlled text as
trusted instructions.

The Remediation Agent has no execution surface, so injected instructions cannot
be acted on; the system prompt and output contract direct it to treat all input
as data. This is verified by a dedicated prompt-injection test.

## Failure handling

Empty/insufficient investigation, malformed LLM output, invalid severity /
confidence / change-kind, unknown finding ids / file references, and
repeatedly-invalid model responses all terminate safely: the agent returns a
`completed=False` plan with `status=FAILED`, `confidence=0.0`, empty changes, and
a `termination_reason`. It never loops indefinitely (a single call, recorded as
`max_iterations=1`).

## Bounds

Explicit, recorded on `RemediationStats`:
* findings considered (`max_findings`);
* proposed code changes (`max_code_changes`);
* tests to add (`max_tests`);
* configuration changes (`max_config_changes`);
* affected files (`max_affected_files`);
* evidence items (`max_evidence_items`);
* validation steps (`max_validation_steps`);
* iterations (`max_iterations = 1`).

## Limitations

* The plan is text/advisory; it does not verify that proposed changes are
  syntactically correct or would actually compile.
* `AffectedFile.verified` reflects knowledge from the investigation, not file
  existence on disk.
* Tests use a scripted fake provider; wiring a real provider is a future
  integration.

## What Step 20 proves

* A structured, evidence-grounded remediation `RemediationPlan` is produced
  downstream of investigation/risk, without re-running them.
* References (finding ids, files, evidence) are validated and grounded by the
  application; the model cannot inject invented ids/files/evidence as observed.
* Bounds and safe termination work; confidence is bounded and does not fabricate
  certainty.
* There is **no** repository-writing, shell, subprocess, or network capability.

## What Step 20 explicitly does NOT prove

* It does **not** apply patches or modify the repository.
* It does **not** implement human approval UI or an application/pipeline that
  acts on the plan.
* It does **not** commit, push, create PRs, or deploy.
* It does **not** implement final reporting/dashboards, new orchestration, new
  specialist agents, or a real LLM API integration.

## Tests

`tests/test_remediation_agent.py` (33 tests) covers: construction; required
fields; confidence bounds; valid-plan parsing; malformed / out-of-bounds /
invalid-change JSON parsing; root-cause & recommendation preservation; proposed
code changes; tests-to-add; configuration changes; affected-file verification
(known vs unknown); finding-id grounding; evidence grounding (observed preserved,
unsupported reclassified); conflicting evidence; empty/insufficient investigation
(low confidence); malformed-LLM safe failure; preservation of investigation/risk
context (including severity stamped from the risk assessment); output bounds; safe
single-call termination; and the security/safety cases: no repository-modification
capability, no shell/subprocess capability, no automatic patch application, and
prompt-injection-in-evidence (treated as data only). All are deterministic and
offline.

The full suite (Steps 6–19) still passes, confirming no regression to the Code,
Dependency, CI/CD agents, the canonical `SecurityFinding`, the Orchestrator, the
Investigation Agent, or the Risk Agent.