# Risk Agent (Step 19)

The **Risk Agent** converts an evidence-backed investigation into a structured,
contextual risk assessment. It receives the completed
[`InvestigationResult`](./investigation-agent.md) and produces a
`RiskAssessment` that answers:

1. How severe is the investigated security issue?
2. How confident are we in that severity judgment?
3. How exploitable is the issue under the available evidence?
4. Which asset/component is affected?
5. What attack path is supported?
6. Why was this risk level assigned?
7. What evidence supports the decision?

> **The Risk Agent performs contextual risk assessment. It does not generate
> remediation.**

Step 19 is assessment-only. Remediation, patch generation, final reporting, and
Step 20+ are explicitly out of scope.

## Purpose

After Steps 17/18 a multi-agent investigation can correlate findings, request
specialist evidence, and produce relationships/attack-paths/root-cause
candidates in an `InvestigationResult`. Before deciding what to do about an
issue, SecureFlow needs a component that turns that evidence into a *risk
judgment* — one that is **contextual**, not a restatement of scanner labels.

The Risk Agent provides that judgment and the mechanism later needed to measure
whether cross-source contextual correlation changes severity relative to raw
scanner labels.

## Architecture

```
SecurityFinding[]
      ↓
Investigation Agent            (Steps 17-18)
      ↓
InvestigationResult
      ↓
Risk Agent                     (Step 19)
      ↓
RiskAssessment
```

Unlike the Investigation Agent, the Risk Agent is **not** an unbounded agent
loop and does **not** delegate to specialists. It makes a single structured LLM
call over the completed investigation, then the application **grounds** the
result before returning it.

```
InvestigationResult
      ↓
Risk Agent (single structured LLM call)
      ↓  application grounding + validation
      ↓   - retain only existing finding ids
      ↓   - reject invented attack paths
      ↓   - reclassify evidence referencing non-existent findings
RiskAssessment
```

### Trust boundary

Findings, evidence, and weapon attack paths are **untrusted data** from the
repository. The Risk Agent shows them to the model as data and never executes
them. The application computes all grounding bookkeeping; the model produces
only the analytical interpretation (severity, confidence, exploitability,
affected assets, reasoning).

## Components

### `src/risk/models.py`

The risk domain contract:

* `RiskSeverity` — contextual severity scale (`critical`, `high`, `medium`,
  `low`, `informational`, `unknown`).
* `Exploitability` — how exploitable under the available evidence (`confirmed`,
  `likely`, `possible`, `unlikely`, `not_exploitable`, `unknown`).
* `RiskReasoning` — structured reasoning separating `observed`,
  `interpretation`, and `assumptions`.
* `RiskEvidence` — evidence tied to an existing finding / attack path.
* `RiskAsset` — a structured affected asset (`endpoint`, `package`, `workflow`,
  `container`, `credential`, `environment`, ...).
* `RiskAttackPath` — a path reference that must be grounded in the
  investigation, and that is labelled `investigation` or `interpretation`.
* `RiskAssessment` — the complete output contract.
* `RiskStats` — light bounded-execution statistics.

### `src/risk/llm.py`

`RiskLLMProvider` (abstract), `parse_risk_assessment` (JSON → validated
`RiskAssessment`, raising `ParseRiskAssessmentError` on malformed/out-of-bounds
output), and the scripted `FakeRiskLLM` for deterministic offline tests.

### `src/risk/agent.py`

`RiskAgent` — the single-call agent. It builds the message context from the
`InvestigationResult`, asks the provider, then **grounds** the result.

## Input contract

The Risk Agent receives an `InvestigationResult` containing:

* canonical `SecurityFinding` objects (`investigation.context.findings`);
* `input_finding_ids` — the authoritative set of valid finding ids;
* `attack_paths` — the authoritative set of valid attack-path ids;
* `delegation_steps` / `evidence` — accumulated specialist evidence;
* `investigation_id`, `repository_name`.

It does not independently re-run the Code, Dependency, or CI/CD agents and does
not directly inspect arbitrary repository files.

## `RiskAssessment` output contract

| Field | Type | Semantics |
|---|---|---|
| `assessment_id` | `str` (required) | Stable id |
| `investigation_id` | `str` | Id of the source investigation |
| `severity` | `RiskSeverity` | Contextual severity |
| `confidence` | `float` 0.0–1.0 | Confidence in the assessment |
| `exploitability` | `Exploitability` | Exploitability under evidence |
| `affected_assets` | `list[RiskAsset]` | Structured affected assets |
| `attack_path` | `RiskAttackPath \| None` | Grounded attack path, or `None` |
| `reasoning` | `RiskReasoning` | Observed / interpretation / assumptions |
| `evidence` | `list[RiskEvidence]` | Evidence referencing findings |
| `finding_ids` | `list[str]` | Grounded finding ids |
| `metadata` | `dict[str, str]` | Bookkeeping |

## Severity semantics

The shared tool `Severity` (`error`/`warning`/`info`/`unknown`) is a
**deterministic scanner label**, not a contextual risk judgment. Because it is
too tool-oriented for risk assessment and lacks a `critical`/`informational`
scale, Step 19 introduces the smallest justified abstraction, `RiskSeverity`,
and documents the relationship:

| Tool `Severity` | Coarse hint |
|---|---|
| `error` | `high` |
| `warning` | `medium` |
| `info` | `low` |
| `unknown` | `unknown` |

`RiskSeverity.from_tool_severity` is a **non-binding starting hint only**. The
Risk Agent reasons over evidence and may depart from it. In particular it must
**never** silently map every `ERROR` finding to `critical`: an unused or
unreachable `ERROR` dependency can legitimately be `low`/`unknown`.

## Confidence semantics

`confidence` (0.0–1.0) represents the Risk Agent's confidence in its **own
assessment**, not exploitability and not scanner certainty. It is validated to
be within bounds. When evidence is insufficient, the agent should express this
as low numeric confidence along with `severity`/`exploitability` `unknown` —
never false confidence.

## Exploitability semantics

`Exploitability` uses terminology aligned with the research methodology:

* `confirmed` — evidence shows a concrete, reachable exploitation.
* `likely` — evidence strongly supports exploitability.
* `possible` — plausible under available evidence.
* `unlikely` — evidence suggests the path is hard or blocked.
* `not_exploitable` — evidence shows the issue cannot be exploited.
* `unknown` — insufficient evidence.

## Affected assets

Affected components are represented as structured `RiskAsset` objects (name +
kind + optional linking `finding_id`) rather than buried in reasoning prose —
e.g. `Public auth endpoint`, `requests==2.28.1 (package)`, `deploy.yml
(workflow)`, `container runtime`, `credential`, `deployment environment`.

## Attack-path handling

The Risk Agent references attack paths from the `InvestigationResult` when they
exist and does **not** invent new ones. The application validates that any
referenced `attack_path_id` exists in the investigation; an unsupported id is
rejected and `attack_path` is set to `None`. If the agent derives additional
interpretation from an existing path, it labels `source` as `interpretation`
rather than `investigation`.

## Evidence requirements

`RiskEvidence` entries must reference existing investigation findings. The
application validates references:

* finding ids not present in the investigation are **removed** from
  `finding_ids`;
* evidence referencing non-existent findings is **reclassified as
  `interpretation`** (and unlinked) so it is clearly not trusted as observed
  input — it is never converted into confidence;
* evidence that fails this is never silently turned into certainty.

## Reasoning vs observed evidence

`RiskReasoning` separates `observed` evidence (what tools/specialists
deterministically reported) from the agent's `interpretation` (its contextual
reading) and from explicit `assumptions` (unsupported claims the agent must
acknowledge rather than assert as fact). The agent must not claim unsupported
deployment/runtime facts.

## Failure handling

The Risk Agent handles safely, returning a valid-but-de-valued assessment
(`completed=False`, `severity=unknown`, `exploitability=unknown`,
`confidence=0.0`, empty evidence, and a `termination_reason`):

* empty investigation;
* no findings;
* no attack path;
* incomplete / conflicting / missing evidence;
* malformed LLM response;
* invalid severity / confidence / exploitability;
* unsupported finding ids / evidence references / fabricated attack-path ids.

Missing evidence never becomes false confidence.

## Prompt-injection boundary

All investigation content is untrusted data. A prompt-injection string embedded
in evidence is rendered to the model as data but never treated as an
instruction — the agent cannot be forced to emit a higher severity by the
content of repository-derived evidence. This is enforced by design (the model
has no tools; the application decides execution) and covered by a test.

## Limitations

* The Risk Agent judges *severity/confidence/exploitability*; it does not verify
  attack-path *semantics* beyond grounding ids to existing investigation data.
* Tests use a scripted fake provider; allowing a real provider to decide the
  conclusion is a future integration.
* No remediation, patch generation, or final reporting is produced.

## Relationship to the Investigation Agent

The Investigation Agent (Steps 17–18) reasons *across* findings and gathers
specialist evidence into an `InvestigationResult`. The Risk Agent (Step 19) is
downstream: it consumes that `InvestigationResult` and turns it into a
contextual risk judgment. The Risk Agent does not re-run investigation or
specialist work.

## Research relevance

Step 19 provides the mechanism needed for later evaluation of the architecture's
research questions:

* **RQ1** (does the multi-agent architecture improve investigation quality?)
  — risk assessment forms the downstream quality measure.
* **RQ3** (does cross-source correlation improve root-cause / attack-path
  identification?) — attack-path-grounded risk judgments rely on that
  correlation.
* **RQ5** (do quality improvements justify multi-agent cost/complexity?) — the
  single, simple Risk Agent adds a bounded, cheap step whose value can be
  weighed against cost.

Risk assessment also establishes the measurement basis for whether *contextual
correlation* changes severity relative to raw scanner labels. No improvement is
claimed yet; Step 19 only builds the mechanism to evaluate it.

## What Step 19 does NOT implement

* Remediation Agent;
* patch / code / configuration fixes;
* pull-request changes;
* final report generation;
* GitHub comments or developer approval workflow;
* dashboard or deployment.

Step 19 only performs contextual risk assessment.

## Tests

`tests/test_risk_agent.py` (31 tests) covers model validation (valid assessment,
missing id, out-of-bound confidence, invalid severity/exploitability, asset /
attack-path / evidence serialization, finding-id preservation); agent behaviour
(complete attack path, unused-dependency lower/uncertain risk, isolated finding
not critical, no-path handling, empty investigation, malformed LLM failure,
evidence handed to provider, id preservation, attack-path grounding); evidence
grounding (no non-existent finding ids, no fabricated attack-path ids,
unsupported evidence → interpretation, scanner severity not decisive); security
(no tool/shell surface, no specialist delegation, no repository code execution,
offline / no API key, prompt injection stays data); and parse helpers. All are
deterministic and offline.

The full suite (Steps 6–18) still passes, confirming no regression to the Code,
Dependency, CI/CD agents, the canonical `SecurityFinding` model, the
Orchestrator, or the Investigation Agent.