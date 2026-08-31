# SecurityFinding — the canonical cross-agent finding

Step 15 of the SecureFlow execution plan, and the start of **standardizing the
agent output contract**. Establishes ONE canonical finding representation that
can be passed between specialized agents and, later, consumed by an
orchestrator, investigation/risk/remediation agents.

Standardized outputs are **infrastructure that enables** the later multi-agent
architecture. This step does **not** implement orchestration, agent delegation,
or agent-to-agent messaging.

## Why standardized findings are necessary

SecureFlow has three specialized agents:

| Agent | Step | Domain |
|---|---|---|
| Code Security Agent | 11 | Source-code security |
| Dependency Agent | 13 | Dependency vulnerabilities |
| CI/CD Security Agent | 14 | CI/CD & deployment configuration |

Each currently returns an internal `CodeFinding` (the LLM's raw structured
output). That model is minimal and LLM-specific — it has no notion of *which
agent* produced the finding, no standardized category, no structured
observed-vs-interpretation evidence split, no multiple affected files, and no
recommendation or extensible metadata.

For a later orchestrator/risk/remediation layer to consume findings from **all**
agents uniformly, there must be a single canonical representation whose core
fields parse identically regardless of the producing agent. That is what Step 15
introduces.

Without it, downstream consumers would have to special-case every agent's
output shape — exactly the fragility a standardized contract avoids.

## Architectural decision: `CodeFinding` vs `SecurityFinding`

The core decision was how to reconcile the existing finding models:

* `src/models/security_finding.SecurityFinding` — the **deterministic
  tool-evidence** record produced by Semgrep, Bandit, the dependency analyzer,
  and the CI/CD analyzer (Steps 7–10). It uses a categorical `Confidence` enum.
* `src/models/code_finding.CodeFinding` — the **LLM agent's raw structured
  output** (Steps 11–14). It uses a numeric `confidence` (0–1) and is the type
  returned by the agent loop and consumed by evaluation.

These two models could not simply be merged: tool evidence is a different,
categorical thing from an agent's probabilistic assessment, and the project
deliberately kept them separate (documented in `docs/code-security-agent.md`).

### Decision

1. **The deterministic tool model was renamed `SecurityFinding` → `ToolFinding`**
   so that the name `SecurityFinding` could be reclaimed by the canonical,
   agent-produced finding. A backward-compatible alias
   (`SecurityFinding = ToolFinding`) remains in `security_finding.py`, so all
   Steps 7–10 tool-layer code and tests work **unchanged**.

2. **`CodeFinding` is retained as the internal LLM raw-output model**, untouched.
   Steps 11–14 and the Step 12 evaluation depend on it and continue to work.

3. **A new canonical `SecurityFinding` (in `src/models/finding.py`) is the single
   cross-agent representation.** The only migration path from an internal
   `CodeFinding` to the canonical model is the one-directional, deterministic
   adapter `SecurityFinding.from_code_finding(...)`. Because there is exactly one
   conversion direction and it is tested, the two schemas cannot drift apart.

This is a **refined Option B**: retain `CodeFinding` internally, provide a
clean deterministic conversion into the canonical `SecurityFinding`. It creates
the least duplication (no third competing schema, no redesign of any agent's
investigation logic) and the cleanest separation of concerns.

## The canonical schema

`src/models/finding.py` defines:

### `SecurityFinding`

| Field | Type | Meaning |
|---|---|---|
| `finding_id` | `str` (non-empty) | Stable, deterministic identifier (e.g. `CODE-001`). Carried through from the agent's raw output; no random UUID churn. |
| `agent` | `AgentName` | Constrained producing agent: `code_security`, `dependency`, `cicd`. Stamped by the agent, never taken from untrusted model output. |
| `category` | `FindingCategory` | Standardized security category: `code`, `dependency`, `cicd` (spans all three agents). |
| `severity` | `Severity` | Reuses the shared enum (`error/warning/info/unknown`). |
| `confidence` | `float` (0–1) | Numeric degree of belief, preserving `CodeFinding` semantics. |
| `evidence` | `list[EvidenceItem]` | Structured evidence; keeps observed vs interpretation distinct. |
| `affected_files` | `list[str]` | Repository-relative affected paths; supports multiple files. |
| `recommendation` | `str` | Remediation recommended by the agent when available (default `""`). |
| `metadata` | `dict[str, str]` | Extensible agent-specific structured data. |
| `description` | `str` | Human-readable finding. |
| `file` | `str` | Convenience/back-compat singular primary file. |
| `line` | `int` (≥0) | Line number (0 = file-level / not line-specific). |

### Supporting types

* `AgentName` (`code_security`, `dependency`, `cicd`) — constrained producing agents.
* `FindingCategory` (`code`, `dependency`, `cicd`) — one coarse category per agent
  domain. Finer sub-categories are deferred to later investigation/risk steps.
* `EvidenceItem` — `{ kind, content, source }` where `kind` is
  `EvidenceKind.OBSERVED` or `EvidenceKind.INTERPRETATION`. `source`
  optionally names the producing tool/scanner.
* `EvidenceKind` — `observed` vs `interpretation`.

### How agent-specific information is represented

Agent-specific detail (dependency package/version/range/fixed version,
vulnerability ID, CI/CD rule ID, scanner name/rule, source line, tool evidence)
lives in **`metadata`** — not in divergent top-level schemas. A consumer that
only needs the core fields (`finding_id`, `agent`, `category`, `severity`,
`confidence`, `affected_files`) parses them identically for every agent and
ignores `metadata`. Consumers that care about a domain read the relevant
`metadata` keys.

Core fields are never duplicated into `metadata`; agent-specific extras go only
in `metadata`.

## Evidence: observed vs interpretation

The canonical `evidence` is a list of structured `EvidenceItem`s. The agent's raw
`CodeFinding` carries evidence as discrete, labeled strings (e.g.
`"analyzer: CICD.GHA.EXCESSIVE_PERMISSIONS ..."`, `"manifest: requirements.txt
declares requests==2.28.0"`). The adapter classifies each string
deterministically:

* strings starting with an *observation* prefix (`analyzer:`, `scanner:`,
  `manifest:`, `config:`, `source:`, `tool:`, `observed:`, `semgrep:`,
  `bandit:`, `dependency:`, ...) → `EvidenceKind.OBSERVED`;
* everything else → `EvidenceKind.INTERPRETATION`.

This preserves the project's core principle that observed evidence is kept
distinct from the agent's reasoning, and it does so as structured data — not an
unstructured prose blob.

## The three agents and the canonical finding

```
Code Security Agent  ──┐
                       ├─► SecurityFinding
Dependency Agent    ──┤
                       ├─► SecurityFinding
CI/CD Agent         ──┘
                       └─► SecurityFinding
```

Each agent now exposes `finding_agent`, `finding_category`, and a
`to_security_finding(code_finding)` method that stamps the agent's identity and
category onto its finding via the shared adapter. Investigation logic is
unchanged; the agent loop still returns its existing `CodeAgentResult` for
back-compatibility with Steps 11–14 and evaluation.

```python
# conceptually, for any of the three agents:
result = agent.investigate()                       # CodeAgentResult(CodeFinding)
canonical = agent.to_security_finding(result.finding)   # SecurityFinding
```

A downstream consumer can parse the shared core of a `SecurityFinding` no matter
which agent produced it.

## Serialization format

`SecurityFinding` is a Pydantic model; canonical serialization is
`model_dump_json()` (JSON). Strongly-typed enums serialize to their string
values (`agent: "code_security"`, `category: "cicd"`, `severity: "error"`), so
the wire format is human-readable and stable. Deserialization uses
`SecurityFinding.model_validate_json(...)`.

## How this enables later agent-to-agent communication

When orchestration, investigation, risk, and remediation agents are added in
later steps, they will receive and emit the same canonical `SecurityFinding`.
Because the schema is agent-agnostic:

* the orchestrator can collect findings from any set of agents and pass them
  without translation;
* an investigation/risk agent can enrich `metadata` / `recommendation` and
  return the same model;
* a remediation agent reads `affected_files`, `recommendation`, and `metadata`
  directly.

This step only establishes that contract and the deterministic conversion; it
does not wire up messaging.

## Validation

Validation is Pydantic and consistent with the existing project:

* `finding_id` is non-empty.
* `agent` is a valid `AgentName` member (missing/invalid agent is rejected).
* `category` is a valid `FindingCategory` member.
* `severity` uses the shared `Severity` enum (with the existing
  `high/medium/low` → `error/warning/info` coercion).
* `confidence` is within `[0, 1]`.
* `evidence` is a list of structured `EvidenceItem`s (`kind`/`content`).
* `affected_files` are normalized to repository-relative forward-slash paths.
* `metadata` is a structured string-dict.

Validation deliberately stops at *shape*; enforcement of any
orchestration/security-policy semantics belongs to later steps.

## Security considerations

All finding fields and evidence come from repository content and agent output —
they are treated as **untrusted data**, never as commands. This module performs
no execution: no shell, no subprocess, no Docker/kubectl/cloud/GitHub CLI, no
network, and no secrets are introduced. Path fields are normalized as data only
(never resolved or executed).

## Testing

`tests/test_security_finding.py` (34 tests), offline and deterministic:

1. Valid `SecurityFinding` construction.
2. Required fields present.
3. Confidence bounds (`[0,1]`, numeric-string coercion, out-of-range rejection).
4. Invalid severity rejected.
5. Invalid/missing agent and missing category rejected.
6. Empty/missing `finding_id` rejected.
7. Multiple affected files (and POSIX normalization).
8. Structured evidence (`EvidenceItem` / `EvidenceKind`).
9. Metadata preservation.
10. JSON serialization/deserialization round-trip.
11. Deterministic findings (identical input → identical output; no random IDs).
12. Conversion from `CodeFinding` (adapter): core preservation, agent/category
    stamping, affected-files derivation, observed/interpretation classification,
    determinism, recommendation passthrough, and that a model cannot fabricate
    `agent`.
13. Compatibility with the Code Security Agent.
14. Compatibility with the Dependency Agent.
15. Compatibility with the CI/CD Agent, including a shared-core parse test.

## Limitations

* `FindingCategory` is coarse (one per agent). Finer, cross-cutting categories
  (e.g. "injection", "secrets") are deferred to later investigation/risk steps.
* `recommendation` is `""` by default because agents do not yet generate
  remediation; agents will populate it in later steps.
* The observed/interpretation evidence split is a deterministic label-prefix
  heuristic, not provenance tracking. It is intentional and documented in
  `src/evaluation/scoring.py` too.
* `metadata` is a `dict[str, str]`; richer nested metadata is deferred.
* Standardized output is infrastructure only — orchestration, delegation, and
  agent-to-agent messaging are NOT implemented in this step.

## Files

* Created: `src/models/finding.py`, `tests/test_security_finding.py`,
  `docs/security-finding.md`.
* Modified: `src/models/security_finding.py` (rename `SecurityFinding` →
  `ToolFinding` with back-compat alias), `src/models/__init__.py` (exports),
  `src/agents/{code_security,dependency,cicd}_agent.py` (canonical output
  method).
* Unchanged: `src/models/code_finding.py`, evaluation, and all Steps 7–10 tool
  layers.
