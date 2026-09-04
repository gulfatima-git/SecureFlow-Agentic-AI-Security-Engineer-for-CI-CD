# SecureFlow Experimental Baselines

## Purpose

This document defines the three experimental systems that will be compared in SecureFlow's evaluation: a traditional security-tool baseline, a single-LLM investigation baseline, and the SecureFlow multi-agent system. The purpose is to ensure that later implementation and experiments compare genuinely different architectures under fair, reproducible, and well-documented conditions.

Each system is defined by its inputs, processing model, outputs, and evaluation role — not by implementation details that have not yet been determined.

## Experimental Design Principles

The following principles govern how the three systems are defined and compared:

1. **Isolate what you study.** Each comparison should isolate one architectural variable. The comparison of B vs C isolates multi-agent specialization. The comparison of A vs B isolates LLM reasoning. The comparison of A vs C isolates the full SecureFlow approach but cannot alone attribute improvement to any single component.

2. **Do not handicap any system.** Baseline A is evaluated on tasks it was designed for. Baseline B receives equivalent evidence and comparable instructions. No system is deliberately weakened to produce a favorable comparison for another.

3. **Compare under controlled inputs.** Where appropriate, systems receive the same repository, the same deterministic-tool evidence, and the same evaluation task. Differences in output are attributable to the reasoning architecture, not to input differences.

4. **Accept that results may not favor SecureFlow.** The research is designed to be capable of producing evidence that the multi-agent architecture provides no advantage over simpler approaches. This is a valid and informative outcome.

5. **Acknowledge task dependence.** Investigation quality improvements, if any, will vary across repository types, vulnerability patterns, and investigation tasks. A single aggregate score is insufficient.

---

## Baseline A — Traditional Security Tools

### Definition

Baseline A is a non-LLM reference condition. A repository is processed by standard deterministic security tools. The tool output — raw findings, warnings, and alerts — is presented to the developer without additional analysis, correlation, or AI-generated reasoning.

This baseline represents the current state of practice for most development teams and establishes the minimum bar that any AI-assisted system must exceed to justify its added complexity.

### Conceptual Pipeline

```
Repository
    → deterministic security tools (static analysis, dependency scanning,
       secret detection, CI/CD config linting, Docker analysis)
    → normalized and/or raw findings
    → developer-facing output
```

### Inputs

- Repository source code, configuration, and CI/CD pipeline definitions
- Deterministic security-tool execution (tool-specific inputs)

### Capabilities

- Detect security issues using well-established deterministic algorithms (SAST, dependency CVE matching, secret-pattern matching, config misconfiguration detection)
- Produce findings with tool-assigned severity levels and CWE/CVE identifiers where applicable
- Generate structured output in standard formats (SARIF, JSON, or tool-native formats)
- Run reproducibly on the same input with deterministic results

### Limitations

- No cross-source correlation: findings from different tools are reported independently
- No investigation reasoning: the system does not determine whether findings are related, exploitable in context, or part of a larger attack path
- No root-cause analysis beyond what deterministic rules can express
- No remediation reasoning: findings may include generic guidance but not context-specific remediation tied to the repository's architecture
- No risk prioritization beyond tool-assigned severity scores
- Susceptible to high false-positive rates that developers must triage manually

### Outputs

- Tool-specific finding reports (one per tool or category)
- Severity, confidence, and rule/CWE identifiers where applicable
- File location and code region references
- No unified cross-source report
- No investigation narrative or attack-path description

### Evaluation Role

Baseline A is evaluated on the tasks traditional security tools are designed to perform: detection, scanning, and finding generation. It is **not** evaluated on investigation quality metrics that require reasoning capabilities it was never designed to provide (root-cause analysis, cross-source correlation, remediation reasoning). Evaluating Baseline A on those tasks and concluding it performs poorly would be an unfair comparison — it would be measuring a tool against capabilities outside its design scope.

The appropriate comparison for Baseline A is: "Does the tool correctly identify vulnerabilities that exist in the repository?" not "Does the tool explain why those vulnerabilities matter."

### Strengths

- Deterministic and reproducible
- Well-understood false-positive characteristics
- Low computational cost
- No API costs or token usage
- Mature tool ecosystem

---

## Baseline B — Single-LLM Security Investigation

### Definition

Baseline B is a single general-purpose LLM that receives repository evidence and security-tool findings, then produces a structured security investigation report in one reasoning pass. The LLM has no specialized agents, no agent-to-agent delegation, and no multi-step orchestration. It is one reasoning process operating over all available evidence.

The purpose of this baseline is to determine whether the benefits attributed to SecureFlow actually come from using an LLM at all, or specifically from multi-agent specialization and orchestration.

### Conceptual Pipeline

```
Repository + security-tool evidence
    → single general-purpose LLM (one reasoning pass)
    → structured security investigation report
```

### Inputs

- Repository source code and configuration (accessible via repository inspection)
- Security-tool findings (the same deterministic-tool output available to System C)
- Task instructions describing the investigation to perform
- Where appropriate, the same ground-truth labels used to evaluate other systems

### Evidence Available

Baseline B has access to the same evidence that System C's agents receive. This includes:

- Repository file structure and source code
- Dependency manifests and lock files
- CI/CD pipeline configuration (GitHub Actions workflows)
- Docker and deployment configuration
- Git history and recent diffs
- Security-tool findings (SAST, dependency scan, secret detection, config analysis)

The LLM can inspect this evidence as part of its reasoning process. It is not limited to pre-digested summaries — it can read files, review configuration, and examine tool output directly.

### Capabilities

- Inspect repository evidence and security findings
- Reason about security issues in natural language
- Correlate evidence from multiple sources within a single reasoning context
- Assess exploitability and severity based on repository context
- Identify possible root causes for detected vulnerabilities
- Describe potential attack paths across multiple findings
- Recommend specific, context-aware remediation
- Produce a structured investigation report

### What "Single LLM" Means

- One reasoning process, one general-purpose agent, one prompt-response cycle
- No decomposition into specialist agents
- No agent-to-agent communication or delegation
- No multi-step orchestration where agents produce intermediate outputs consumed by other agents
- The LLM may use the same underlying model family as System C — the architectural difference (single reasoning process vs. multiple specialized processes) is what we want to study, not model quality

### Prohibited

- Multi-agent delegation or orchestration
- Specialized sub-agents with focused instructions
- Iterative agent-to-agent follow-up investigation
- Any architectural feature that distributes reasoning across multiple independent processes

### Strengths

- Single reasoning pass reduces latency and token cost
- No coordination overhead or information loss at agent boundaries
- Full evidence context available simultaneously — no risk of relevant information being excluded by specialization
- All reasoning is coherent within a single context window

### Limitations

- Context-window constraints may limit the amount of evidence that can be processed simultaneously
- No specialized domain expertise — the LLM must apply general reasoning to all investigation areas
- No tool-grounded sub-investigation — the LLM reasons over evidence but does not have role-specific tool access
- Single-pass reasoning may miss connections that iterative investigation would surface

### Outputs

- Structured security investigation report including:
  - Identified issues
  - Evidence basis for each issue
  - Affected components
  - Severity/risk assessment
  - Exploitability analysis
  - Root-cause identification where possible
  - Attack-path descriptions
  - Remediation recommendations

### Fairness Requirements

This baseline must not be deliberately weakened:

- It receives the same repository evidence available to System C
- It receives comparable task instructions
- It may use the same underlying LLM model as System C
- It is prompted to perform the same investigation tasks
- It is not given less time, fewer tokens, or lower-quality prompts to produce a favorable comparison for System C

The comparison between B and C isolates the contribution of multi-agent specialization and orchestration, not differences in evidence access, model quality, or prompt design.

### Evaluation Role

Baseline B is the critical experimental condition for answering RQ1 and RQ2. It determines whether multi-agent specialization provides measurable benefit beyond what a single LLM can accomplish with equivalent evidence. If Baseline B achieves comparable investigation quality to System C, the added complexity of multi-agent orchestration is not justified for the tasks evaluated.

---

## System C — SecureFlow Multi-Agent Investigation

### Definition

System C is the proposed SecureFlow architecture: a multi-agent system where specialized agents, each with focused instructions and role-specific tool access, process structured security evidence through a coordinated pipeline to produce an investigation report.

### Conceptual Pipeline

```
Repository
    → deterministic security analysis
    → structured evidence
    → specialized agents (parallel and sequential)
        → evidence correlation
        → investigation (root-cause, attack-path)
        → risk assessment
        → remediation recommendation
    → structured security report
```

### Architecture

System C is distinguished from Baseline B by the following architectural features:

1. **Role specialization.** Multiple agents, each assigned a specific investigation domain.
2. **Structured agent outputs.** Agents produce intermediate outputs in defined formats that other agents consume.
3. **Deterministic tool grounding.** Agents operate over evidence produced by deterministic security tools, not raw repository content alone.
4. **Cross-source evidence correlation.** A dedicated process links findings from different security sources into unified investigation signals.
5. **Agent-to-agent delegation.** The orchestrator assigns investigation tasks to appropriate agents and assembles their outputs.
6. **Iterative follow-up.** Agents can request additional evidence or clarification from other agents or tools.
7. **Risk assessment.** A dedicated agent evaluates and prioritizes findings based on context.
8. **Remediation reasoning.** A dedicated agent produces context-specific remediation recommendations.

### Agent Roles

The following roles are defined by purpose, not by implementation class. Multiple agents may use the same underlying LLM. Agents are software components with specialized instructions, tools, state, and structured interfaces — they are not separate trained neural networks.

#### Orchestrator

- **Purpose:** Coordinate the investigation pipeline. Receive the initial investigation request, determine which agents to invoke, pass evidence to appropriate agents, assemble results, and produce the final report.
- **Relevant evidence:** Repository metadata, initial security-tool findings, agent intermediate outputs.
- **Type of reasoning:** Task decomposition, delegation decisions, result integration.
- **Expected output:** Investigation plan, assembled investigation report.

#### Code Security Agent

- **Purpose:** Investigate source-code-level security findings. Analyze SAST results, review code patterns, assess whether flagged issues are genuine vulnerabilities, and identify code-level root causes.
- **Relevant evidence:** SAST findings, source code files, code diffs, Git history.
- **Type of reasoning:** Code-level vulnerability analysis, pattern recognition, contextual severity assessment.
- **Expected output:** Code-security findings with evidence, severity, root-cause assessment, and remediation guidance.

#### Dependency Agent

- **Purpose:** Investigate dependency-related security findings. Analyze dependency manifests, review known vulnerabilities, assess whether vulnerable dependencies are actually reachable in the application, and identify dependency-chain root causes.
- **Relevant evidence:** Dependency scan results, package manifests, lock files, source code references to dependencies.
- **Type of reasoning:** Dependency reachability analysis, version assessment, transitive dependency analysis.
- **Expected output:** Dependency findings with reachability evidence, severity, and upgrade/remediation guidance.

#### CI/CD Agent

- **Purpose:** Investigate CI/CD pipeline configuration for security issues. Analyze workflow permissions, secret handling, action versions, and pipeline logic for misconfigurations or exploitable patterns.
- **Relevant evidence:** CI/CD workflow files, action definitions, permission configurations, secret references.
- **Type of reasoning:** Configuration analysis, permission assessment, pipeline-security pattern recognition.
- **Expected output:** CI/CD configuration findings with evidence, severity, and configuration-change recommendations.

#### Investigation Agent

- **Purpose:** Correlate findings from multiple sources, trace attack paths across different finding types, and identify connections that domain-specific agents may not see. This agent operates at the cross-source level.
- **Relevant evidence:** Outputs from Code Security, Dependency, and CI/CD agents; repository structure; Git history.
- **Type of reasoning:** Cross-source correlation, attack-path construction, multi-finding relationship analysis.
- **Expected output:** Correlated findings, attack-path descriptions, cross-source relationships, root-cause analysis spanning multiple domains.

#### Risk Agent

- **Purpose:** Assess and prioritize findings based on contextual factors: exploitability, exposure, business impact, fix difficulty, and relationships to other findings.
- **Relevant evidence:** All agent findings, correlated findings from the Investigation Agent, repository context.
- **Type of reasoning:** Risk scoring, prioritization, contextual severity adjustment.
- **Expected output:** Prioritized finding list with risk scores and prioritization rationale.

#### Remediation Agent

- **Purpose:** Produce specific, actionable remediation recommendations for each finding or correlated finding group, tied to the repository's actual code, configuration, and architecture.
- **Relevant evidence:** All findings, risk assessment, repository code and configuration.
- **Type of reasoning:** Fix recommendation generation, code-level remediation guidance, configuration change specification.
- **Expected output:** Remediation recommendations with specific code changes, configuration changes, or dependency updates.

### Capabilities

- Process repository evidence through domain-specialized reasoning
- Correlate findings across security sources (code, dependencies, CI/CD, secrets)
- Trace attack paths that span multiple finding types
- Assess risk in context rather than relying solely on tool-assigned severity
- Produce investigation reports with evidence-linked findings, root causes, and remediation guidance
- Support follow-up investigation where agents can request additional evidence

### Outputs

- Structured security investigation report including:
  - Identified issues with evidence
  - Affected components
  - Severity/risk assessment with contextual prioritization
  - Exploitability analysis
  - Root-cause identification
  - Cross-source attack-path descriptions
  - Remediation recommendations with specific guidance
  - Confidence levels where applicable

### Evaluation Role

System C is the proposed system under evaluation. It is compared against Baseline A and Baseline B on investigation quality, cost, and robustness metrics. It is also the subject of ablation studies that isolate individual architectural contributions (specialization, correlation, tool grounding).

---

## Fair Comparison Principles

### Common Controlled Inputs

Where appropriate, the following are held constant across experimental conditions:

- **Same repository.** All systems analyze the same repository at the same commit or PR.
- **Same vulnerability scenarios.** Evaluation repositories contain known, ground-truth-labeled vulnerabilities.
- **Same ground-truth labels.** All systems are evaluated against the same reference labels for detection and investigation quality.
- **Same evaluation task.** Systems perform the same investigation task on the same input.
- **Same deterministic-tool evidence.** Where Baseline B or System C uses tool output, the tool output is produced by the same tools at the same version on the same repository.
- **Same model family where practical.** Where AI-based systems are compared (B vs C), the same underlying LLM model is used if practical. This isolates the architectural difference from model quality differences.
- **Equivalent task instructions where practical.** Baseline B receives investigation instructions comparable in scope and detail to those given to System C's agents.

### Where Inputs Should Not Be Identical

Not every input should be identical across all three systems. Baseline A is fundamentally a deterministic toolchain and cannot consume or produce LLM reasoning. It operates on different inputs (repository files directly, not natural-language instructions) and produces different output types (tool reports, not investigation narratives). The fairness principle is: **compare each system under conditions that isolate the architectural difference being studied, without artificially handicapping any system.**

### Confounding Factors

The following factors may confound experimental results and should be controlled, documented, or accounted for in experimental methodology:

- **Different LLM models.** If B and C use different models, architectural comparisons are confounded by model quality. Prefer using the same model family.
- **Different prompts.** If B and C receive different instructions, differences may be attributable to prompt quality rather than architecture. Use comparable investigation instructions.
- **Different amounts of evidence.** If C's agents receive evidence that B does not (or vice versa), the comparison is confounded. Ensure evidence access is equivalent where the experiment requires it.
- **Different tool access.** If C's agents have access to tools that B does not, the comparison is confounded by tool access, not architecture. Document any necessary differences.
- **Context-window differences.** If the LLM model used for B has a different context window than the model(s) used for C's agents, evidence processing may differ for technical reasons unrelated to architecture.
- **Stochastic model behavior.** LLM outputs vary across runs. Experiments should use controlled temperature settings, report variance, and run sufficient repetitions for statistical reliability.
- **Different number of LLM calls.** System C makes multiple agent calls; Baseline B makes one. Differences may be attributable to repeated reasoning opportunities rather than specialization. This is a known confounder that should be documented.
- **Tool configuration differences.** If deterministic tools are configured differently across conditions, results are confounded. Use identical tool configurations.

Not every confounder can be fully eliminated. The goal is to identify them, control what can be controlled, and document what cannot.

---

## Primary Experimental Conditions

### Condition A — Traditional Security Tools

A repository is processed by deterministic security tools. Raw findings are presented without AI-based analysis. This condition measures detection capability and the baseline quality of tool output that developers currently receive.

### Condition B — Single-LLM Investigation

A repository and its security-tool findings are processed by a single general-purpose LLM in one reasoning pass. The LLM receives the same evidence available to System C and produces a structured investigation report.

### Condition C — SecureFlow Multi-Agent

A repository is processed through the full SecureFlow pipeline: deterministic tools, specialized agents, evidence correlation, investigation, risk assessment, and remediation recommendation.

### Comparison Logic

| Comparison | What it isolates |
|---|---|
| **A vs B** | Whether LLM reasoning adds value beyond raw deterministic findings |
| **B vs C** | Whether multi-agent specialization and orchestration adds value beyond a single LLM |
| **A vs C** | Whether the complete SecureFlow approach produces more useful investigation than traditional tooling |

**Important:** The A vs C comparison alone cannot attribute any improvement to multi-agent architecture specifically. Only the B vs C comparison isolates the multi-agent contribution. A vs C is useful for establishing whether the full system is practically better than the current state of practice, but it conflates the contribution of LLM reasoning with the contribution of multi-agent architecture.

---

## Candidate Ablations

The following ablations are experimental variants of System C that isolate specific architectural components. They should only be implemented when the corresponding evaluation phase requires them. Not all ablations may be implemented — the set should be narrowed based on feasibility and relevance to the research questions.

### Ablation 1 — Without Cross-Source Correlation

**Purpose:** Evaluate RQ3 (cross-source evidence correlation).

System C operates without the Investigation Agent's cross-source correlation step. Domain-specific agents produce their findings independently, and these findings are assembled without explicit linking across sources. This tests whether explicit correlation improves root-cause identification and attack-path tracing compared with independent analysis.

**Expected comparison:** System C (with correlation) vs System C (without correlation).

### Ablation 2 — Without Deterministic Tool Grounding

**Purpose:** Evaluate RQ4 (deterministic tool grounding).

System C's agents operate without deterministic security-tool evidence. Agents receive repository source code and configuration directly but not the structured output from SAST, dependency scanning, secret detection, or config analysis. This tests whether grounding agent reasoning in tool output improves factual accuracy and reduces hallucination.

**Expected comparison:** System C (grounded) vs System C (ungrounded).

### Ablation 3 — Non-Specialized / Generalist Agent Configuration

**Purpose:** Evaluate RQ2 (agent specialization).

System C operates with a single general-purpose agent that receives all evidence and performs all investigation tasks, rather than decomposing work across specialized agents. This agent has access to the same tools and evidence as the specialized agents but processes them in a single reasoning context. This tests whether specialization improves outcomes compared with a generalist approach.

**Expected comparison:** System C (specialized agents) vs System C (generalist agent) vs Baseline B.

**Note:** This ablation overlaps with Baseline B but differs in that the generalist agent may still use System C's tooling and multi-step orchestration without specialization. The distinction should be carefully documented.

### Ablation 4 — Reduced Delegation / No Follow-Up

**Purpose:** Determine whether iterative agent interaction contributes to investigation quality.

System C operates without iterative follow-up between agents. Each agent produces its output in a single pass with no ability to request additional evidence or clarification from other agents. This tests whether the iterative interaction between agents contributes to investigation quality beyond what single-pass specialization achieves.

**Expected comparison:** System C (with follow-up) vs System C (without follow-up).

---

## Prompt-Injection Conditions

### Purpose

Evaluate RQ6 (prompt injection resistance) by exposing the AI-based experimental conditions to adversarial repository content.

### Attack Locations

Prompt-injection payloads may be embedded in:

- README files and documentation
- Source-code comments
- Commit messages
- Test file names and content
- Configuration file comments
- Variable names and string literals designed to influence LLM reasoning

### Experimental Design

Each AI-based condition (B and C) is evaluated on two versions of the same repository:

1. **Clean repository.** No adversarial content. Establishes baseline investigation quality.
2. **Adversarial repository.** Identical repository with controlled prompt-injection payloads added to repository content.

The comparison measures the effect of adversarial content on investigation output.

### What to Measure

- **Finding suppression.** Does the injection cause the system to miss or dismiss real vulnerabilities?
- **Incorrect conclusions.** Does the injection cause the system to generate false findings or misrepresent findings?
- **Report integrity.** Does the injection alter the structure or reliability of the investigation report?
- **Investigation accuracy.** Does investigation quality degrade under adversarial conditions?
- **Attack success rate.** What fraction of injected payloads successfully influence the system's output?

### What Not to Claim

- No system should be claimed to be prompt-injection resistant based on未经验证的假设.
- The evaluation should identify which injection vectors succeed and which fail, not assume resistance.
- Architectural differences (e.g., agent isolation, structured evidence boundaries) may affect susceptibility, but this must be demonstrated empirically.

---

## Output Comparability

### Purpose

To compare investigation outputs across systems fairly, results from all three systems must eventually be mapped to a common output structure. The exact implementation schema will be defined in a later engineering step.

### Common Output Dimensions

Each system's output should eventually be evaluable along the following dimensions:

| Dimension | Description |
|---|---|
| Identified issue | What security issue was found |
| Evidence | What evidence supports this finding |
| Affected component | Which file, dependency, workflow, or configuration is affected |
| Severity / risk | How severe the issue is (tool-assigned or agent-assessed) |
| Exploitability | Whether the issue is exploitable in context |
| Root cause | Why the issue exists |
| Attack path | How the issue relates to other findings in a potential attack chain |
| Remediation | How to fix the issue |
| Confidence | How confident the system is in the finding |

### Mapping Challenges

Not all systems naturally produce all dimensions:

- **Baseline A** produces tool findings with severity and location but typically lacks root-cause analysis, attack-path description, and context-specific remediation. These dimensions are either absent or limited to tool-generic guidance.
- **Baseline B** produces a full investigation report but may not distinguish between tool-grounded findings and LLM-generated claims.
- **System C** produces a structured report with explicit evidence links but the report format may differ from B.

The evaluation must distinguish between:

1. **What a system actually produces.** Raw output in its native format.
2. **What can be derived objectively from its output.** Structured fields that can be extracted or mapped programmatically.
3. **What requires human or rater assessment.** Qualitative dimensions like remediation quality, report clarity, or actionability.

---

## Reproducibility Requirements

Every experimental run should record the following to ensure reproducibility and auditability:

### Repository and Version

- Repository identifier (owner/name or local path)
- Commit SHA or PR identifier
- Repository snapshot or clone instructions

### Tool Configuration

- Security-tool names and versions
- Tool configuration parameters and rulesets
- Tool invocation mode (default, strict, custom)

### AI Configuration

- LLM model identifier (e.g., model name and version)
- Model provider and API endpoint
- Prompt template or version identifier
- Temperature and other generation settings
- Maximum token limits
- System prompt or agent instruction version

### Agent Configuration

- Agent roles and their assignment (for System C)
- Agent-to-agent communication graph
- Tools available to each agent
- Orchestration sequence and delegation rules

### Execution Context

- Experimental condition (A, B, C, or ablation)
- Evaluation task identifier
- Date and time of execution
- Computational environment (local, cloud, container)

### Resource Usage

- Total token usage (input and output tokens per call, aggregated)
- API cost per investigation (where measurable)
- End-to-end latency (wall-clock time)
- Number of LLM invocations (for B and C)

### Randomness

- Random seed where applicable
- Number of repetitions per condition
- Variance across repetitions (for stochastic outputs)

### Output

- Full system output in its native format
- Mapped output in common evaluation format (where applicable)
- Evaluation scores per dimension

---

## Research Question Traceability

| Research Question | Experimental Comparison | Primary Conditions |
|---|---|---|
| RQ1 — Multi-Agent Investigation Quality | System C vs Baseline B vs Baseline A | All three conditions on same repositories |
| RQ2 — Agent Specialization | System C (specialized) vs System C (generalist) vs Baseline B | Ablation 3 and Baseline B |
| RQ3 — Cross-Source Evidence Correlation | System C (with correlation) vs System C (without correlation) | Ablation 1 |
| RQ4 — Deterministic Tool Grounding | System C (grounded) vs System C (ungrounded) vs Baseline B (ungrounded) | Ablation 2 and Baseline B variant |
| RQ5 — Investigation Cost and Complexity | System C vs Baseline B vs Baseline A (cost and latency measurement) | All three conditions |
| RQ6 — Prompt Injection Resistance | System C vs Baseline B under adversarial input | Adversarial repository variants |

---

## Experimental Non-Goals

The following are explicitly excluded from the experimental design to maintain focus:

- **Comprehensive vulnerability detection benchmarking.** SecureFlow is not evaluated as a vulnerability scanner. Detection completeness is not a primary metric.
- **Large-scale human-subject studies.** The initial evaluation uses automated metrics and controlled benchmarks, not human studies.
- **Production-scale repository evaluation.** Experiments use controlled repositories with known vulnerabilities, not production repositories at scale.
- **Cross-model generalization.** Findings are specific to the LLM model(s) used. Generalization to other models is not claimed.
- **Longitudinal evaluation.** The system is evaluated on static snapshots, not on evolving repositories over time.
- **Full compliance evaluation.** Regulatory compliance is out of scope for experimental evaluation.
- **Runtime security evaluation.** The system analyzes source code and configuration, not running deployments.
- **Training or fine-tuning.** No foundation model training or fine-tuning is performed. Experiments use existing models via API.

---

## Implementation Status

### Baseline A — implemented (Step 27)

Baseline A is implemented and measured as `src/evaluation/baseline_a.py`:
it runs the deterministic offline scanner layer (Bandit + CI/CD analyzer) over
the Step 26 vulnerability corpus and scores it against that corpus's ground
truth. See `docs/benchmark-design.md` → *Step 27* for the matching policy,
metrics, and observed results.

- Reproduce: `python -m src.evaluation.baseline_a`
- Artifact: `evaluation/results/baseline_a.json`
- Observed (offline): TP = 4, FP = 3, FN = 3; precision = recall = 0.5714.
  Semgrep (not installed) and the OSV dependency analyzer (network-only) are
  recorded as unavailable; their categories are reported as false negatives.

Baseline B and System C remain future comparison arms and are not yet executed.
