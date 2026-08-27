# Problem Definition

## 1. Problem Statement

Modern software development produces security signals from many disconnected sources: static analysis tools, dependency scanners, secret detectors, CI/CD pipeline logs, Docker configuration, Git history, and platform-specific alerts. Each tool reports findings independently, often in different formats and at different granularity levels.

This creates a fundamental gap between **detection** and **investigation**. Detection answers whether a potential vulnerability exists. Investigation answers whether it matters: whether it is exploitable in context, how it relates to other findings, what the root cause is, and how it should be fixed. Most current tooling stops at detection and leaves investigation to developers.

The consequences for developers are concrete:

- **Alert fatigue.** High-volume, low-context findings train developers to ignore or dismiss security output, even when critical issues are present.
- **Disconnected findings.** A vulnerable dependency, a misconfigured CI workflow, and an exposed secret in a Dockerfile may each appear as separate alerts, even when they describe a single exploitable attack path.
- **Unclear prioritization.** Without correlation and risk context, developers cannot easily determine which issues to fix first or whether a finding is exploitable in practice.
- **Manual investigation overhead.** Triaging security findings requires manually tracing evidence across source code, configuration, version history, and tool output — a time-consuming process that does not scale.
- **Incomplete remediation.** Fixing a symptom without understanding root cause can leave the underlying issue in place or introduce new problems.

The core problem is not that security tools fail to detect vulnerabilities. It is that raw detection output is insufficient to support developer decision-making. There is a need for systems that can aggregate, correlate, and reason over security evidence to produce actionable investigation.

## 2. Problem Scope

SecureFlow is designed to investigate software repositories and their CI/CD pipelines. The scope of investigation includes:

**In scope:**

- Source code (application logic, configuration, infrastructure-as-code)
- Software dependencies (direct and transitive, including known vulnerabilities)
- CI/CD pipeline configuration (GitHub Actions workflows, pipeline logic, permissions)
- Container and deployment configuration (Dockerfiles, compose files, deployment manifests)
- Git history and diffs (commit messages, change patterns, recent modifications)
- Security-tool findings (static analysis, dependency scanning, secret detection results)

The primary input is a GitHub repository, optionally scoped to a specific pull request or commit range. The system analyzes the repository and its associated CI/CD metadata, not a running deployment.

**Out of scope for the initial prototype:**

- Runtime application testing (DAST, IAST, penetration testing)
- Cloud infrastructure post-deployment analysis
- Network traffic analysis or monitoring
- Real-time incident response
- Compliance framework evaluation (SOC 2, HIPAA, PCI-DSS)
- Binary analysis or compiled artifact inspection
- Non-GitHub hosting platforms

Defining these boundaries is important because it determines what evidence the system can reliably obtain and what it must explicitly exclude from its analysis.

## 3. Proposed Solution

SecureFlow is an AI-assisted security investigation system built on two complementary layers: **deterministic security tools** and **specialized AI agents**.

**Deterministic tools** perform tasks where they are more reliable than a language model: static analysis, dependency scanning, secret detection, and configuration linting. These tools produce structured, reproducible output that serves as the evidentiary foundation for investigation.

**Specialized AI agents** — each with a defined role, focused instructions, and access to relevant tools — reason over the structured evidence produced by deterministic tooling. Rather than performing security scanning themselves, agents interpret results, identify relationships between findings, assess risk in context, and produce investigation reports with remediation guidance.

This separation is deliberate. Language models are capable of reasoning, summarizing, and generating explanations, but they are not reliable as replacements for deterministic analysis. They can hallucinate findings, miss issues that a scanner would catch, and produce inconsistent results. The design principle is: **LLMs should reason over evidence, not replace the tools that produce it.**

The combination addresses a problem that neither layer solves alone. Deterministic tools produce findings without investigation context. Language models can investigate but are unreliable as primary detection tools. Together, structured tool output gives agents a factual basis, and agent reasoning adds the investigative context that raw findings lack.

## 4. High-Level System Behavior

The intended flow through SecureFlow is:

```
Repository / Pull Request
        │
        ▼
   SecureFlow
        │
        ▼
   Deterministic Security Analysis
   (static analysis, dependency scanning, secret detection, config linting)
        │
        ▼
   Structured Evidence
   (normalised findings, dependency graph, CI config analysis, Git context)
        │
        ▼
   Specialized Agents
        │
        ├──► Evidence Correlation
        │    (linking findings across sources, identifying related signals)
        │
        ├──► Investigation
        │    (tracing attack paths, assessing exploitability, identifying root cause)
        │
        ├──► Risk Assessment
        │    (prioritising findings by severity and context)
        │
        └──► Remediation Recommendation
             (actionable guidance, not just alerts)
        │
        ▼
   Security Report / Developer Decision
```

The developer receives a structured report and can:

- **Accept** the findings and proceed with recommended remediation.
- **Override** the assessment if domain knowledge or business context warrants it.
- **Investigate** further by requesting additional analysis or evidence from the system.

This flow positions SecureFlow as an investigation and decision-support tool, not an autonomous gatekeeper.

## 5. Multi-Agent Rationale

SecureFlow uses multiple specialized agents rather than a single general-purpose agent. The rationale is grounded in observable design trade-offs, not in an assumption that more agents automatically produce better results.

**Specialization advantages:**

- **Focused context.** A dependency agent can receive dependency-specific evidence and instructions without irrelevant context about CI workflows or Docker configuration. This reduces the cognitive load on the model and improves relevance of outputs.
- **Role-specific tooling.** Different agent roles require access to different tools and data. Specialization allows each agent to interact with only the tools relevant to its task.
- **Composability.** Specialized agents produce structured intermediate outputs that other agents can consume. A risk agent can reason over correlated findings produced by an investigation agent, without needing to re-process raw evidence.
- **Testability.** Individual agents can be evaluated independently against domain-specific benchmarks, which is important for a research-oriented system.

**Important caveat:** Agent specialization introduces orchestration complexity, potential coordination failures, and increased token and computational cost compared to a single-agent approach. Whether the benefits of specialization outweigh these costs is a question this project intends to evaluate empirically, not assert a priori.

## 6. Research Contribution and Hypothesis

**Core hypothesis:**

A specialized multi-agent architecture, where each agent has focused instructions, role-specific tool access, and operates over structured security evidence, improves the quality of automated software-security investigation compared to either traditional security-tool output alone or a single general-purpose LLM processing the same evidence.

**What would support the hypothesis:**

- The multi-agent system produces investigation reports with higher accuracy (fewer false positives, more correct root-cause identification, more relevant remediation) than either baseline on a controlled evaluation benchmark.
- The system identifies attack paths and correlations between findings that neither baseline surfaces.
- Developer feedback indicates the multi-agent output is more actionable than baseline output.

**What would contradict the hypothesis:**

- A single LLM with equivalent evidence and prompting performs comparably or better on investigation quality metrics.
- The overhead of multi-agent orchestration (latency, cost, complexity) does not produce meaningfully better outcomes.
- Agent specialization introduces coordination errors that degrade overall investigation quality.
- Deterministic tool output, when presented clearly to a developer, is sufficient without agent-based investigation.

**What this project does NOT claim:**

- That multi-agent systems are inherently superior for security investigation.
- That LLMs can replace deterministic security tooling.
- That the proposed system will detect all or most vulnerabilities.
- That the system eliminates the need for human security expertise.

The research contribution is the systematic evaluation of whether specialization and structured evidence flow improve investigation outcomes in a defined domain.

## 7. Research Baselines

To evaluate SecureFlow meaningfully, the system must be compared against defined baselines, not assessed in isolation.

**Baseline A — Traditional security tools:**

A repository is processed by standard security tooling (static analysis, dependency scanning, secret detection). The output is raw findings presented to a developer without additional analysis or correlation.

This baseline represents the current state of practice for most teams. It establishes the minimum bar: can any AI-assisted system produce investigation that is more useful than the raw tool output developers already receive?

**Baseline B — Single LLM:**

A repository and its security-tool output are processed by a single LLM in a single pass. The LLM receives all available evidence and produces a security report in one step.

This baseline isolates the contribution of the LLM itself, independent of multi-agent architecture. If a single LLM produces comparable investigation quality, the added complexity of specialization is not justified.

**Baseline C — SecureFlow multi-agent system:**

A repository is processed through the full multi-agent pipeline: deterministic tools, specialized agents, evidence correlation, investigation, risk assessment, and remediation recommendation.

Comparison across all three baselines determines whether the multi-agent architecture provides measurable improvement over both traditional tooling and single-LLM approaches on the same evaluation tasks.

## 8. Security and Trust Considerations

SecureFlow processes untrusted repository content — code, comments, documentation, commit messages, and configuration — and uses it as input to language models. This creates adversarial attack surface that must be investigated as part of the research.

**Key concerns:**

- **Prompt injection.** Repository content may contain text designed to manipulate agent behavior, alter outputs, or cause the system to misrepresent findings. This is a well-documented risk when LLMs process external content.
- **Malicious comments and documentation.** Code comments, README files, and documentation may include instructions or misleading context intended to influence agent reasoning.
- **Data poisoning.** Deliberately introduced vulnerabilities or misleading security artifacts could corrupt agent analysis and lead to incorrect conclusions.
- **Conflicting evidence.** Agents may receive contradictory signals from different sources. The system must handle inconsistency without producing unreliable or misleading output.
- **Untrusted content boundaries.** Repository content must be treated as untrusted data at all stages, not as trusted agent instructions. This distinction is critical for system integrity.

These concerns are not implementation details to address later — they are fundamental to the research question. A security investigation system that is vulnerable to manipulation from the very content it analyzes has limited practical value. Prompt-injection resilience and untrusted-content handling should be evaluated as part of the research, not added as afterthoughts.

## 9. Human-AI Collaboration

SecureFlow is designed as a decision-support tool, not an autonomous security gatekeeper. The developer remains in the loop with three primary interaction modes:

- **Accept.** The developer reviews the investigation report and implements the recommended remediation.
- **Override.** The developer uses domain knowledge, business context, or additional information to modify or reject the system's assessment.
- **Investigate.** The developer requests additional analysis, evidence, or explanation from the system before deciding.

This interaction model creates a structured opportunity to study human-AI decision-making in software security:

- How often do developers agree with or override the system's risk assessments?
- Does the system change developer behavior, such as which issues they prioritize or how long they spend investigating?
- What types of findings do developers most and least trust?
- When developers override the system, are they correct?

These questions are secondary to the primary research hypothesis but represent a meaningful extension of the evaluation.

## 10. Initial Success Criteria

For the eventual prototype to be considered successful, it should meet the following criteria:

**Technical functionality:**

- The system can ingest a GitHub repository and produce a structured investigation report without manual configuration beyond repository selection.
- Deterministic security tools run reliably and produce structured output.
- Agents process evidence and produce investigation reports in defined formats.

**Investigation quality:**

- The system identifies relationships between findings from different sources (e.g., linking a vulnerable dependency to a CI workflow that exposes it).
- Root-cause identification is at least as accurate as the single-LLM baseline on evaluation tasks.
- Remediation recommendations are specific, actionable, and tied to identified evidence.

**Measurable evaluation:**

- The system can be evaluated against defined metrics (precision, recall, false-positive rate, root-cause accuracy, remediation quality) on a reproducible benchmark.
- Results are comparable across all three research baselines.

**Security robustness:**

- The system handles untrusted repository content without producing manipulated or misleading output in known prompt-injection test cases.
- Adversarial repository content does not cause the system to misrepresent findings.

**Reproducibility:**

- The evaluation can be reproduced from the repository without access to proprietary infrastructure beyond standard API access.
- Results include token usage, latency, and cost measurements for transparency.

## 11. Non-Goals

The following are explicitly excluded from SecureFlow's scope for the initial prototype. This prevents scope creep and ensures the research remains focused:

- **Training a foundation model.** SecureFlow uses existing language models via API, not custom-trained or fine-tuned models.
- **Replacing all existing security scanners.** SecureFlow uses deterministic tools as evidence sources, not as components to be replaced.
- **Autonomous repository modification.** The system recommends remediation; it does not push changes, create commits, or modify repositories without explicit developer approval.
- **Guaranteeing vulnerability detection.** The system is an investigation and analysis tool, not a comprehensive vulnerability scanner. Detection completeness is not a claim.
- **General-purpose coding assistance.** SecureFlow is focused on security investigation, not code generation, refactoring, or feature development.
- **Runtime or production monitoring.** The system analyzes source code and configuration, not running systems.
- **Compliance auditing.** SecureFlow does not evaluate regulatory compliance (SOC 2, HIPAA, PCI-DSS, etc.).
- **Real-time or continuous analysis.** The initial prototype analyzes a repository on demand, not continuously.
