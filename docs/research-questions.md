# SecureFlow Research Questions

## Research Objective

This research investigates whether a specialized multi-agent architecture, operating over structured security evidence produced by deterministic tools, can improve the quality of automated software-security investigation compared to traditional tool output and a single general-purpose LLM receiving equivalent evidence.

The research is designed to produce evidence that could support or contradict the hypothesis, depending on the experimental results.

## Primary Research Question

### RQ1 — Multi-Agent Investigation Quality

**Question:** Does a specialized multi-agent architecture improve the quality of automated software-security investigation compared with a single general-purpose LLM receiving equivalent evidence?

**Motivation:** The core contribution of SecureFlow is the claim that decomposing security investigation into specialized, composable agents — each operating over structured evidence — produces better investigation than a single LLM processing the same information. If a single LLM achieves comparable results, the additional orchestration complexity of multiple agents is not justified. If traditional tool output alone is sufficient, the entire AI-assisted approach requires re-evaluation.

**Hypothesis:** The multi-agent system produces investigation reports that are more accurate in root-cause identification, more complete in attack-path tracing, more precise in false-positive reduction, and produce more actionable remediation recommendations than either the single-LLM baseline or traditional security-tool output on the same evaluation tasks.

**What would support the hypothesis:**
- The multi-agent system achieves higher root-cause identification accuracy than the single-LLM baseline on controlled evaluation repositories.
- The multi-agent system identifies attack paths and cross-source correlations that neither the single LLM nor traditional tools surface.
- Remediation recommendations from the multi-agent system are rated as more specific, more actionable, and more appropriately prioritized than those from either baseline.
- The multi-agent system achieves lower false-positive rates without sacrificing recall compared to both baselines.

**What would contradict or fail to support the hypothesis:**
- The single LLM, receiving equivalent evidence and comparable instructions, achieves statistically comparable or better investigation quality on the same tasks.
- The multi-agent system produces investigation reports that are no more accurate or actionable than traditional tool output presented clearly to a developer.
- Agent specialization introduces coordination failures that degrade overall investigation quality below the single-LLM baseline.
- Any quality improvement achieved by the multi-agent system is marginal and does not justify the added latency, cost, and complexity.

**Evaluation direction:** Compare all three systems (A: traditional tools, B: single LLM, C: multi-agent) on a controlled set of repositories with known vulnerabilities. Evaluate investigation quality metrics independently for each system on the same tasks.

**Relevant metrics:** Root-cause identification accuracy, false-positive rate, recall for vulnerability-related findings, attack-path identification completeness, remediation quality, investigation report actionability.

**Required comparison:** System C (multi-agent) versus System B (single LLM) on the same repositories and evidence. System C versus System A (traditional tools) for the subset of tasks where traditional tools provide a meaningful baseline.

---

## Secondary Research Questions

### RQ2 — Agent Specialization

**Question:** Does decomposing security analysis into role-specialized agents improve investigation outcomes compared with a single general-purpose agent operating over the same evidence?

**Motivation:** SecureFlow assigns distinct roles to agents (e.g., dependency analysis, CI/CD configuration analysis, code security analysis) and allows each to operate with focused context. Specialization reduces irrelevant context per agent and enables role-specific tooling, but introduces coordination overhead and potential information loss at agent boundaries. Whether the benefits of focused context outweigh these costs depends on the task.

**Hypothesis:** Role-specialized agents produce more accurate and complete findings within their domain than a single general-purpose agent receiving all evidence simultaneously, because focused context reduces noise and improves domain-specific reasoning.

**What would support the hypothesis:**
- Specialized agents correctly identify domain-specific issues that the single general-purpose agent misses or mischaracterizes.
- Agent outputs within their specialization achieve higher precision and recall than the generalist agent's equivalent analysis.

**What would contradict or fail to support the hypothesis:**
- The general-purpose agent achieves comparable or better performance on domain-specific investigation tasks.
- Information lost at agent boundaries (e.g., a dependency finding that is relevant to CI/CD analysis) results in investigation gaps that the generalist agent does not have.
- Coordination overhead introduces errors that degrade overall investigation quality.

**Evaluation direction:** Compare the multi-agent system's domain-specific outputs against the single-LLM baseline's outputs on the same investigation tasks. Also compare against an ablation where agents are given all evidence rather than their specialized subset.

**Relevant metrics:** Domain-specific precision and recall, false-negative rate per investigation area, information loss at agent boundaries, coordination error rate.

**Required comparison:** System C (multi-agent) versus System B (single LLM) on domain-specific subtasks. Within-system comparison of specialized versus non-specialized agent configurations.

---

### RQ3 — Cross-Source Evidence Correlation

**Question:** Does explicitly correlating findings from multiple security sources improve root-cause identification and attack-path tracing compared with analyzing each source independently?

**Motivation:** A central claim of the problem definition is that disconnected findings are a primary cause of developer investigation burden. If the system explicitly links a vulnerable dependency to a CI workflow that exposes it, or connects a secret leak to a Docker configuration issue, this should improve root-cause accuracy and attack-path identification compared with treating each finding in isolation.

**Hypothesis:** Explicit cross-source correlation produces more accurate root-cause identification and more complete attack-path descriptions than analyzing each security source independently, because related findings become visible as a unified signal.

**What would support the hypothesis:**
- The correlation process identifies relationships between findings from different sources that independent analysis does not surface.
- Root-cause identification accuracy improves when correlation is performed versus when findings are analyzed independently.
- Attack-path descriptions produced with correlation include more steps and more accurately reflect the actual exploit chain.

**What would contradict or fail to support the hypothesis:**
- Explicit correlation produces no measurable improvement in root-cause identification over independent source analysis.
- Correlation generates false connections between unrelated findings, reducing precision without improving recall.
- The single-LLM baseline, given all findings simultaneously, implicitly performs adequate correlation without a dedicated correlation step.

**Evaluation direction:** Compare investigation outputs produced with explicit cross-source correlation against outputs produced from independent source analysis on the same repositories. Use repositories with known multi-source vulnerability patterns.

**Relevant metrics:** Root-cause identification accuracy, attack-path completeness and accuracy, false-positive rate for correlated findings, precision of cross-source connections.

**Required comparison:** System C with correlation versus System C without correlation (ablation). System C versus System B, where System B receives all findings simultaneously and must implicitly correlate.

---

### RQ4 — Deterministic Tool Grounding

**Question:** Does grounding LLM agent reasoning in deterministic security-tool evidence improve investigation reliability compared with LLM-driven analysis that does not rely on structured tool output?

**Motivation:** The design principle that LLMs should reason over evidence rather than replace deterministic tools implies that tool-grounded investigation should be more reliable than LLM-only investigation. However, this has not been empirically established for the specific architecture proposed. It is possible that LLMs perform adequately without tool grounding for certain investigation tasks, or that the structure of tool output constrains agent reasoning in unhelpful ways.

**Hypothesis:** Agent reasoning grounded in deterministic tool output produces investigation results that are more factually accurate and less prone to hallucinated findings than LLM-driven analysis without tool grounding, because the structured evidence provides verifiable anchors for agent reasoning.

**What would support the hypothesis:**
- Tool-grounded agents produce fewer hallucinated findings (findings with no corresponding tool evidence) than the ungrounded baseline.
- Factual accuracy of investigation claims is higher when grounded in tool output.
- Deterministic tool findings correctly flag issues that the ungrounded LLM fails to identify.

**What would contradict or fail to support the hypothesis:**
- Ungrounded LLM analysis achieves comparable factual accuracy on the same tasks.
- Tool grounding constrains agent reasoning in ways that cause it to miss issues the LLM would otherwise identify.
- The structure of tool output introduces noise or formatting artifacts that degrade agent performance.

**Evaluation direction:** Compare investigation outputs from tool-grounded agents against outputs from LLM analysis without tool grounding on the same repositories. Measure factual accuracy against ground truth.

**Relevant metrics:** Hallucination rate, factual accuracy of investigation claims, recall for tool-detectable vulnerabilities, false-negative rate.

**Required comparison:** System C (tool-grounded) versus a variant of System C without deterministic tool evidence. System C versus System B when System B does not receive tool output.

---

### RQ5 — Investigation Cost and Complexity

**Question:** Do improvements in investigation quality achieved by the multi-agent system justify the additional latency, token usage, and computational cost introduced by multi-agent orchestration?

**Motivation:** Multi-agent systems are more expensive to operate than single-LLM or traditional tool approaches. Each agent invocation consumes tokens, introduces latency, and adds orchestration overhead. If the quality improvement is marginal, the cost may not be justified. This question quantifies the trade-off and determines whether the efficiency cost is proportional to the quality benefit.

**Hypothesis:** When investigation quality improvements are substantial, the additional cost is proportional and justified; when quality improvements are marginal, the cost increase is disproportionate and the multi-agent approach is less practical.

**What would support the hypothesis:**
- Measurable investigation quality improvements on key metrics are accompanied by cost increases within a reasonable range.
- The cost-per-quality-improvement ratio compares favorably to alternative approaches (e.g., human investigation time).

**What would contradict or fail to support the hypothesis:**
- Quality improvements are marginal while cost increases are substantial.
- The single-LLM baseline achieves comparable quality at significantly lower cost.
- Orchestration latency makes the system impractical for time-sensitive investigation workflows.

**Evaluation direction:** Measure token usage, API cost, and wall-clock latency for each system on the same evaluation tasks. Compare against investigation quality metrics to determine whether the cost-quality trade-off is favorable.

**Relevant metrics:** Total token usage per investigation, API cost per investigation, end-to-end latency, quality-improvement-per-token ratio, quality-improvement-per-dollar ratio.

**Required comparison:** System C versus System B versus System A, measuring both quality and cost on the same tasks.

---

### RQ6 — Prompt Injection Resistance

**Question:** How do different AI-based investigation approaches respond to prompt injection and malicious content embedded in repository source code, comments, or documentation?

**Motivation:** SecureFlow processes untrusted repository content as input to language models. If the system can be manipulated by prompt injection — for example, causing it to suppress a finding, misrepresent risk, or generate a misleading report — the investigation output cannot be trusted. This question evaluates robustness across different architectural configurations, not just the multi-agent system.

**Hypothesis:** Systems that isolate untrusted content within structured evidence boundaries and apply content-handling policies are less susceptible to prompt injection than systems that process raw repository content directly through LLM reasoning.

**What would support the hypothesis:**
- Structured evidence processing (tool output normalization) reduces prompt-injection success rates compared with raw content processing.
- Agent isolation (each agent receives a bounded subset of content) reduces the blast radius of a successful injection.

**What would contradict or fail to support the hypothesis:**
- All AI-based approaches are equally susceptible to prompt injection regardless of architectural configuration.
- The multi-agent architecture introduces additional attack surface (e.g., injection propagates through agent communication) that increases vulnerability.
- Deterministic tool processing does not neutralize injection attempts embedded in source code.

**Evaluation direction:** Introduce known prompt-injection payloads into repository content across evaluation repositories. Measure the effect on investigation output accuracy, report integrity, and finding suppression for each system.

**Relevant metrics:** Prompt-injection success rate, finding suppression rate under attack, report integrity score, type of successful injection vectors.

**Required comparison:** System C versus System B, both exposed to identical adversarial repositories. System C with content isolation versus System C without.

---

## Research Question to Evaluation Mapping

| Question | Main comparison | Key evidence dimension |
|---|---|---|
| RQ1 — Multi-Agent Investigation Quality | System C vs. System B vs. System A | Root-cause accuracy, false-positive rate, remediation quality, attack-path completeness |
| RQ2 — Agent Specialization | System C vs. System B on domain-specific tasks | Domain-specific precision/recall, information loss at boundaries |
| RQ3 — Cross-Source Evidence Correlation | System C with correlation vs. System C without, vs. System B | Root-cause accuracy, attack-path completeness, cross-source connection precision |
| RQ4 — Deterministic Tool Grounding | System C (grounded) vs. System C (ungrounded) vs. System B (ungrounded) | Hallucination rate, factual accuracy, recall for tool-detectable issues |
| RQ5 — Investigation Cost and Complexity | System C vs. System B vs. System A | Token usage, API cost, latency, cost-quality ratio |
| RQ6 — Prompt Injection Resistance | System C vs. System B under adversarial input | Injection success rate, finding suppression, report integrity |

## Research Assumptions and Boundaries

- **Same evidence baseline.** Where appropriate, systems being compared operate on the same repository and the same deterministic-tool output. Differences in investigation quality are attributable to the reasoning architecture, not to differences in input.
- **Single-LLM baseline is not weakened.** System B receives the same evidence, comparable instructions, and equivalent model access as System C's agents. It is not deliberately handicapped to produce a favorable comparison for the multi-agent system.
- **Traditional tools are evaluated fairly.** System A is evaluated on the tasks traditional tools are designed to perform (detection, scanning). It is not penalized for failing at tasks that require reasoning, which is outside its design scope.
- **Results may show no advantage.** The research is designed to be capable of producing evidence that the multi-agent system provides no meaningful improvement over simpler approaches. This is a valid and informative outcome.
- **Results are expected to be task-dependent.** Investigation quality improvements, if any, are likely to vary across different types of repositories, vulnerability patterns, and investigation tasks. A single aggregate score is insufficient; task-level analysis is necessary.
- **Evaluation is reproducible.** Experiments use publicly available repositories, standard security tools, and documented LLM API access. Results include cost and token measurements for transparency.
- **No foundation model training.** The research evaluates existing LLMs accessed via API, not custom-trained or fine-tuned models. Findings about investigation quality are specific to the models used and may not generalize to other models.

## What This Research Does Not Attempt to Prove

- That multi-agent systems are universally superior to single-agent systems for security tasks.
- That LLMs are universally better than traditional security tools for all security activities.
- That SecureFlow detects all or most vulnerabilities in a given repository.
- That one evaluation benchmark can represent the full complexity of real-world software security.
- That results obtained with specific LLMs, repositories, and tools will automatically generalize to all other models, repositories, and environments.
- That the multi-agent architecture is the optimal decomposition for security investigation.
- That AI-assisted security investigation is sufficient without human oversight.
