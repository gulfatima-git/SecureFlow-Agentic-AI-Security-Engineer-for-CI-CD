# SecureFlow Evaluation Methodology

## 1. Evaluation Objective

The evaluation aims to determine whether a specialized multi-agent architecture (System C) improves the quality of automated software-security investigation compared with traditional security-tool output (Baseline A) and a single general-purpose LLM receiving equivalent evidence (Baseline B), and whether any improvement justifies the added complexity and cost.

The evaluation connects directly to the six research questions defined in `docs/research-questions.md`:

- RQ1 is answered by the primary A/B/C comparison on investigation quality.
- RQ2 is answered by comparing specialized versus generalist agent configurations.
- RQ3 is answered by an ablation that removes cross-source correlation.
- RQ4 is answered by an ablation that removes deterministic tool grounding.
- RQ5 is answered by measuring cost and efficiency alongside quality for all conditions.
- RQ6 is answered by exposing AI-based conditions to adversarial repository content.

Evaluating SecureFlow in isolation is insufficient because the research question is comparative, not absolute. A system may appear to produce useful investigation reports, but that does not mean the multi-agent architecture is responsible for the quality. The investigation could be driven entirely by LLM reasoning capabilities that a single-LLM baseline would also possess. Controlled A/B/C comparisons and ablations isolate the contribution of specific architectural decisions.

The evaluation must measure multiple dimensions independently. These dimensions must not be collapsed into a single vague "accuracy" or "quality" score:

| Dimension | What it measures |
|---|---|
| **System capability** | Can the system produce an investigation report at all? |
| **Detection** | Are genuine security issues identified? (Primarily Baseline A.) |
| **Investigation quality** | Are findings validated, correlated, root-caused, and attack-pathed correctly? |
| **Remediation quality** | Are recommended fixes specific, correct, and actionable? |
| **Robustness** | Does adversarial repository content degrade investigation output? |
| **Efficiency** | What does the investigation cost in tokens, latency, and API spend? |

---

## 2. Evaluation Philosophy

The following principles govern how the evaluation is designed and executed. Each is stated as a principle, followed by why it matters.

### Controlled comparison

Every comparison isolates one architectural variable. Systems are compared on the same benchmark case, with identical inputs where the experiment requires it. Differences in output are attributable to the reasoning architecture, not to input differences.

*Why it matters:* Without controlled comparison, results cannot be attributed to any specific architectural decision. An apparent improvement might be caused by better evidence access, a different prompt, or a different model.

### Fair baselines

Baseline A is evaluated on detection tasks it was designed for. Baseline B receives equivalent evidence and comparable instructions. No system is deliberately weakened.

*Why it matters:* A straw-man comparison produces meaningless results. If Baseline B is weakened, any apparent advantage of System C may reflect the handicapping rather than the architecture.

### Evidence parity

Where the experiment compares reasoning architectures (B vs C), both conditions have access to the same repository evidence and deterministic-tool output. Neither condition has access to information the other lacks.

*Why it matters:* If one system receives more or different evidence, the comparison is confounded by information access, not architecture.

### No cherry-picking

Evaluation metrics and benchmark cases are defined before experiments are run. Results are not selectively reported to support a desired conclusion. All benchmark cases and all metrics are reported, including cases where Baseline B or Baseline A outperforms System C.

*Why it matters:* Selective reporting produces misleading conclusions and undermines research credibility.

### No post-hoc modification of evaluation criteria

Evaluation criteria (metrics, scoring rubrics, benchmark case selection) are frozen before final experimental runs. They may be refined during development, but final results are scored against frozen criteria.

*Why it matters:* Changing criteria after seeing results allows unconscious bias to influence what counts as "correct."

### Separation of development and evaluation

Development decisions (prompt tuning, agent configuration, architecture choices) may use a development subset of benchmark cases. Final evaluation runs use cases the system has not been specifically tuned against.

*Why it matters:* If the system is tuned against evaluation cases, results reflect optimization for specific examples, not general capability.

### No ground truth as system input

Ground-truth labels are never provided to any system as input. Systems must produce investigation outputs from repository evidence alone. Ground truth is used only for scoring.

*Why it matters:* If ground truth is available to the system, the evaluation measures whether the system can repeat known answers, not whether it can investigate independently.

### Transparent reporting of failures

Failures are reported alongside successes. The evaluation does not filter out benchmark cases where the system performs poorly.

*Why it matters:* Understanding where a system fails is as important as knowing where it succeeds, especially for a research project.

### Preservation of raw outputs

Raw system outputs are preserved exactly as produced. Normalized or scored versions are derived artifacts, not replacements.

*Why it matters:* Raw outputs allow independent re-evaluation, error analysis, and reproducibility verification.

---

## 3. Evaluation Dataset / Benchmark Design

### Composition

The evaluation benchmark should consist of publicly available repositories or deliberately constructed controlled repositories/scenarios containing security-relevant cases. The benchmark must cover a range of security problem types to avoid over-fitting the evaluation to a single category.

### Category coverage

The benchmark should include cases across the following categories:

| Category | Description | Primary agents involved |
|---|---|---|
| **Source-code vulnerabilities** | SAST-detectable issues: injection, XSS, path traversal, insecure deserialization, etc. | Code Security Agent |
| **Vulnerable dependencies** | Direct and transitive dependencies with known CVEs, including reachable and unreachable cases. | Dependency Agent |
| **CI/CD misconfigurations** | Overly permissive workflow permissions, unpinned actions, secret exposure in pipelines, unsafe script execution. | CI/CD Agent |
| **Secret exposure** | Hardcoded credentials, API keys, tokens in source or configuration. | Code Security Agent, CI/CD Agent |
| **Docker/container configuration** | Running as root, unnecessary capabilities, exposed ports, insecure base images. | Code Security Agent |
| **Multi-source / cross-layer scenarios** | Cases where two or more findings from different sources combine to form an attack path or share a root cause. | Investigation Agent, all domain agents |
| **Benign findings / false-positive cases** | Cases where tools report findings that are not genuine vulnerabilities in context. | All agents |
| **Prompt-injection cases** | Repositories with adversarial content designed to manipulate AI-based investigation. | RQ6 evaluation |

### Why multi-source cases are important

Multi-source cases are critical for evaluating RQ3. A single-source case (e.g., a vulnerable dependency with no contextual exposure) does not test whether cross-source correlation adds value. Cases where a vulnerable dependency, a CI/CD misconfiguration, and a Docker permission issue together form an exploitable chain are necessary to determine whether correlation improves investigation beyond independent source analysis.

### Benchmark case metadata

Each benchmark case should eventually record:

| Field | Description |
|---|---|
| Case identifier | Unique ID for the benchmark case |
| Repository identifier | Owner/name or local path |
| Commit SHA | Exact commit or PR snapshot |
| Vulnerability category | Category from the table above |
| Affected files/components | Which files, dependencies, or workflows are involved |
| Expected security issue | What the ground truth says the vulnerability is |
| Root cause | Why the vulnerability exists |
| Exploitability / context | Whether and how the vulnerability is exploitable in the repository context |
| Attack path | How the vulnerability relates to other findings (where applicable) |
| Expected remediation | What an appropriate fix would be |
| Relevant tool findings | Which deterministic tools should flag this case |
| Multi-source involvement | Whether multiple evidence sources are required |
| Difficulty level | Simple (single-source, clear finding) vs. complex (multi-source, requires correlation) |

---

## 4. Ground Truth Definition

### What ground truth means for SecureFlow

Ground truth is the independently established reference against which system outputs are scored. It represents what a knowledgeable human investigator would conclude about the security state of the repository.

Ground truth is not a single label — it is a structured reference that may include:

| Dimension | Ground truth meaning |
|---|---|
| **Vulnerability existence** | Does the security issue actually exist in the repository? |
| **Affected component / location** | Which file, dependency, or configuration is affected? |
| **Root cause** | Why does the issue exist? (e.g., missing input validation, unpinned dependency, overly permissive workflow) |
| **Exploitability / context** | Is the issue exploitable in this repository's context? Under what conditions? |
| **Attack-path relationships** | Are multiple findings related? Do they form an exploit chain? |
| **Remediation correctness** | What would a correct fix look like? Is there more than one valid fix? |
| **False-positive status** | Is a tool-reported finding a genuine issue or a false positive in this context? |

### Establishing ground truth independently

Ground truth must be established independently from the AI systems being evaluated. Systems must never influence what ground truth says. Possible sources include:

| Source | Strengths | Limitations |
|---|---|---|
| **CVE / GHSA databases** | Authoritative for known vulnerabilities | May not cover repository-specific context, local code issues, or misconfigurations |
| **Security advisories** | Detailed remediation guidance | Not all findings correspond to published advisories |
| **Maintainer fixes** | If the maintainer committed a fix, the issue was likely real | Not all fixes are correct; fixes may address symptoms, not root causes |
| **Controlled vulnerability injection** | Full control over ground truth; can create multi-source scenarios | May not perfectly represent natural vulnerability patterns |
| **Expert-reviewed annotations** | Can cover all ground-truth dimensions including exploitability and root cause | Subjective; requires documented rubric; expensive |
| **Repository history** | Git history may reveal when issues were introduced and fixed | Not all issues are visible in history |

No single source is always sufficient. A combination is typically necessary. For example, a CVE database confirms that a dependency version is vulnerable, but expert annotation is needed to determine whether the vulnerability is reachable in the specific application context.

### Conflicting or uncertain ground truth

Some ground-truth dimensions are inherently ambiguous:

- **Exploitability** may depend on deployment context not visible in the repository.
- **Root cause** may be debatable when multiple contributing factors exist.
- **Remediation** may have multiple valid approaches.
- **Attack paths** may be theoretically possible but practically unlikely.

When ground truth is uncertain:

1. Document the uncertainty and the basis for the best-available judgment.
2. Use a scoring method that allows partial credit for answers that are partially correct.
3. Where possible, have multiple independent annotators establish ground truth and report inter-annotator agreement.
4. Never present uncertain ground truth as definitive.

---

## 5. Dataset Splitting and Leakage Prevention

### Terminology

SecureFlow is not a trained model — it is a system composed of LLMs accessed via API, deterministic tools, and orchestration logic. The standard machine-learning terminology of "train/validation/test" does not directly apply. Instead, the benchmark cases are divided into:

- **Development cases.** Used during system development for prompt tuning, agent configuration, architecture iteration, and debugging. These cases are iterated on repeatedly.
- **Evaluation cases.** Used only for final experimental runs to produce reported results. The system is not specifically tuned against these cases.

### Splitting principles

- Development and evaluation cases should be drawn from different repositories where possible, or from different commits/PRs of the same repository with sufficiently different code.
- The evaluation set should include cases across all benchmark categories.
- The split should be documented and frozen before final experiments.

### Leakage prevention

The following practices prevent evaluation leakage:

1. **No prompt tuning on evaluation cases.** Prompts, agent instructions, and orchestration logic are finalized before evaluation runs begin. If evaluation results reveal a prompt issue, the prompt is fixed and evaluation is re-run from scratch (not patched against specific cases).

2. **No ground truth as system input.** Ground-truth labels are never visible to any system during investigation. They are used only for scoring after outputs are produced.

3. **No test-case descriptions that reveal expected answers.** Benchmark case descriptions do not tell the system what the expected vulnerability is. The system must discover it from repository evidence.

4. **No iterative tuning against evaluation set.** The system is not refined based on evaluation-set performance. Development iteration uses development cases only.

5. **Repository duplication and near-duplicate leakage.** If two benchmark cases are from the same repository (different commits), care must be taken that the system has not seen the specific vulnerability pattern during development. Document any same-repository cases in the evaluation set.

---

## 6. Evaluation Tasks

### Task definitions

Every AI-based system (B and C, and relevant ablations) should perform the following investigation tasks where applicable. Baseline A is evaluated only on the tasks it was designed to perform.

| Task | Description | Applicable to A | Applicable to B/C |
|---|---|---|---|
| **T1 — Finding validation** | Determine whether a reported security finding is a genuine issue or a false positive in this repository's context. | Yes (tool-native confidence) | Yes |
| **T2 — Contextual severity / risk assessment** | Assess practical risk based on repository context rather than copying scanner severity scores. | No (tools provide fixed severity) | Yes |
| **T3 — Root-cause identification** | Identify why the security issue exists, not just that it exists. | No (beyond rule-based) | Yes |
| **T4 — Cross-source correlation** | Determine whether findings from different sources (code, dependencies, CI/CD) are related. | No (no cross-source reasoning) | Yes |
| **T5 — Attack-path reconstruction** | Describe how related findings could form an exploit chain. | No | Yes |
| **T6 — Remediation recommendation** | Provide a specific, technically appropriate fix. | Limited (generic guidance only) | Yes |
| **T7 — Evidence attribution** | Identify the evidence supporting each conclusion. | Yes (tool reports include references) | Yes |
| **T8 — Prompt-injection robustness** | Maintain correct investigation behavior when malicious instructions are embedded in repository content. | N/A (deterministic) | Yes |
| **T9 — Overall investigation report** | Produce a structured, developer-facing report containing the required fields. | No (tools produce finding lists, not reports) | Yes |

### Fair scoring of Baseline A

Baseline A is scored only on tasks where deterministic tools provide meaningful output:

- **T1 (finding validation):** Tool-native confidence scores and rule precision provide partial ground truth for whether findings are genuine.
- **T7 (evidence attribution):** Tool reports reference specific files and line numbers.

Baseline A is **not** scored on T2, T3, T4, T5, T6, or T9, because these require reasoning capabilities the tools were not designed to provide. Scoring Baseline A on these tasks and reporting poor performance would be an invalid comparison.

---

## 7. Common Output / Evaluation Schema

### Conceptual fields

To compare outputs across A, B, C, and ablations, results should be mappable to the following conceptual fields:

| Field | Description | Verifiability |
|---|---|---|
| `finding_id` | Unique identifier for each finding | Objective |
| `issue` | Description of the security issue | Objectively verifiable against ground truth |
| `source` | Which evidence source produced this finding (tool, code review, correlation) | Derivable from output |
| `affected_component` | File, dependency, workflow, or configuration affected | Objectively verifiable |
| `evidence` | Specific evidence supporting the conclusion | Partially verifiable; completeness requires judgment |
| `severity` | Tool-assigned or agent-assessed severity | Scorable against ground truth severity |
| `exploitability` | Whether the issue is exploitable in context | Requires expert judgment |
| `root_cause` | Why the issue exists | Partially verifiable; may have multiple valid answers |
| `related_findings` | IDs of findings this one is linked to | Verifiable against ground-truth relationships |
| `attack_path` | Description of how related findings form an exploit chain | Requires expert judgment; partial credit needed |
| `remediation` | Recommended fix | Partially verifiable; multiple valid fixes possible |
| `confidence` | System's confidence in the finding | Not directly scorable; useful for calibration analysis |
| `uncertainty` | Areas where the system is uncertain | Not directly scorable; useful for failure analysis |

### Field categories

- **Objectively verifiable:** `finding_id`, `issue`, `affected_component`, `severity` (for tool findings), `source`.
- **Partially derivable from tool output:** `evidence` (tool references), `root_cause` (for tool-detectable issues with known fix patterns).
- **Requiring expert or rater judgment:** `exploitability`, `attack_path`, `remediation` quality and actionability, `evidence` completeness, `root_cause` accuracy for complex cases.

### Mapping challenges

Baseline A produces tool finding reports in native formats (SARIF, JSON). These must be mapped to the common schema. The mapping may leave many fields empty (e.g., `root_cause`, `attack_path`, `remediation`) because the tools do not produce them. This is expected and should not be penalized — it reflects the actual capability of the baseline.

---

## 8. Metrics

### Detection-related metrics (primarily for Baseline A, and for validating that AI systems do not miss tool-detectable issues)

| Metric | Definition |
|---|---|
| **Precision** | Of the findings reported, what fraction correspond to genuine issues? |
| **Recall** | Of the genuine issues present, what fraction were reported? |
| **False-positive rate** | Of the issues reported, what fraction are false positives? |
| **False-negative rate** | Of the genuine issues present, what fraction were missed? |

For Baseline A, precision and recall are computed against ground-truth vulnerability existence. For AI systems, detection is assessed as part of finding validation (T1).

### Investigation-related metrics

| Metric | Definition | Scoring notes |
|---|---|---|
| **Finding validation accuracy** | Fraction of findings correctly classified as genuine or false positive. | Binary classification per finding. |
| **Root-cause identification accuracy** | Fraction of findings where the stated root cause matches ground truth. | Exact match may be too strict; partial-credit scoring required for rephrased but equivalent root causes. |
| **Root-cause completeness** | For findings with multiple contributing factors, how many factors are identified. | Fraction of ground-truth factors mentioned. |
| **Attack-path accuracy** | Whether the described attack path matches the ground-truth attack chain. | Sequence of steps may be partially correct; partial credit needed. |
| **Attack-path completeness** | Fraction of ground-truth attack-path steps present in the system's description. | Measured as step-level recall. |
| **Cross-source correlation precision** | Of the cross-source correlations asserted, what fraction are correct? | Only for benchmark cases with multi-source ground truth. |
| **Cross-source correlation recall** | Of the ground-truth cross-source relationships, what fraction were identified? | Only for cases with known cross-source relationships. |
| **Remediation correctness** | Whether the recommended fix would resolve the issue. | Partial credit for directionally correct but incomplete fixes. |
| **Remediation actionability** | Whether the fix is specific enough for a developer to implement without further research. | Requires human or rubric-based rating. |
| **Evidence attribution accuracy** | Whether the cited evidence actually supports the conclusion. | Partially verifiable against ground truth. |
| **Factual consistency** | Whether investigation claims are consistent with the repository evidence. | Claims must not contradict observable facts in the repository. |
| **Hallucination rate** | Fraction of stated findings or claims that have no corresponding evidence in the repository or tool output. | Each hallucinated claim is a false finding. |

### Robustness metrics

| Metric | Definition |
|---|---|
| **Prompt-injection success rate** | Fraction of adversarial payloads that cause a measurable change in investigation output. |
| **Finding suppression rate** | Fraction of genuine findings that the system fails to report under adversarial conditions (but reports under clean conditions). |
| **Incorrect-conclusion rate** | Fraction of conclusions that change from correct (clean) to incorrect (adversarial). |
| **Report-integrity degradation** | Whether the overall structure and completeness of the report degrades under adversarial conditions. |

### Efficiency metrics

| Metric | Definition |
|---|---|
| **Input tokens** | Total input tokens consumed across all LLM calls for one investigation. |
| **Output tokens** | Total output tokens produced across all LLM calls for one investigation. |
| **Total tokens** | Input + output tokens. |
| **Number of LLM calls** | How many separate LLM invocations occurred. |
| **Wall-clock latency** | End-to-end time from receiving the investigation request to producing the final report. |
| **API cost** | Total API spend per investigation (computed from token counts and provider pricing). |
| **Cost per investigation** | Same as API cost; stated explicitly for clarity. |
| **Quality-per-token ratio** | Investigation quality score divided by total tokens consumed. Used for RQ5 cost-quality trade-off analysis. |
| **Quality-per-dollar ratio** | Investigation quality score divided by API cost. Used for RQ5. |

### Metric scoring notes

- **Partial credit:** Attack paths, root causes, and remediation may be partially correct. A binary correct/incorrect scoring is insufficient. Define a rubric (see Section 9) that assigns partial scores.
- **False positives and false negatives:** Counted per finding. A finding is a false positive if the ground truth says the issue does not exist or is not exploitable in context. A false negative is a genuine issue that the system did not report.
- **Hallucination:** A finding or claim is hallucinated if it references evidence, code, or a condition that does not exist in the repository at the evaluated commit. Hallucinated findings count as false positives.
- **Metric aggregation:** Report per-task metrics and per-category metrics separately before computing aggregate scores. Aggregate scores should be clearly identified as summary statistics, not as the primary result.

---

## 9. Human Evaluation / Expert Rating

### Where human evaluation is appropriate

Certain investigation dimensions cannot be reliably evaluated through automated matching:

| Dimension | Why human evaluation is needed |
|---|---|
| **Remediation quality** | A fix may be technically correct but impractical, or may resolve the symptom but not the root cause. Automated matching cannot assess this reliably. |
| **Remediation actionability** | A recommendation may be correct but too vague for a developer to implement. |
| **Root-cause explanation quality** | The root cause may be accurately identified but poorly explained, or may be partially correct. |
| **Attack-path completeness** | An attack path may be partially described; human judgment is needed to assess whether missing steps are important. |
| **Evidence sufficiency** | Whether the cited evidence is sufficient to support the conclusion, given the repository context. |
| **Report usefulness** | Whether the report as a whole would help a developer make a security decision. |

### Structured rating rubric

For each dimension requiring human evaluation, use a structured rubric rather than informal judgment:

**Remediation quality (1–4 scale):**

| Score | Description |
|---|---|
| 1 | Incorrect or harmful recommendation. Would not resolve the issue or would introduce new problems. |
| 2 | Directionally correct but incomplete or impractical. Addresses the symptom but not the root cause. |
| 3 | Correct and implementable. Would resolve the issue with reasonable effort. May not be the optimal approach. |
| 4 | Correct, implementable, and well-justified. Addresses the root cause and explains why the fix is appropriate. |

**Root-cause explanation quality (1–4 scale):**

| Score | Description |
|---|---|
| 1 | Incorrect root cause. |
| 2 | Partially correct. Identifies a contributing factor but not the primary cause. |
| 3 | Correct root cause with adequate explanation. |
| 4 | Correct root cause with detailed explanation that would help a developer understand and prevent recurrence. |

**Attack-path completeness (1–4 scale):**

| Score | Description |
|---|---|
| 1 | No attack path described, or path is incorrect. |
| 2 | Partial path. Identifies some steps but misses critical steps. |
| 3 | Complete path with all critical steps. May miss minor steps. |
| 4 | Complete path with all steps, including conditions and prerequisites. |

### Evaluation protocol

- **Blinded evaluation:** Raters should not know which system (A, B, C, or ablation) produced the output being rated. Outputs are anonymized before presentation to raters.
- **Independent raters:** Where practical, have at least two independent raters evaluate each output. This allows measurement of inter-rater agreement.
- **Inter-rater agreement:** Compute inter-rater reliability (e.g., Cohen's kappa for pairwise agreement, or intraclass correlation for continuous scales). Report agreement levels. Low agreement indicates the rubric needs refinement.
- **Conflict resolution:** When raters disagree, a third rater adjudicates, or raters discuss and reach consensus with documented reasoning.
- **Avoiding knowledge bias:** Raters should not be told what the ground truth is when rating system outputs. They should evaluate the output independently against the repository.

### Scope

This is a student research prototype. Human evaluation should be limited to a representative subset of benchmark cases, not every case. The subset should cover all categories and all systems being compared. Report the sample size and how it was selected.

---

## 10. Ablation Evaluation Methodology

### General principles

Each ablation changes exactly one architectural variable from System C. All other variables remain constant. This ensures that observed differences in output are attributable to the removed component, not to confounding changes.

### Ablation 1 — Without Cross-Source Correlation

| Property | Value |
|---|---|
| **Purpose** | Evaluate RQ3 |
| **What changes** | The Investigation Agent's cross-source correlation step is removed. Domain-specific agents produce findings independently. |
| **What remains constant** | Agent roles, evidence access, deterministic tool grounding, orchestration, follow-up, model, prompts |
| **Primary comparison** | System C (with correlation) vs. System C (without correlation) |
| **Key metrics** | Cross-source correlation precision/recall, root-cause identification accuracy, attack-path completeness |
| **Benchmark cases** | Must include multi-source cases where cross-source relationships exist in ground truth |

### Ablation 2 — Without Deterministic Tool Grounding

| Property | Value |
|---|---|
| **Purpose** | Evaluate RQ4 |
| **What changes** | Agents receive repository source code and configuration directly but not deterministic security-tool output (SAST, dependency scan, secret detection, config analysis results). |
| **What remains constant** | Agent roles, specialization, orchestration, follow-up, model, prompts, evidence source access (files) |
| **Primary comparison** | System C (grounded) vs. System C (ungrounded) |
| **Key metrics** | Hallucination rate, factual accuracy, recall for tool-detectable vulnerabilities |
| **Note** | This ablation also allows comparison against Baseline B when Baseline B does not receive tool output (as in RQ4's full comparison) |

### Ablation 3 — Non-Specialized / Generalist Agent Configuration

| Property | Value |
|---|---|
| **Purpose** | Evaluate RQ2 |
| **What changes** | A single general-purpose agent replaces all specialized agents. It receives all evidence and performs all investigation tasks in a single reasoning context. |
| **What remains constant** | Deterministic tool grounding, evidence access, model, orchestration structure (if any), prompts |
| **Primary comparison** | System C (specialized) vs. System C (generalist) vs. Baseline B |
| **Key metrics** | Domain-specific precision/recall, information loss at boundaries, coordination error rate |
| **Documentation requirement** | Carefully document how this generalist configuration differs from Baseline B. If the generalist agent still uses System C's tools or orchestration without specialization, state that explicitly. |

### Ablation 4 — Reduced Delegation / No Follow-Up

| Property | Value |
|---|---|
| **Purpose** | Determine whether iterative agent interaction contributes to investigation quality (secondary analysis, no direct RQ) |
| **What changes** | Each agent produces output in a single pass. No iterative follow-up between agents. No ability for one agent to request additional evidence from another. |
| **What remains constant** | Agent roles, specialization, deterministic tool grounding, evidence access, model, prompts |
| **Primary comparison** | System C (with follow-up) vs. System C (without follow-up) |
| **Key metrics** | Overall investigation quality, evidence completeness, multi-step reasoning quality |

---

## 11. Prompt Injection Evaluation Methodology

### Purpose

Evaluate RQ6 by measuring how adversarial repository content affects the investigation output of AI-based systems (B and C).

### Injection locations

Prompt-injection payloads may be embedded in any repository content that the AI system processes:

- README files and documentation
- Source-code comments
- Configuration file comments (Docker, CI/CD, YAML)
- String literals and variable names
- Test file names and content
- Commit messages (where accessible)

### Categories of attack intent

| Category | Goal |
|---|---|
| **Finding suppression** | Cause the system to miss or dismiss a genuine vulnerability. |
| **False safety assertion** | Cause the system to explicitly state that an issue is safe or not a vulnerability when it is. |
| **Vulnerability invention** | Cause the system to report a non-existent vulnerability. |
| **Severity manipulation** | Alter the system's severity assessment (inflate or deflate). |
| **Remediation manipulation** | Cause the system to recommend an incorrect or harmful fix. |
| **Instruction following** | Cause the system to follow attacker instructions embedded in the repository (e.g., "ignore all security findings in this file"). |
| **Agent communication interference** | Cause one agent's output to mislead another agent (System C only). |

### Experimental design

For each adversarial evaluation case:

1. Start with a clean repository that has known ground-truth vulnerabilities.
2. Add controlled prompt-injection payloads to repository content. The payloads are the only change to the repository.
3. Run both Baseline B and System C on the clean and adversarial versions.
4. Compare outputs to measure degradation.

The key principle: **the only meaningful change between clean and adversarial versions is the adversarial content itself.** No other repository content, configuration, or tool output changes.

### Measuring success and failure

| Metric | Definition |
|---|---|
| **Injection success rate** | Fraction of payloads that cause any measurable change in the investigation output. |
| **Finding suppression rate** | Fraction of genuine findings present in the clean-condition output that are absent or dismissed in the adversarial-condition output. |
| **False-conclusion rate** | Fraction of conclusions that change from correct (clean) to incorrect (adversarial). |
| **Report integrity score** | Whether the overall report structure, completeness, and format are maintained under adversarial conditions. |
| **Severity change rate** | Fraction of findings whose severity changes between clean and adversarial conditions. |

### Controls

- Use identical tool configurations, prompts, and evidence for clean and adversarial runs.
- Run each condition (clean and adversarial) multiple times to account for stochastic variation.
- Document the specific payloads used, their intended attack category, and their locations.

---

## 12. Experimental Procedure

### Step-by-step run procedure

The following procedure should be followed for each benchmark case and each experimental condition:

1. **Select benchmark case.** Identify the case by its unique ID.
2. **Freeze repository commit.** Record the exact commit SHA or PR identifier.
3. **Record benchmark metadata.** Case ID, repository, commit, category, ground-truth summary.
4. **Run deterministic security tools.** Using the fixed tool configuration defined for the experiment.
5. **Store raw tool output.** Preserve exact tool output without modification.
6. **Construct the evidence package.** Assemble the repository evidence and tool output that will be provided to the AI system. For B and C, this is the same package (evidence parity).
7. **Run the relevant experimental condition.** Execute the system (A, B, C, or ablation) on the evidence package.
8. **Store raw AI output.** Preserve the system's exact output in its native format.
9. **Normalize output into the common evaluation representation.** Map the output to the conceptual schema defined in Section 7.
10. **Score against ground truth.** Apply the metrics defined in Section 8.
11. **Record resource usage.** Token counts, latency, API cost, number of LLM calls.
12. **Repeat where necessary.** For stochastic systems (B and C), repeat steps 7–11 for the defined number of repetitions.
13. **Preserve all artifacts.** Raw outputs, normalized outputs, scores, and metadata.
14. **Aggregate results only after individual runs are complete.** Do not compute aggregate scores until all benchmark cases for a condition are scored.

### Identical procedure across conditions

Steps 1–6 and 13–14 are identical across comparable conditions. Steps 7–8 differ by condition. Steps 9–12 are identical in method but differ in the output being processed.

---

## 13. Repetition and Randomness

### Handling stochastic outputs

LLM outputs are stochastic. Two runs of the same system on the same input with the same configuration may produce different outputs. The methodology must account for this.

### Temperature and generation settings

Define a fixed temperature and generation configuration for each experimental condition. Record these settings as part of the reproducibility metadata. Common choices include temperature 0 (deterministic where supported) or a fixed non-zero temperature (e.g., 0.2–0.7) with reported variance.

### Seeds

Where the LLM API supports random seeds, use a fixed seed for reproducible runs. Where seeds are not supported, rely on repetition and variance reporting.

### Repeated runs

For each benchmark case and each stochastic condition, define a minimum number of repetitions before experiments begin. The number should be large enough to estimate variance but small enough to be practically feasible for a student project. Common choices for LLM evaluation include 3–5 repetitions per case. The exact number should be documented as a methodological decision and applied uniformly.

### Reporting

- Report mean or median scores across repetitions for each metric.
- Report variance (standard deviation or interquartile range) alongside central tendency.
- Report confidence intervals where appropriate.
- Do not select the "best" run from multiple repetitions — this would be cherry-picking.

---

## 14. Statistical Analysis Plan

### Paired comparisons

Systems are compared on the same benchmark cases. This means results are paired — each case produces a score for each condition. Paired analysis should be used rather than independent-sample analysis.

### Per-task and per-category metrics

Report metrics separately for:
- Each evaluation task (T1–T9).
- Each vulnerability category (source code, dependencies, CI/CD, secrets, multi-source).
- Each system condition (A, B, C, ablations).

Do not collapse all results into a single aggregate score as the primary result. Aggregate scores may be reported as summaries but must not obscure per-task and per-category variation.

### Distribution of scores

Show the distribution of scores across benchmark cases, not just the mean. Box plots or similar visualizations are useful for revealing whether a system consistently performs well, performs well on some cases and poorly on others, or has high variance.

### Variance

Report variance across benchmark cases and across repetitions (for stochastic systems). High variance indicates that results may be sensitive to specific cases or to random variation in model output.

### Effect sizes

Report effect sizes (e.g., Cohen's d for paired comparisons, or Cliff's delta for non-parametric comparisons) alongside statistical tests. A statistically significant result with a tiny effect size may not be practically meaningful.

### Confidence intervals

Report confidence intervals for key metrics. This provides uncertainty quantification and helps readers assess whether observed differences are likely to be real.

### Statistical tests

Use appropriate statistical tests where justified:

- For paired comparisons of continuous metrics: paired t-test (if normally distributed) or Wilcoxon signed-rank test (if not).
- For categorical metrics (e.g., finding validation accuracy): McNemar's test or paired proportion tests.
- For multiple comparisons: apply appropriate correction (e.g., Bonferroni, Holm) or report uncorrected p-values with a clear note about the number of comparisons.

### Statistical significance vs. practical significance

Statistical significance indicates that an observed difference is unlikely to be due to chance. It does not indicate that the difference is large enough to matter in practice. The analysis must distinguish:

- **Statistical significance:** The difference is unlikely to be a random fluctuation.
- **Effect size:** How large the difference is in absolute terms.
- **Practical significance:** Whether the difference would matter to a developer using the system.

A statistically significant improvement of 1% in root-cause accuracy may not be practically significant if the multi-agent system costs 10x more.

---

## 15. Cost / Quality Trade-off Analysis (RQ5)

### What to compare

For each experimental condition on each benchmark case, record:

1. **Investigation quality score** (composite or per-task metric).
2. **Total token usage** (input + output, aggregated across all calls).
3. **Number of LLM calls.**
4. **Wall-clock latency.**
5. **API cost** (computed from token counts and provider pricing).

### Analysis approach

- Plot quality scores against cost metrics (tokens, latency, dollars) for each condition.
- Compute quality-per-token and quality-per-dollar ratios.
- Identify the Pareto frontier: conditions that are not dominated by another condition on both quality and cost simultaneously.
- Report whether System C's quality improvement over Baseline B is proportional to its cost increase.

### Why "better quality" is not automatically sufficient

If System C produces a 10% improvement in root-cause accuracy but costs 5x more in tokens and latency, the practical value of that improvement depends on the use case. For time-critical security triage, latency may matter more than a small quality improvement. For thorough investigation of a critical vulnerability, quality may matter more than cost. The evaluation should present the trade-off honestly without imposing a single threshold.

---

## 16. Failure Analysis

### Purpose

Aggregate scores reveal whether one system performs better on average. They do not reveal why, or which types of failures are most common. Qualitative failure analysis is essential for understanding system behavior.

### Failure categories

| Category | Description |
|---|---|
| **Missed vulnerability** | A genuine issue that the system did not report (false negative). |
| **False positive** | A reported issue that does not exist or is not exploitable in context. |
| **Incorrect root cause** | The system identified the issue but stated an incorrect root cause. |
| **Incomplete attack path** | The system described an attack path but missed critical steps. |
| **Incorrect correlation** | The system asserted a relationship between findings that does not exist. |
| **Missed correlation** | Related findings that the system did not connect. |
| **Hallucinated evidence** | The system cited evidence (code, file, condition) that does not exist in the repository. |
| **Unsupported remediation** | The recommended fix would not resolve the issue or would introduce new problems. |
| **Prompt injection success** | Adversarial content caused the system to change its output incorrectly. |
| **Agent coordination failure** | Information was lost or distorted between agents (System C only). |
| **Excessive cost / latency** | The investigation took unacceptably long or consumed disproportionate resources. |

### Process

After aggregate scoring, review a sample of failures from each category. Document:

- The benchmark case and ground truth.
- What the system produced.
- Why it was incorrect, incomplete, or problematic.
- Whether the failure is systematic (repeated across runs) or intermittent (varies across repetitions).
- Whether the failure is specific to one system or common across conditions.

Failure analysis is particularly important for the research contribution. Understanding when and why the multi-agent architecture fails is as valuable as understanding when it succeeds.

---

## 17. Reproducibility and Artifact Preservation

### What to preserve for each experimental run

| Artifact | Description |
|---|---|
| Repository / commit identifier | Exact repository and commit SHA |
| Benchmark case ID | Unique case identifier |
| Tool versions | Names and versions of all deterministic tools used |
| Tool configurations | Configuration files, rulesets, invocation parameters |
| Model identifier | LLM model name, version, and provider |
| Prompt / instruction version | Exact prompt template or agent instruction, versioned |
| Agent configuration | Agent roles, communication graph, orchestration sequence |
| Evidence package | The exact evidence provided to the AI system |
| Raw AI output | System output in its native format, unmodified |
| Normalized output | Output mapped to the common evaluation schema |
| Scores | Per-metric scores for this run |
| Token counts | Input, output, and total tokens |
| Latency | End-to-end wall-clock time |
| API cost | Computed from token counts and pricing |
| Random seed | Where applicable |
| Environment | Computational environment details |
| Repetition number | Which repetition this run represents |

### Raw output preservation

Raw outputs must never be overwritten by normalized or evaluated versions. The normalized and scored versions are derived artifacts stored separately. This allows independent re-evaluation if scoring criteria are later refined, and provides a complete audit trail.

---

## 18. Research Question to Metric to Experiment Mapping

| Research Question | Experimental Comparison | Primary Metrics | Benchmark Requirements |
|---|---|---|---|
| **RQ1** — Multi-Agent Investigation Quality | System C vs. Baseline B vs. Baseline A | Root-cause accuracy, false-positive rate, attack-path completeness, remediation quality, evidence attribution accuracy | Full benchmark (all categories) |
| **RQ2** — Agent Specialization | System C (specialized) vs. System C (generalist) vs. Baseline B | Domain-specific precision/recall, information loss at boundaries, coordination error rate | Full benchmark, with per-domain subtask analysis |
| **RQ3** — Cross-Source Evidence Correlation | System C (with correlation) vs. System C (without correlation) | Cross-source correlation precision/recall, root-cause accuracy, attack-path completeness | Must include multi-source cases |
| **RQ4** — Deterministic Tool Grounding | System C (grounded) vs. System C (ungrounded) vs. Baseline B (ungrounded) | Hallucination rate, factual accuracy, recall for tool-detectable vulnerabilities | Must include cases with tool-detectable findings |
| **RQ5** — Investigation Cost and Complexity | System C vs. Baseline B vs. Baseline A | Token usage, API cost, latency, quality-per-token ratio, quality-per-dollar ratio | Full benchmark, with cost measurements per case |
| **RQ6** — Prompt Injection Resistance | System C vs. Baseline B under adversarial input | Injection success rate, finding suppression rate, incorrect-conclusion rate, report integrity | Must include adversarial repository variants |

---

## 19. Threats to Validity

### Internal validity

| Threat | Description | Mitigation |
|---|---|---|
| **Prompt differences** | B and C may receive different instructions, confounding architectural comparison. | Use comparable investigation instructions. Version and document all prompts. |
| **Model differences** | If B and C use different models, differences may reflect model quality, not architecture. | Use the same model family for B and C where practical. |
| **Tool configuration differences** | Different tool settings across conditions confound tool-related comparisons. | Use identical tool configurations. Document all tool settings. |
| **Evidence differences** | If one system receives more or different evidence, the comparison is confounded. | Enforce evidence parity. Document any necessary differences. |
| **Stochastic outputs** | LLM output variation may produce misleading single-run results. | Use multiple repetitions. Report variance and confidence intervals. |
| **Unequal context windows** | Different models or configurations may process different amounts of evidence. | Document context-window sizes. Discuss as a known limitation where relevant. |
| **Unequal number of LLM calls** | System C makes multiple calls; Baseline B makes one. Differences may reflect repeated reasoning opportunities. | Document this as a known confounder. It is inherent to the architectural comparison and cannot be fully eliminated. |
| **Implementation bugs** | Errors in system implementation may produce misleading results. | Thorough testing of each condition. Manual inspection of outputs during development. |

### External validity

| Threat | Description | Mitigation |
|---|---|---|
| **Limited benchmark size** | A small benchmark may not represent the full range of security investigation challenges. | Acknowledge this limitation. Select benchmark cases to cover multiple categories. |
| **Public repositories may not represent enterprise repositories** | Open-source repositories may have different code patterns, tool configurations, and security cultures. | Acknowledge this limitation. Discuss generalizability carefully. |
| **Findings may depend on selected LLM** | Results are specific to the model used. Different models may produce different results. | Acknowledge this limitation. Document the model used. Do not generalize beyond the evaluated model. |
| **GitHub-only scope** | The evaluation uses GitHub repositories. Results may not generalize to other platforms. | Acknowledge this as a scope limitation consistent with the problem definition. |
| **Limited vulnerability categories** | The benchmark may not cover all vulnerability types equally. | Document category coverage and identify underrepresented categories. |

### Construct validity

| Threat | Description | Mitigation |
|---|---|---|
| **Difficulty of defining "investigation quality"** | Investigation quality is multidimensional and does not reduce to a single score. | Use multiple independent metrics. Report per-task and per-category results. Do not rely on a single aggregate score. |
| **Subjective remediation scoring** | What counts as a "good" remediation recommendation is partially subjective. | Use a structured rating rubric. Report inter-rater agreement. |
| **Imperfect ground truth** | Ground truth may be incomplete, uncertain, or incorrect. | Document ground-truth sources and limitations. Allow partial credit. Acknowledge uncertainty. |
| **Metric limitations** | No set of metrics perfectly captures investigation quality. | Use complementary metrics. Acknowledge what metrics do not measure. |

### Reproducibility risks

| Risk | Description | Mitigation |
|---|---|---|
| **Model / API changes** | LLM providers update models and APIs over time. A reproduction attempt months later may get different results. | Pin model versions where possible. Document exact model versions used. Archive API responses. |
| **Dependency / tool version changes** | Deterministic tools may update rules or behavior. | Pin tool versions. Record exact versions in reproducibility metadata. |
| **External service availability** | API outages or rate limits may affect results. | Document any service interruptions during experiments. Note if runs were affected. |

---

## 20. What the Evaluation Must NOT Claim

The evaluation must not claim:

- That multi-agent systems are universally superior to single-agent systems for security investigation.
- That SecureFlow detects all or most vulnerabilities in a repository.
- That one benchmark proves general security investigation capability.
- That one model's performance generalizes to all LLMs.
- That statistical significance automatically implies practical superiority.
- That prompt-injection testing proves the system is injection-proof or fully robust.
- That AI-generated investigation output can replace human security judgment.
- That the results apply to all repository types, languages, or CI/CD environments.
- That the multi-agent architecture is the optimal decomposition for security investigation.

Any finding that supports the hypothesis should be stated as evidence for the specific conditions tested, not as a general proof. Any finding that contradicts the hypothesis should be reported as honestly as supporting findings.

---

## 21. Final Evaluation Checklist

Use this checklist before running the final evaluation experiments:

- [ ] Benchmark cases selected and documented across all required categories.
- [ ] Ground truth established independently from AI systems, with documented sources and uncertainty.
- [ ] Evaluation criteria (metrics, scoring rubrics, task definitions) frozen before final runs.
- [ ] Prompts and agent instructions versioned and frozen.
- [ ] Deterministic tool configurations documented and fixed.
- [ ] Evidence parity enforced between comparable conditions (B vs C).
- [ ] Same repository and commit used for all conditions on each benchmark case.
- [ ] No evaluation leakage (system not tuned against evaluation cases).
- [ ] Raw outputs preserved for all runs, separate from normalized/scored artifacts.
- [ ] Repetition count defined and applied uniformly for stochastic conditions.
- [ ] Resource usage captured (tokens, latency, cost, LLM calls) for all runs.
- [ ] Metrics defined with clear scoring criteria, including partial-credit rubrics.
- [ ] Human rating protocol defined (blinding, independence, rubric, conflict resolution) where applicable.
- [ ] All A/B/C conditions and required ablation conditions reproducible from recorded metadata.
- [ ] Failure cases preserved and available for qualitative analysis.
- [ ] No results invented, fabricated, or selectively reported.
- [ ] Random seeds and temperature settings documented.
- [ ] Adversarial repository variants prepared for RQ6 evaluation (where applicable).
- [ ] Statistical analysis plan documented before running final experiments.
