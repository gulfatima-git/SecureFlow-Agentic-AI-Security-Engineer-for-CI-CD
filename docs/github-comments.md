# GitHub PR Comments (Step 23)

## Why this exists

When a SecureFlow investigation completes, the findings need to be surfaced to
developers in a place they already look: the pull request. Step 23 adds the
ability to render a concise, developer-friendly **Markdown security
investigation comment** and the **GitHub PR comment API boundary** needed to
post it.

The comment is rendered **deterministically** from the structured output of the
investigation pipeline. No LLM generates the Markdown, and no evidence is
fabricated — every line comes from validated `InvestigationResult`,
`RiskAssessment`, and `RemediationPlan` data.

## Architecture / data flow

```text
InvestigationResult + RiskAssessment + RemediationPlan
        ↓
render_investigation_comment(...)      (deterministic Markdown, no LLM)
        ↓
comment body (with stable HTML marker)
        ↓
GitHubCommenter.post_investigation_comment(...)
        ↓
GitHubCommentClient.post_comment(...)  (HTTP POST to GitHub API)
        ↓
POST /repos/{owner}/{repo}/issues/{pr}/comments
```

The PR comment layer is a **thin external-output boundary**. It is separate
from the security agents; agents never render or post comments, and they never
modify repositories.

## GitHub permission requirements

Posting an issue/PR comment via the GitHub REST API requires the
**`pull-requests: write`** permission on the workflow job that performs the
post.

**Step 23 does not yet wire comment posting into the live `secureflow.yml`
workflow.** The workflow remains read-only (`contents: read`). This is a
deliberate decision:

- Comment posting is not yet enabled end-to-end (the scan is still gated on the
  not-yet-deployed SecureFlow API, and there is no running API producing
  `InvestigationResult` objects to post).
- Granting `pull-requests: write` before it is actually used would violate the
  project's least-privilege principle and could weaken the security model for
  no current benefit.

When comment posting is enabled in a future step, the workflow will request the
minimum permission needed:

```yaml
permissions:
  contents: read
  pull-requests: write   # minimum required to post PR comments
```

## Fork PRs

GitHub Actions does not provide repository secrets to workflows triggered by
pull requests from forks by default, and fork PRs must not be granted write
permissions that could be abused by untrusted fork-controlled code. Comment
posting must therefore not assume:

- a `SECUREFLOW_GITHUB_TOKEN` is available for fork PRs;
- `pull-requests: write` is safe to grant to fork PRs.

The comment client fails safely (with a clear configuration error) when the
token is missing, rather than attempting an unauthenticated or privileged
write from an untrusted context.

## Comment structure

```markdown
## SecureFlow Security Investigation

**Risk:** HIGH
**Confidence:** 91%

### Root Cause

Unsanitized user input reaches a SQL query.

### Evidence

- Semgrep finding CODE-001
- Endpoint is publicly accessible
- auth.py:42

### Recommended Fix

Use parameterized queries.

[View Investigation](https://secureflow.example/inv/1)

<!-- secureflow-investigation -->
```

| Section             | Source                                                     |
|---------------------|------------------------------------------------------------|
| Heading             | Fixed string                                               |
| Risk                | `RiskAssessment.severity` (upper-cased risk level)         |
| Confidence          | `RiskAssessment.confidence` rendered as a percentage       |
| Root Cause          | `RemediationPlan.root_cause`, else investigation candidates|
| Evidence            | Structured `EvidenceItem` / `RiskEvidence` content         |
| Recommended Fix     | `RemediationPlan.recommended_fix`                          |
| Investigation link  | Optional caller-supplied URL                               |
| HTML marker         | Fixed `<!-- secureflow-investigation -->`                  |

## Stable HTML marker

Every SecureFlow comment ends with:

```html
<!-- secureflow-investigation -->
```

`COMMENT_MARKER` is the single source of truth. A future integration can search
the PR's existing comments for this marker and **update** that comment instead
of creating a duplicate. Step 23 does **not** implement that updating/dedup
logic — only the marker is emitted.

## Deterministic rendering

`render_investigation_comment(...)` is a pure function:

- Same inputs always produce the same output.
- No LLM, no randomness, no current time.
- Missing optional data (no plan, no evidence, no root cause, no link, zero
  confidence) is handled with safe fallback text.

## No fabrication

The renderer only consumes structured, validated data. It never invents:

- finding IDs, file paths, or line numbers not present in the data;
- confidence values;
- remediation recommendations;
- URLs.

Empty/duplicate evidence is filtered; any evidence shown originates from the
`InvestigationResult`, `RiskAssessment`, or `RemediationPlan`.

## Python API

```python
from src.github import (
    render_investigation_comment,
    GitHubCommenter,
    GitHubCommentConfig,
    GitHubCommentClient,
    COMMENT_MARKER,
)

body = render_investigation_comment(investigation, risk, plan,
                                    investigation_link="https://...")

config = GitHubCommentConfig(token="<from-env>")
client = GitHubCommentClient(config)
commenter = GitHubCommenter(config, client)
comment = commenter.post_investigation_comment("owner/repo", 42,
                                               investigation, risk, plan)
```

## Configuration

The GitHub comment token is read from the `SECUREFLOW_GITHUB_TOKEN` environment
variable (supplied via GitHub Actions secrets). It is never hard-coded. The
GitHub API endpoint defaults to `https://api.github.com` and is configurable;
only HTTPS endpoints are accepted.

## What is implemented

- Deterministic Markdown comment renderer (`render_investigation_comment`)
- Stable `COMMENT_MARKER` for future dedup/update
- `GitHubComment` model
- `GitHubCommentConfig` (token/endpoint from environment)
- `GitHubCommentClient` (stdlib `urllib` GitHub API POST with bearer token)
- `GitHubCommenter` high-level facade
- Comprehensive offline tests

## What is intentionally deferred

- No automatic comment posting wired into the live `secureflow.yml` workflow
- No comment updating / deduplication logic (the marker supports it later)
- No license/`GITHUB_TOKEN`-based workflow permission changes yet
- No remediation, patching, commits, pushes, merges, or deployments
- No real GitHub API calls during tests

## Security considerations

- Least privilege retained: the workflow stays read-only until comment posting
  is actually enabled.
- Fork PRs are not trusted with write permissions or secrets.
- Token comes from environment/secret only; never logged or hard-coded.
- Only HTTPS GitHub endpoints are used.
- No shell/subprocess execution; no repository modification.
