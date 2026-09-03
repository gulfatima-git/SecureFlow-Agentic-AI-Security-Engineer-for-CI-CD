# GitHub Action Integration (Step 22)

## Why this exists

SecureFlow's existing pipeline runs locally via `RepositoryIngestor` and the
`Orchestrator`. Step 22 adds the **GitHub Actions integration layer**: a
reusable workflow that repositories can include to trigger a SecureFlow security
scan whenever a pull request is opened or updated.

This is the integration boundary between GitHub's automation infrastructure and
SecureFlow's API. It is intentionally minimal: it sends a structured request to
a configurable endpoint and surfaces the result in the Actions log.

## Architecture / data flow

```text
Developer opens/updates PR
        ↓
GitHub Actions
        ↓
.github/workflows/secureflow.yml
        ↓
SecureFlow API endpoint (configured via secrets)
        ↓
SecureFlow security investigation (future)
        ↓
Result surfaced in GitHub Actions log
```

The workflow is the outermost integration layer. Inside SecureFlow, the flow is:

```text
SecureFlowActionConfig  (reads SECUREFLOW_API_URL, SECUREFLOW_API_TOKEN)
        ↓
SecureFlowAction.run(GitHubPREvent)
        ↓
event_to_request(GitHubPREvent) → SecureFlowRequest
        ↓
HTTPClientProtocol.send(url, request, token) → SecureFlowResponse
        ↓
(result, error) returned to caller
```

## Supported PR events

| Event           | Triggers scan |
|-----------------|---------------|
| `opened`        | Yes           |
| `synchronize`   | Yes           |
| `reopened`      | Yes           |
| `closed`        | No            |
| Other           | No            |

## Required configuration

The repository must configure two GitHub Actions secrets:

| Secret                | Purpose                              |
|-----------------------|--------------------------------------|
| `SECUREFLOW_API_URL`  | HTTPS endpoint of the SecureFlow API |
| `SECUREFLOW_API_TOKEN`| Bearer token for authentication      |

These are read from the GitHub Actions environment — they are never hard-coded
in the workflow file or source code.

```yaml
secrets:
  SECUREFLOW_API_URL: https://api.secureflow.example.com
  SECUREFLOW_API_TOKEN: <your-token>
```

### Skipping until SECUREFLOW_API_URL is configured

SecureFlow does not yet have a deployed production API. During this development
stage `SECUREFLOW_API_URL` is deliberately **not configured**, so the workflow's
scan step is gated to run only when the secret is present:

- If `SECUREFLOW_API_URL` is **unset or empty**, the workflow logs a clear notice
  that the SecureFlow scan was skipped because `SECUREFLOW_API_URL` is not
  configured, and completes **successfully** (it does not fail the check).
- If `SECUREFLOW_API_URL` **is configured**, the scan proceeds as normal.

This keeps pull-request checks green during development while preserving the
production behavior once the SecureFlow API is deployed (a later step). No fake
production URL is used as a stand-in.

## Secret handling

- `SECUREFLOW_API_URL` and `SECUREFLOW_API_TOKEN` are supplied through GitHub
  Actions secrets.
- Secrets are never printed to the Actions log.
- Secrets are never hard-coded in source.
- The workflow does not expose secrets to fork-controlled code.
- `SecureFlowHTTPClient` never logs the token.

## Permissions

The workflow requests only **read** permissions:

```yaml
permissions:
  contents: read
```

At the job level, permissions are also constrained to `read`. No write access to
`contents`, `pull-requests`, or `actions` is granted.

## Fork PR security considerations

GitHub Actions does **not** provide repository secrets to workflows triggered by
pull requests from forks by default. This means:

- Fork PRs will **not** have access to `SECUREFLOW_API_URL` or
  `SECUREFLOW_API_TOKEN`.
- Because the scan step is gated on `SECUREFLOW_API_URL`, fork PRs (which do not
  have the secret) will have the scan **skipped** gracefully — they will not run
  the workflow body that requires the secret.
- Secrets are never exposed to untrusted fork code.

This is the expected security behavior. To run SecureFlow on fork PRs, a
repository would need to configure a more advanced workflow (e.g. using
`pull_request_target`) — that is out of scope for Step 22 and is a future
consideration.

## API request structure

The workflow constructs a JSON payload and sends it via `curl`:

```json
{
  "repository": "owner/name",
  "pr_number": 123,
  "head_sha": "abc1234...",
  "base_sha": "def5678..."
}
```

This is the minimal information needed to identify a pull request and initiate
an investigation.

Internally, the `SecureFlowRequest` model is used by the Python client:

```python
SecureFlowRequest(
    repository="owner/name",
    pr_number=123,
    head_sha="abc1234...",
    base_sha="def5678...",
    changed_files=[...],
)
```

## Python modules

| Module                          | Purpose                                              |
|---------------------------------|------------------------------------------------------|
| `src/api/models.py`            | `SecureFlowRequest`, `SecureFlowResponse` models     |
| `src/api/client.py`            | `HTTPClientProtocol`, `SecureFlowHTTPClient`, fake   |
| `src/github/action.py`         | `SecureFlowAction`, `SecureFlowActionConfig`, adapter|
| `src/github/__init__.py`       | Re-exports the public surface                        |
| `src/api/__init__.py`          | Re-exports the public surface                        |

## Failure behavior

The workflow distinguishes the following outcomes:

| Situation                 | Behavior                                             |
|---------------------------|------------------------------------------------------|
| `SECUREFLOW_API_URL` unset/empty | Scan is **skipped**; a notice is logged; workflow succeeds |
| `SECUREFLOW_API_URL` set, HTTP 2xx | Success message logged                               |
| `SECUREFLOW_API_URL` set, HTTP non-2xx | Error logged, scan step exits with code 1            |
| Network timeout           | Timeout error logged, scan step exits with code 1     |
| Unexpected exception      | Error logged, scan step exits with code 1             |

Only a missing/empty `SECUREFLOW_API_URL` causes a graceful skip. Any API
invocation that does occur still treats non-success responses, timeouts, and
unexpected errors as failures.

The workflow **never** automatically modifies the PR, creates commits, or
applies remediation.

## What is implemented

- Reusable GitHub Actions workflow (`.github/workflows/secureflow.yml`)
- `SecureFlowRequest` / `SecureFlowResponse` API models
- `HTTPClientProtocol` test seam and `SecureFlowHTTPClient`
- `SecureFlowFakeHTTPClient` for offline testing
- `SecureFlowActionConfig` (reads from environment)
- `SecureFlowAction` (orchestrates config → adapter → client)
- `event_to_request` adapter (`GitHubPREvent → SecureFlowRequest`)
- Comprehensive offline tests

## What is intentionally deferred

- No production SecureFlow API deployment — until one is configured, the scan is
  skipped gracefully (a deployed API will be configured in a later step)
- No PR comments or status checks (future step)
- No automatic remediation
- No repository modification
- No real credentials
- No fork PR secret forwarding
- No GitHub API client for fetching additional PR data

## Limitations

- The workflow constructs its payload via shell string interpolation — PR number
  and SHAs are trusted GitHub-provided values in this context.
- The `SecureFlowHTTPClient` uses `urllib.request` (stdlib) — no third-party
  HTTP library is introduced as a dependency.
- Changed files in the workflow payload are not included (only repository, PR
  number, and SHAs). The full `SecureFlowRequest` with changed files is available
  through the Python `event_to_request` adapter when invoked programmatically.
- Because `SECUREFLOW_API_URL` is not configured during development, the workflow
  effectively skips scanning until a production API is deployed and the secret is
  set.

## Step 22 statement

**Step 22 provides the GitHub Actions integration boundary.** It does not:

- Implement automatic remediation
- Expose real credentials
- Provide a production SecureFlow API deployment
- Create PR comments or status checks (those are future steps)
