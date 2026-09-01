# GitHub Integration (Step 21)

## Why this exists

SecureFlow's existing pipeline begins at repository ingestion (`RepositoryIngestor`)
and runs agents over a `RepositoryContext`. Step 21 adds the **external-input
boundary** for GitHub pull requests: it receives a GitHub webhook payload, validates
it, and normalizes it into a structured internal model that later stages of the
pipeline can consume.

This is intentionally a **thin boundary**. It does **not** provide a production
deployment, and it does **not** perform autonomous remediation. It only captures
and validates the pull-request context so that a future orchestrator trigger can be
added without agents ever seeing raw GitHub JSON.

## Intended future flow

```text
GitHub Pull Request
        ↓
Webhook
        ↓
SecureFlow
        ↓
PR context extraction
        ↓
RepositoryContext
        ↓
Orchestrator / investigation pipeline
```

## Package layout

```text
src/github/
    __init__.py   (re-exports the public surface)
    models.py     (GitHubPREvent, PRAction, PRFile)
    webhook.py    (parse_pr_webhook, webhook_handler, verify_signature, to_repository_context)
```

## Supported PR actions

Only actions that should trigger a SecureFlow security investigation are supported:

| Action        | Behavior                                  |
| ------------- | ----------------------------------------- |
| `opened`      | Accepted                                   |
| `synchronize` | Accepted (new commits pushed to the PR)   |
| `reopened`    | Accepted                                   |
| *any other*   | Rejected with `UnsupportedActionError`    |

Actions such as `closed`, `labeled`, `edited`, `assigned`, etc. must **not** trigger
an investigation and are rejected explicitly by the parser. The top-level
`webhook_handler` also filters on the `X-GitHub-Event` type (`pull_request` only).

## Normalized event model

`GitHubPREvent` (`src/github/models.py`) is the single internal representation:

- `repository_full_name` — e.g. `octocat/hello-world`
- `repository_owner` / `repository_name` — split from the full name
- `pr_number` — must be a positive integer
- `head_sha` / `base_sha` — validated Git commit SHAs (`base_sha` optional)
- `action` — a `PRAction` enum value
- `title`, `author`, `draft` — PR metadata used for later context
- `changed_files` — `list[PRFile]`
- `metadata` — internal provenance (source, action)

`PRFile` captures a change:

- `filename` — repository-relative path
- `status` — GitHub status string (`added`, `modified`, `removed`, `renamed`)
- `additions`, `deletions`, `changes` — clamped to non-negative integers

## Webhook parsing

`parse_pr_webhook(payload: dict) -> GitHubPREvent` is the core parser. It reads a
single `pull_request` event, extracts the repository / PR / commit / file
information, and returns a fully validated `GitHubPREvent`.

`webhook_handler(payload, event_type="pull_request") -> GitHubPREvent | None` is the
application-level entry point. It returns `None` for non-`pull_request` event types
(e.g. `ping`) so the dispatcher can ignore them without error.

## Validation

The webhook boundary treats all input as **untrusted**. The parser validates:

- the payload is a JSON object;
- `repository.full_name` exists and has the form `owner/name`;
- `pull_request.number` is a positive integer;
- `action` is a supported `PRAction`;
- `head_sha` (and `base_sha` when present) is a hex string of sufficient length;
- changed-file entries have a non-empty filename with no path traversal.

Every failure raises `WebhookPayloadError` (or `UnsupportedActionError` for
unsupported actions). The webhook boundary never silently falls back to trusting a
raw field.

## Security boundary

The GitHub webhook is untrusted external input. The boundary therefore:

- **never** executes shell commands or uses `subprocess`;
- **never** clones arbitrary URLs;
- **never** executes repository code;
- **never** modifies a repository, creates commits, or creates PRs;
- **never** automatically applies remediation;
- performs **no** network calls;
- performs **no** Docker / kubectl / cloud execution.

Signature verification (`verify_signature`) is provided and is HMAC-SHA256 over the
raw body using a secret. The secret must be supplied through
configuration/environment — it is intentionally **not** hard-coded anywhere in
source. No GitHub personal access token is used or required.

## Changed files

The normalized event preserves the changed files needed by later orchestration.
Paths are stored as repository-relative strings. The parser rejects:

- absolute paths (`/etc/passwd`);
- `..` directory-traversal components (including under `src/`);
- backslash traversal (`..\\..\\evil.py`);
- `~` home expansion;
- NUL bytes.

Only these confined, repository-relative filenames are retained; every entry is a
passive metadata record — the boundary never reads, writes, or executes any path.

## Connection to RepositoryContext

`to_repository_context(event: GitHubPREvent) -> RepositoryContext` is an explicit,
tested adapter that bridges the GitHub boundary into SecureFlow's existing
architecture without redesigning `RepositoryContext`.

It produces:

- `repository_name` = `owner/name`
- `repository_url` = `https://github.com/<owner/name>.git`
- `commit_sha` = the PR `head_sha`
- `changed_files` mapped from `PRFile` statuses to `ChangeStatus`
- `metadata` carrying `pr_number`, `head_sha`, `base_sha`, `title`, `author`

`local_path` is set to an empty string because the webhook boundary never performs a
checkout or clone. Classification of files into `source_files` / `dependency_files`
/ etc. is **not** performed at the webhook boundary — that requires filesystem
access and remains the responsibility of `RepositoryIngestor`.

```text
GitHubPREvent
      ↓
validated internal representation
      ↓
to_repository_context()
      ↓
RepositoryContext / future pipeline input
```

## What is and is not implemented

**Implemented:**

- Structured `GitHubPREvent` / `PRFile` models
- Validated `pull_request` webhook parsing (`opened`, `synchronize`, `reopened`)
- Explicit rejection of unsupported actions
- Path-traversal confinement of changed files
- Application-level `webhook_handler` boundary
- `to_repository_context` adapter
- Optional HMAC signature verification helper
- Comprehensive offline tests

**Not implemented (Step 21 scope):**

- No production webhook deployment (no HTTP server / framework wiring)
- No live GitHub API client
- No prompt / orchestration trigger from a webhook event
- No autonomous remediation

## Limitations

- The webhook boundary only models `pull_request` events; non-PR events are ignored.
- GitHub does not always include `files` in the initial webhook delivery; the
  boundary treats a missing/empty `files` as an empty change list, which the caller
  may reconcile via the API later.
- File classification into `RepositoryContext` category lists is left to ingestion
  (requires a checkout), so `to_repository_context` cannot populate them.
- No automatic handling of draft PRs beyond surfacing the `draft` flag.

## Future webhook deployment

A future step will wrap `webhook_handler` in an HTTP endpoint (e.g. FastAPI /
Flask), verify `X-Hub-Signature-256` using a secret from environment configuration,
and dispatch the resulting `GitHubPREvent` into the orchestrator. No such deployment
exists yet.

## Future GitHub API integration

Later steps may add a GitHub API client to fetch additional data (e.g. diff or
commit list) for a known PR. That client would consume `GitHubPREvent` fields and
would be its own network-boundary component; it is out of scope for this step.

## Explicit statement

**Step 21 does NOT yet provide a production deployment or autonomous remediation.**
