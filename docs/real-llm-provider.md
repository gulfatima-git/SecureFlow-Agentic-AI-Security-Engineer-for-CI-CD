# Real LLM provider (Step 29)

SecureFlow now ships its first real, environment-configured LLM provider:
`src/llm/openai.py` (`OpenAIProvider`). It integrates with the existing
`StructuredLLMProvider` abstraction, so every agent keeps consuming
`AgentDecision` objects exactly as it does with `FakeLLM` — no agent code
changed and `FakeLLM` remains the default for offline tests.

This page documents how the provider is configured, what it guarantees, and
what is and is not implemented.

## Scope

Implemented:

- One real provider (`OpenAIProvider`) in `src/llm/openai.py`.
- Typed provider errors in `src/llm/errors.py`.
- Telemetry and deterministic cost estimation in `src/llm/telemetry.py`.
- Config validation, bounded timeouts, bounded retries, structured JSON
  output, token-usage, latency, and cost capture.
- Offline, deterministic tests (no network, no real key) plus an offline
  integration test driving the existing `CodeSecurityAgent`.
- A manual smoke command (does not run under pytest).

Not implemented (still deferred):

- Benchmark/Baseline execution against a real provider (Baseline B/C runs
  remain deferred; see `experimental-baselines.md`).
- Servers, dashboards, GitHub/webhook actions, agent memory, autonomous
  loops, vector stores, RAG, LangChain/LangGraph wiring.
- Any second LLM abstraction or any agent redesign.

## Configuration

Environment variables (see `.env.example`; placeholders only):

| Variable | Required | Meaning |
|---|---|---|
| `OPENAI_API_KEY` | yes | OpenAI API key |
| `OPENAI_MODEL` | yes | Model identifier, e.g. `gpt-4o-mini` |
| `OPENAI_TIMEOUT_SECONDS` | no (default `60`) | Per-request timeout, seconds, > 0 |
| `OPENAI_MAX_RETRIES` | no (default `3`) | Max automatic retries, >= 0 |

`OpenAIProviderConfig.from_env()` builds and validates this; missing/blank
keys, unparseable or out-of-range timeout/retry values raise
`LLMConfigurationError`.

The API key is stored as `pydantic.SecretStr` and never appears in
`str`/`repr`, JSON serialization, exceptions, logs, or telemetry. The
repository ships no real key; tests use `test-key-not-real` and assert it
never leaks.

## Provider guarantees

- **Existing abstraction only.** `OpenAIProvider(StructuredLLMProvider)`
  implements `raw_complete` and inherits `StructuredLLMProvider.complete`
  (Pydantic `parse_decision` remains the single source of truth for
  structured output).
- **Structured output requested from the API** via Chat Completions
  `response_format={"type": "json_object"}`; text is parsed with `json` +
  Pydantic (no fragile string splitting). Malformed/empty replies raise the
  existing `MalformedLLMResponseError`.
- **Messages are transmitted verbatim.** The provider builds the payload from
  the agent's `Message` list (role/content) and sends it as-is. Repository
  content is untrusted data: it is never executed, echoed in logs, or placed
  in telemetry.
- **Timeouts are bounded and configurable**, applied at the SDK client
  boundary.
- **Retries are bounded and owned by the provider.** The SDK client is built
  with `max_retries=0`; the provider retries only transient failures
  (timeout, connection, 429, 5xx) with capped exponential backoff, up to
  `max_retries`. Auth/config/lookup failures fail fast and are never retried.
- **Typed errors** (`src/llm/errors.py`) distinguish configuration,
  authentication, timeout, rate limit, transient, and unexpected failures via
  distinct classes with a stable `category` and `retryable` flag; messages
  are sanitized and never embed credentials or headers.
- **Telemetry is real, not fabricated.** `last_telemetry` on the provider
  exposes `LLMTelemetry {provider, model, latency_seconds, usage, retries,
  estimated_cost}`. Latency uses a monotonic clock; token counts come only
  from the API response (or `None` when the API did not report them);
  estimated cost comes only from the explicit, versioned pricing table.

## Cost estimation

`src/llm/telemetry.py` contains `OPENAI_STANDARD_PRICING_PER_1M`, a small
explicit table of standard-tier, cache-miss rates in USD per 1M tokens, plus
its source (`PRICING_SOURCE`) and reference date (`PRICING_REFERENCE_DATE`).
`estimate_openai_cost` is deterministic and returns `None` (cost
"unavailable") for models with no known price or requests with missing token
counts — it never guesses or rounds-away detail. Cached-input and Batch
discounts are intentionally not applied.

## Observability and security

- No secrets through telemetry or artifacts: `LLMTelemetry` has no credential
  fields, and tests assert the key never appears in repr/str, exceptions,
  logs, serialized telemetry, or SDK request kwargs.
- The provider performs no logging of prompts, keys, or headers.
- `OpenAIProvider` makes no network call at construction (the SDK client is
  created lazily at first request).

## Manual smoke test

Requires a real key and model::

    export OPENAI_API_KEY=... OPENAI_MODEL=gpt-4o-mini   # shell
    $env:OPENAI_API_KEY="..."; $env:OPENAI_MODEL="gpt-4o-mini"  # PowerShell
    python -m src.llm.openai_smoke

Makes exactly one harmless Chat Completions request that returns
`{"ok": true}`, prints only safe metadata (model, latency, usage, cost), and
exits 0/1/2. It never executes under pytest and never prints the key or
prompt.

## Offline tests and integration

`tests/test_openai_provider.py` mocks the SDK client at the provider
boundary; no network request is made and no real key is used. It covers:

- env config validation and secret masking,
- verbatim message transmission, JSON response_format, model selection,
- structured parsing incl. malformed/empty replies,
- SDK-client wiring (timeout/max_retries/config forwarded),
- bounded retry behavior and non-retry of permanent errors,
- typed error translation for the SDK error hierarchy,
- telemetry (latency, usage, derived totals, cost, per-call updates),
- security assertions (no key in repr/str/exceptions/logs/telemetry/requests),
- an end-to-end agent test: `CodeSecurityAgent` driven by `OpenAIProvider`
  with a mocked client returns a real `CodeAgentResult` (both a final-finding
  path and a read-tool round-trip path).

`FakeLLM` is unchanged and the full offline suite continues to pass.