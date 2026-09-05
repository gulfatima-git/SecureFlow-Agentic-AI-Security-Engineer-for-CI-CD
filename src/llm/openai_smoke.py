"""Manual smoke test for the OpenAI provider (Step 29).

Run after exporting a real key and model::

    python -m src.llm.openai_smoke

This makes exactly one harmless chat-completion request and prints only safe
metadata (model, latency, token usage, estimated cost). It never executes
under pytest. Exit codes: 0 success, 1 unexpected model output, 2 missing or
invalid configuration.
"""

from __future__ import annotations

import json
import sys

from src.llm.base import Message
from src.llm.openai import OpenAIProvider, OpenAIProviderConfig

SMOKE_PROMPT = 'Reply with exactly the JSON object {"ok": true} and nothing else.'
EXPECTED = ('{"ok": true}', '{"ok":true}')


def run_smoke() -> int:
    try:
        config = OpenAIProviderConfig.from_env()
    except Exception as exc:
        print(f"[openai-smoke] invalid configuration: {exc}")
        print("Set OPENAI_API_KEY and OPENAI_MODEL (e.g. OPENAI_MODEL=gpt-4o-mini).")
        return 2

    provider = OpenAIProvider(config)
    raw = provider.raw_complete([Message(role="user", content=SMOKE_PROMPT)])

    telemetry = provider.last_telemetry
    assert telemetry is not None

    if raw.strip() not in EXPECTED:
        print("[openai-smoke] unexpected model output; expected exactly " + EXPECTED[0])
        return 1

    body = {
        "provider": telemetry.provider,
        "model": telemetry.model,
        "latency_seconds": telemetry.latency_seconds,
        "usage": telemetry.usage.model_dump(),
        "retries": telemetry.retries,
        "estimated_cost": (
            telemetry.estimated_cost.model_dump() if telemetry.estimated_cost is not None else None
        ),
    }
    print(json.dumps(body, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(run_smoke())