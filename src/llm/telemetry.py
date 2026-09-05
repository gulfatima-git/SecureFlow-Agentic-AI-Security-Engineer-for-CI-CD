"""LLM provider telemetry: token usage, latency, and cost estimation (Step 29).

The provider records what actually happened on the wire (latency, token
usage reported by the API) and derives a deterministic cost estimate from an
explicit, versioned pricing table. When a figure is unknown — the model has
no known price or the API did not report token counts — the value is
reported as unavailable (``None``) rather than guessed.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

# Source of the per-1M-token prices in OPENAI_STANDARD_PRICING_PER_1M.
# Standard-tier, cache-miss rates as published by OpenAI. Cached-input and
# Batch discounts are intentionally NOT applied; the estimate is a simple,
# explicit figure and is labeled as such.
PRICING_SOURCE = (
    "OpenAI API pricing, standard tier, cache-miss rates "
    "(https://developers.openai.com/api/docs/pricing)"
)
PRICING_REFERENCE_DATE = "2026-09-06"


class LLMTokenUsage(BaseModel):
    """Token counts reported by the API for a single request.

    Any field may be ``None`` when the API did not report it.
    """

    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None


class LLMCost(BaseModel):
    """A reported cost estimate for a request, in a fixed currency."""

    input_cost: float = Field(ge=0.0)
    output_cost: float = Field(ge=0.0)
    total_cost: float = Field(ge=0.0)
    currency: str = "USD"


class LLMTelemetry(BaseModel):
    """Observability record for one provider request.

    Never contains credentials, request headers, or message contents.
    """

    provider: str
    model: str
    latency_seconds: float = Field(ge=0.0)
    usage: LLMTokenUsage
    retries: int = Field(ge=0)
    estimated_cost: LLMCost | None = None


# Standard-tier rates in USD per 1,000,000 input/output tokens. Only models
# whose public rates are confidently known are listed; anything else reports
# its cost as unavailable rather than estimating it.
OPENAI_STANDARD_PRICING_PER_1M: dict[str, tuple[float, float]] = {
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
}


def estimate_openai_cost(model: str, usage: LLMTokenUsage) -> LLMCost | None:
    """Estimate USD cost deterministically, or return None when unknown.

    The estimate uses the standard-tier, cache-miss rate for ``model``. It
    returns ``None`` (cost unavailable) when the model has no known price or
    when the token counts were not reported, rather than inventing a figure.
    """
    prices = OPENAI_STANDARD_PRICING_PER_1M.get(model)
    if prices is None or usage.input_tokens is None or usage.output_tokens is None:
        return None
    input_rate, output_rate = prices
    input_cost = usage.input_tokens * input_rate / 1_000_000
    output_cost = usage.output_tokens * output_rate / 1_000_000
    return LLMCost(
        input_cost=input_cost,
        output_cost=output_cost,
        total_cost=input_cost + output_cost,
    )