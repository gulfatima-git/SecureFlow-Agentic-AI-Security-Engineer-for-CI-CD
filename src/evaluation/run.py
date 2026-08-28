"""Optional entry point for real-LLM evaluation of the Code Security Agent.

This script runs the existing ``CodeSecurityAgent`` against the Step 12
fixtures using a real ``LLMProvider`` and writes an inspectable JSON report.

REQUIREMENTS / DESIGN:

* It does NOT bundle a production LLM provider. You must supply one that
  implements :class:`src.llm.base.LLMProvider`.
* It does NOT hard-code an API key. Your provider should read its own key from
  an environment variable.
* It performs NO network access unless a provider is supplied. If no provider
  is configured, the script prints guidance and exits 0 — so it is safe to run
  in CI and in normal offline test environments.

USAGE:

    python -m src.evaluation.run \
        --fixtures <path-to/tests/fixtures/agent_eval> \
        --provider my_module:my_factory \
        --out report.json

Where ``my_factory`` is a zero-argument callable returning a fresh
``LLMProvider`` (called once per evaluation case).

Env var ``SECUREFLOW_EVAL_PROVIDER`` may be used instead of ``--provider``.

The report contains only fixture names, findings, and metric values — never
API keys, secrets, or private environment variables.
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections.abc import Callable
from pathlib import Path

from src.evaluation.harness import run_evaluation
from src.evaluation.scoring import EvaluationResult
from src.llm.base import LLMProvider


def _load_provider_factory(spec: str | None) -> Callable[[], LLMProvider] | None:
    """Load a ``module:callable`` provider factory from a spec string."""
    if not spec:
        return None
    module_path, _, attr = spec.partition(":")
    if not module_path or not attr:
        raise ValueError(
            "Provider spec must be 'module.path:factory_callable' "
            f"(got {spec!r})"
        )
    module = importlib.import_module(module_path)
    factory = getattr(module, attr, None)
    if factory is None:
        raise ValueError(f"Module {module_path!r} has no attribute {attr!r}")
    if not callable(factory):
        raise ValueError(f"{spec!r} does not resolve to a callable")
    return factory  # type: ignore[no-any-return]  # caller supplies a provider factory


def _summarize(results: list[EvaluationResult]) -> dict[str, object]:
    passed = sum(1 for r in results if r.passed)
    return {
        "cases": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "details": [r.to_dict() for r in results],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Real-LLM evaluation of the Code Security Agent (Step 12)."
    )
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=Path("tests/fixtures/agent_eval"),
        help="Path to the agent_eval fixtures directory.",
    )
    parser.add_argument(
        "--provider",
        dest="provider_spec",
        default=None,
        help="module.path:factory for an LLMProvider (see module docstring).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write the JSON report to this file.",
    )
    parser.add_argument(
        "--fixture",
        dest="fixtures_filter",
        action="append",
        help="Restrict to a fixture name (repeatable).",
    )
    args = parser.parse_args(argv)

    spec = args.provider_spec or __import__("os").environ.get(
        "SECUREFLOW_EVAL_PROVIDER"
    )
    factory = _load_provider_factory(spec)
    if factory is None:
        print(
            "No LLM provider configured.\n"
            "Real-model evaluation requires an LLMProvider implementation.\n"
            "Supply one via --provider 'module.path:factory' or the\n"
            "SECUREFLOW_EVAL_PROVIDER environment variable. See\n"
            "docs/code-agent-evaluation.md. Exiting without network access.",
            file=sys.stderr,
        )
        return 0

    results = run_evaluation(
        args.fixtures,
        factory,
        fixtures=args.fixtures_filter,
    )
    report = _summarize(results)

    if args.out:
        args.out.write_text(
            json.dumps(report, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
        print(f"Wrote report to {args.out}")

    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(
            f"[{status}] {r.fixture} detection={r.detection} "
            f"localization={r.localization} grounded={r.evidence_grounded} "
            f"hallucination={r.hallucination} sev_ok={r.severity_ok} "
            f"confidence={r.confidence:.2f}"
        )
    print(f"Summary: {report['passed']}/{report['cases']} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
