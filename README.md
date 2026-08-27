# SecureFlow

Agentic AI Security Engineer for CI/CD — research prototype.

## Research Question

Does a multi-agent AI architecture improve automated security investigation in CI/CD pipelines compared to single-agent and traditional-tool baselines?

## Current Status

**Stage: Project structure established (Step 4 of execution plan).**

Research documentation is complete:

| Document | Description |
|---|---|
| `docs/problem-definition.md` | Problem scope, baselines, research motivation |
| `docs/research-questions.md` | RQ1–RQ6 with hypotheses and metrics |
| `docs/experimental-baselines.md` | Baseline A/B/C conditions, agent roles, ablations |
| `docs/evaluation-methodology.md` | Evaluation tasks, metrics, procedure, threats to validity |
| `docs/benchmark-design.md` | Hybrid benchmark design, case schema, ground truth |

Code implementation has not yet begun.

## Project Structure

```
src/
├── agents/        # AI agent definitions (not yet implemented)
├── tools/         # Deterministic security tool wrappers (not yet implemented)
├── orchestration/ # Multi-agent orchestration logic (not yet implemented)
├── models/        # Data models and schemas (not yet implemented)
└── api/           # External interface layer (not yet implemented)
tests/             # Test suite (not yet populated)
evaluation/        # Benchmark runner and evaluation scripts
datasets/          # Benchmark cases and ground truth
scripts/           # Utility and automation scripts
```

## Getting Started

```bash
# Clone the repository
git clone https://github.com/<owner>/SecureFlow-Agentic-AI-Security-Engineer-for-CI-CD.git
cd SecureFlow-Agentic-AI-Security-Engineer-for-CI-CD

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install dependencies (none yet — added as implementation progresses)
pip install -r requirements.txt

# Copy environment variables
cp .env.example .env
# Edit .env with your API keys
```

## License

MIT
