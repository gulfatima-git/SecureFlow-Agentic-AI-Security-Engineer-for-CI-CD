# Semgrep Integration

Step 7 of the SecureFlow execution plan. Adds Semgrep as SecureFlow's first
deterministic static-analysis security tool.

## Purpose

SecureFlow's architecture separates deterministic security tooling from LLM
reasoning. Semgrep runs first, producing structured findings. AI agents
consume those findings later to perform investigation, correlation, and
remediation.

```
Repository
    ↓
Repository Ingestion (Step 6)
    ↓
Semgrep Scan (Step 7)
    ↓
Structured SecurityFindings
    ↓
Future AI Agents
```

## Architecture

### SecurityFinding model

A tool-agnostic model shared across all future deterministic tools (Semgrep,
Bandit, dependency scanners, CI/CD analyzers). Defined in
`src/models/security_finding.py`.

| Field | Type | Description |
|---|---|---|
| `tool` | `str` | Tool that produced the finding (e.g., `"semgrep"`) |
| `rule_id` | `str` | Tool-specific rule identifier |
| `severity` | `Severity` | Normalized: `error`, `warning`, `info`, `unknown` |
| `confidence` | `Confidence` | Normalized: `high`, `medium`, `low`, `unknown` |
| `message` | `str` | Human-readable description |
| `file_path` | `str` | Path relative to repository root |
| `start_line` | `int` | Start line number |
| `end_line` | `int` | End line number |
| `start_column` | `int` | Start column |
| `end_column` | `int` | End column |
| `code_snippet` | `str` | Source code excerpt if available |
| `category` | `str` | Finding category (e.g., `"security"`) |
| `metadata` | `dict[str, str]` | Tool-specific metadata (CWEs, OWASP, etc.) |

### ScanResult model

Wraps findings with execution metadata for evaluation:

| Field | Type | Description |
|---|---|---|
| `tool` | `str` | Tool name |
| `findings` | `list[SecurityFinding]` | Structured findings |
| `status` | `str` | `success`, `error`, or `timeout` |
| `error_message` | `str` | Error details if status is not success |
| `findings_count` | `int` | Number of findings |
| `scan_duration_seconds` | `float` | Wall-clock scan time |
| `command` | `str` | The command that was executed |
| `tool_version` | `str` | Semgrep version if available |

## SemgrepRunner API

Defined in `src/tools/semgrep_runner.py`.

```python
from src.tools import SemgrepRunner

runner = SemgrepRunner()
# Optional: semgrep_path="/custom/path", config="p/default", timeout=300

result = runner.scan("/path/to/repository")

if result.status == "success":
    for finding in result.findings:
        print(f"{finding.severity}: {finding.rule_id} in {finding.file_path}")
```

### Constructor parameters

- `semgrep_path` — explicit path to semgrep binary (auto-detected by default)
- `config` — Semgrep ruleset (default: `p/default`)
- `timeout` — max scan time in seconds (default: 300)

## Installation / Prerequisites

Semgrep is a CLI tool installed separately from Python dependencies:

```bash
pip install semgrep
```

The Semgrep binary must be on PATH or discoverable by the runner. The runner
checks PATH, then common pip Scripts directories.

Semgrep is **not** listed in `requirements.txt` or `pyproject.toml` because it
is an external CLI tool, not a Python library dependency.

## How Scanning Works

1. The runner validates the repository path exists and is a directory.
2. It constructs a subprocess argument list (never shell=True).
3. It invokes: `semgrep --config p/default --json --quiet --no-git-ignore <path>`
4. It captures stdout and stderr.
5. It parses the JSON output.
6. It converts Semgrep results into `SecurityFinding` objects.
7. It returns a `ScanResult` with findings and metadata.

## Error Handling

The runner distinguishes five states:

| State | Condition | Result status |
|---|---|---|
| Findings detected | Semgrep exits 0 or 1 | `success` |
| No findings | Semgrep exits 0 with empty results | `success` |
| Execution failure | Semgrep exits >= 2 | `error` |
| Timeout | Scan exceeds timeout | `timeout` |
| Not installed | Binary not found | `error` |

Exit code 1 (findings detected) is **not** treated as an error.

## Security Restrictions

- Repository code is never executed.
- Semgrep runs as a subprocess with `shell=False`.
- Arguments are passed as a list, not string interpolation.
- The repository path is validated before scanning.
- No dependency installation occurs.
- The repository is treated as untrusted input.

## Testing

45 tests covering:

- `SecurityFinding` model creation and defaults
- `ScanResult` model
- Severity and confidence mapping (case-insensitive)
- JSON parsing of Semgrep output (multiple findings, missing fields, malformed data)
- Binary resolution (explicit path, PATH search)
- Runner behavior with mocked subprocess:
  - Success with zero findings
  - Success with findings
  - Exit code 1 (findings) not treated as error
  - Exit code >= 2 treated as error
  - Timeout handling
  - Binary not found
  - OS errors
  - Invalid JSON output
  - Duration and command recording
  - `shell=False` verification
- Integration tests (require Semgrep installed):
  - Vulnerable fixture repo detection
  - Clean directory produces zero findings

Tests are deterministic and offline. Integration tests are skipped when
Semgrep is not available.

## Limitations

- Semgrep's JSON output does not always include code snippets. The runner
  extracts snippets from the `lines` field when available.
- Metadata values may be lists (e.g., CWE references). These are joined
  with commas into a flat string dictionary.
- Semgrep must be installed separately. The runner does not install it.
- Results are Semgrep-specific until Bandit and other tools are integrated
  (which will populate the same `SecurityFinding` model).

## Why Deterministic Analysis Is Separate from LLM Reasoning

SecureFlow does not replace deterministic security tooling with an LLM.
Semgrep (and future tools) produce evidence. AI agents reason over that
evidence to perform investigation, correlation, and remediation. This
separation ensures:

- Reproducible findings that do not depend on LLM output.
- Clear evaluation boundaries (tool accuracy vs. agent reasoning).
- The ability to swap or upgrade tools independently of agent logic.
- Ground-truth comparison against known tool output.
