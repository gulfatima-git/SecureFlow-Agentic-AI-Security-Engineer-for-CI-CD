# Bandit Integration

Step 8 of the SecureFlow execution plan. Adds Bandit as SecureFlow's second
deterministic security-analysis tool, specializing in Python code.

## Purpose

Semgrep (Step 7) performs general pattern-based static analysis across many
languages. Bandit specializes in Python security issues with deeper
language-aware checks. Together they provide complementary evidence:

- **Semgrep**: pattern-based, multi-language, catches a broad set of issues.
- **Bandit**: Python-native, catches Python-specific idioms and anti-patterns.

Both tools produce findings through the same `SecurityFinding` model, giving
downstream AI agents a unified evidence format regardless of which tool
produced the finding.

```
Repository
    ↓
Repository Ingestion (Step 6)
    ↓
+--------+---------+
|                  |
Semgrep (Step 7)   Bandit (Step 8)
|                  |
+--------+---------+
         ↓
Normalized Security Findings
         ↓
    Future AI Agents
```

## Architecture

Bandit findings populate the same `SecurityFinding` model defined in Step 7.
There is no separate `BanditFinding` class. This is intentional.

### Severity mapping

Bandit uses HIGH/MEDIUM/LOW severity. These map to SecureFlow's normalized
`Severity` enum:

| Bandit severity | SecureFlow Severity | Rationale |
|---|---|---|
| `HIGH` | `error` | Direct security vulnerabilities |
| `MEDIUM` | `warning` | Potential security concerns |
| `LOW` | `info` | Informational security notes |

The original Bandit value is preserved in metadata for full traceability.

### Confidence mapping

Bandit uses HIGH/MEDIUM/LOW confidence. These map directly to SecureFlow's
`Confidence` enum:

| Bandit confidence | SecureFlow Confidence |
|---|---|
| `HIGH` | `high` |
| `MEDIUM` | `medium` |
| `LOW` | `low` |

### Finding normalization

Each Bandit result is converted as follows:

| Bandit JSON field | SecurityFinding field |
|---|---|
| `test_id` + `test_name` | `rule_id` (e.g., `B105.hardcoded_password_string`) |
| `issue_severity` | `severity` (mapped) |
| `issue_confidence` | `confidence` (mapped) |
| `issue_text` | `message` |
| `filename` | `file_path` |
| `line_number` | `start_line` |
| `line_range[-1]` | `end_line` |
| `col_offset` | `start_column` |
| `end_col_offset` | `end_column` |
| `code` | `code_snippet` |
| `issue_cwe` | `metadata["cwe"]`, `metadata["cwe_link"]` |
| `more_info` | `metadata["more_info"]` |
| `test_name` | `metadata["test_name"]` |

The `tool` field is always `"bandit"` and `category` is always `"security"`.

## BanditRunner API

Defined in `src/tools/bandit_runner.py`.

```python
from src.tools import BanditRunner

runner = BanditRunner()
# Optional: bandit_path="/custom/path", timeout=300

result = runner.scan("/path/to/repository")

if result.status == "success":
    for finding in result.findings:
        print(f"{finding.severity}: {finding.rule_id} in {finding.file_path}")
```

### Constructor parameters

- `bandit_path` — explicit path to bandit binary (auto-detected by default)
- `timeout` — max scan time in seconds (default: 300)

## Installation / Prerequisites

Bandit is a Python library installed via pip:

```bash
pip install bandit
```

Bandit **is** listed in `requirements.txt` and `pyproject.toml` as a core
dependency (unlike Semgrep which is an external CLI tool). Bandit runs as
`python -m bandit` within the project's virtual environment.

Bandit version: **1.9.4** (compatible with Python 3.14.4).

## How Scanning Works

1. The runner validates the repository path exists and is a directory.
2. It checks whether any `.py` files exist in the repository.
3. If no Python files exist, it returns a success result with zero findings
   and a message indicating the scan was skipped.
4. If Python files exist, it constructs a subprocess argument list (never
   shell=True).
5. It invokes: `bandit -r -f json --exit-zero <path>`
6. It captures stdout and stderr.
7. It parses the JSON output.
8. It converts Bandit results into `SecurityFinding` objects.
9. It returns a `ScanResult` with findings and metadata.

### Bandit invocation flags

| Flag | Purpose |
|---|---|
| `-r` | Recurse into subdirectories |
| `-f json` | Machine-readable JSON output |
| `--exit-zero` | Always exit 0 regardless of findings (prevents exit-code confusion) |

### Python file detection

Bandit is Python-specific. The runner checks for `.py` files before invoking
Bandit, excluding generated directories (`__pycache__`, `.git`, `.mypy_cache`,
`.pytest_cache`, `node_modules`, `.tox`). This avoids unnecessary scans and
clearly communicates when Bandit is not applicable.

## Error Handling

The runner distinguishes these states:

| State | Condition | Result status |
|---|---|---|
| Findings detected | Bandit exits 0 | `success` |
| No findings | Bandit exits 0 with empty results | `success` |
| No Python files | Repository has no `.py` files | `success` (skipped) |
| Execution failure | Bandit exits >= 2 | `error` |
| Timeout | Scan exceeds timeout | `timeout` |
| Not installed | Binary not found | `error` |
| Invalid path | Path does not exist | `error` |
| Parse failure | Invalid JSON output | `error` |

The `--exit-zero` flag ensures Bandit always exits 0 when it can parse the
code. Non-zero exit codes indicate actual tool failures.

## Security Restrictions

- Repository code is never executed.
- Bandit runs as a subprocess with `shell=False`.
- Arguments are passed as a list, not string interpolation.
- The repository path is validated before scanning.
- No dependency installation occurs.
- No `setup.py`, `pip install`, or Docker builds occur.
- The repository is treated as untrusted input.
- Arbitrary repository paths cannot become shell commands.

## Handling of Non-Python Repositories

If a repository contains no `.py` files, the runner returns:

```python
ScanResult(
    tool="bandit",
    status="success",
    error_message="No Python files found — Bandit scan skipped",
    findings_count=0,
)
```

This makes it explicit that Bandit was not run because the repository is
not applicable, rather than reporting zero findings which could be misleading.

## Testing

53 tests covering:

- Severity and confidence mapping (case-insensitive, all levels)
- JSON parsing of Bandit output (multiple findings, missing fields, malformed data)
- Rule ID construction from `test_id` + `test_name`
- CWE and metadata preservation
- Python file detection (with excluded directories)
- Binary resolution (explicit path, PATH search)
- Runner behavior with mocked subprocess:
  - Success with zero findings
  - Success with findings
  - High exit code treated as error
  - Timeout handling
  - Binary not found
  - OS errors
  - Invalid JSON output
  - Duration and command recording
  - `shell=False` verification
  - No Python files skips scan
  - Tool version recorded
  - stderr does not cause error
- Shared normalization interoperability:
  - Findings are `SecurityFinding` instances
  - `ScanResult` is correctly structured
  - Findings serialize to dicts
- Integration tests (require Bandit installed):
  - Vulnerable fixture repo detection
  - Clean directory produces zero findings

Tests are deterministic and offline. Integration tests are skipped when
Bandit is not available.

## Limitations

- Bandit only analyzes Python code. For other languages, Semgrep (Step 7)
  or future tools must be used.
- Bandit's `code` field may contain multi-line snippets with varying
  whitespace normalization.
- The `--exit-zero` flag means the runner always treats Bandit execution as
  successful unless the process itself fails (exit >= 2).
- Bandit must be installed as a Python package. The runner does not install it.

## Why Bandit Is Separate from Semgrep

Both tools produce `SecurityFinding` objects, but they detect different things:

- Semgrep uses pattern rules that can match across languages.
- Bandit uses Python AST analysis and knows Python-specific idioms.

Some issues are caught by both tools (e.g., `shell=True` in subprocess).
Some are caught by only one. The overlap and gaps are part of the evaluation
research — the AI agents in later steps will correlate findings across tools.

## Why Deterministic Analysis Is Separate from LLM Reasoning

SecureFlow does not replace deterministic security tooling with an LLM.
Semgrep and Bandit produce evidence. AI agents reason over that evidence
to perform investigation, correlation, and remediation. This separation
ensures:

- Reproducible findings that do not depend on LLM output.
- Clear evaluation boundaries (tool accuracy vs. agent reasoning).
- The ability to swap or upgrade tools independently of agent logic.
- Ground-truth comparison against known tool output.
