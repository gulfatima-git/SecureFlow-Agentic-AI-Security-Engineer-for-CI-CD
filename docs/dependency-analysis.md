# Dependency Analysis

Step 9 of the SecureFlow execution plan. Adds dependency vulnerability
analysis using the OSV (Open Source Vulnerabilities) database.

## Purpose

SecureFlow's deterministic tools now cover three evidence sources:

- **Semgrep** (Step 7): pattern-based static analysis
- **Bandit** (Step 8): Python-specific security analysis
- **Dependency Analyzer** (Step 9): known vulnerability detection in dependencies

The dependency analyzer answers three questions:
1. Which dependencies are present?
2. What versions are declared/resolved?
3. Are any known vulnerabilities associated with those dependencies?

```
Repository
    ↓
RepositoryContext (Step 6)
    ↓
+--------+---------+------------------+
|        |         |                  |
Semgrep  Bandit   Dependency Analyzer
(Step 7) (Step 8) (Step 9)
|        |         |                  |
+--------+---------+------------------+
         ↓
Normalized Security Findings
         ↓
    Future AI Agents
```

## Supported Dependency Files

| File | Ecosystem | What is extracted |
|---|---|---|
| `requirements.txt` | PyPI | Package names, version constraints |
| `pyproject.toml` | PyPI | `[project].dependencies` strings |
| `package.json` | npm | `dependencies`, `devDependencies` version ranges |
| `package-lock.json` | npm | Resolved versions from `packages` (v2/v3) or `dependencies` (v1) |

## Version Handling

This is the most important design decision in the dependency analyzer.

### Exact/resolved version

```
requirements.txt:
    requests==2.31.0
→ declared_version = "==2.31.0"
→ no lockfile resolution needed
```

### Version range (no resolution)

```
package.json:
    "lodash": "^4.17.20"
→ declared_version = "^4.17.20"
→ resolved_version = "" (unless package-lock.json provides it)
```

### Resolved lockfile version

```
package-lock.json:
    lodash resolved to 4.17.21
→ resolved_version = "4.17.21"
→ This is the strongest version evidence
```

### Unknown version

```
requirements.txt:
    flask
→ declared_version = ""
→ resolved_version = ""
→ OSV is queried without a version constraint (returns all known vulns)
```

**Key rule**: When a `package-lock.json` exists alongside `package.json`, the
lockfile's resolved version overrides the declared range. This provides the
most accurate vulnerability matching.

When only a version range is available (no lockfile), OSV is queried without
a version constraint and returns all known vulnerabilities for that package.

## API

Defined in `src/tools/dependency_analyzer.py`.

```python
from src.tools import DependencyAnalyzer

analyzer = DependencyAnalyzer()
result = analyzer.scan("/path/to/repository")

if result.status == "success":
    for finding in result.findings:
        print(f"{finding.severity}: {finding.package_name} {finding.message}")
```

### Constructor parameters

- `timeout` — OSV API request timeout in seconds (default: 30)

### Usage with parsers directly

```python
from src.tools.dependency_parsers import (
    parse_requirements_txt,
    parse_pyproject_toml,
    parse_package_json,
    parse_package_lock,
)
from pathlib import Path

deps = parse_requirements_txt(Path("requirements.txt"))
for dep in deps:
    print(f"{dep.name} {dep.declared_version}")
```

## OSV Integration

The analyzer queries the [OSV API](https://osv.dev/) for each discovered
dependency. OSV is a free, open vulnerability database maintained by Google.

### How OSV is queried

For each dependency with a known ecosystem and name:
1. POST to `https://api.osv.dev/v1/query`
2. Include `package.name`, `package.ecosystem`, and `version` (if known)
3. Parse returned vulnerabilities
4. Extract identifiers (GHSA, CVE, OSV), severity, affected/fixed versions

### When OSV is queried without a version

When the declared version is empty or a range (not pinned), OSV is queried
without a version constraint. This returns all known vulnerabilities for
that package. The findings still carry the declared version for context.

### HTTP client

The OSV client uses Python's stdlib `urllib.request` — no external HTTP
library is required.

## Normalized Output

Each vulnerability becomes a `SecurityFinding` with:

| Field | Content |
|---|---|
| `tool` | `"dependency-analyzer"` |
| `rule_id` | First alias (CVE/GHSA) or OSV ID |
| `severity` | Mapped from OSV severity (HIGH/CRITICAL→error, MEDIUM→warning, LOW→info) |
| `confidence` | HIGH if resolved version, MEDIUM if only declared range |
| `message` | Vulnerability summary + fixed version if available |
| `file_path` | Dependency file that declared the package |
| `category` | `"dependency-vulnerability"` |
| `ecosystem` | `"PyPI"` or `"npm"` |
| `package_name` | Package name |
| `declared_version` | Version constraint from the dependency file |
| `resolved_version` | Resolved version from lockfile (if available) |
| `metadata` | `osv_id`, `aliases`, `references`, `fixed_version`, `source` |

### SecurityFinding extension

Step 9 adds four optional fields to `SecurityFinding`:

```python
ecosystem: str = ""
package_name: str = ""
declared_version: str = ""
resolved_version: str = ""
```

These are backwards-compatible — existing tools (Semgrep, Bandit) leave
them empty. Only the dependency analyzer populates them.

## Error Handling

| State | Result status |
|---|---|
| Vulnerabilities found | `success` |
| No vulnerabilities found | `success` |
| No dependency files found | `success` (with error_message) |
| Invalid repository path | `error` |
| OSV API failure | `error` (if all queries fail) |
| Partial OSV failure | `success` (with partial error message) |

A network/API failure does **not** silently become "0 vulnerabilities."
The `error_message` field distinguishes parsing failures from successful
scans with zero findings.

## Security Restrictions

- Repository code is never executed.
- No `pip install`, `npm install`, or package manager invocations.
- No `setup.py`, `poetry install`, or build scripts.
- No Docker image builds.
- No subprocess calls whatsoever (pure Python parsing).
- HTTP requests go only to `api.osv.dev`.
- Repository contents are treated as untrusted data.
- Dependency files are parsed with stdlib parsers (`tomllib`, `json`, `re`).

## Testing

69 tests covering:

- **requirements.txt parsing**: exact versions, ranges, unpinned, multiple deps, comments, options, inline comments, extras, env markers, file not found
- **pyproject.toml parsing**: project dependencies, no project section, empty deps, malformed TOML, non-string deps
- **package.json parsing**: dependencies, devDependencies, both sections, malformed JSON
- **package-lock.json parsing**: v2 resolved versions, v1 resolved versions, malformed JSON
- **OSV client** (all mocked): successful query, no vulns, multiple vulns, references, API error, timeout, malformed response, empty vulns, missing ID, version in payload
- **Severity mapping**: HIGH, CRITICAL, MEDIUM, LOW, unknown
- **Vulnerability→Finding conversion**: basic, no resolved version, no aliases, metadata, no fixed version
- **DependencyAnalyzer** (mocked OSV): invalid path, no files, with vulns, no vulns, OSV error, partial error, tool version, duration, multiple files, npm+lockfile
- **Shared normalization**: Pydantic model, serialization, backward compatibility
- **Security**: no subprocess, no pip

All network tests are mocked. The test suite does not depend on the live OSV API.

## Limitations

- Only four dependency file formats are supported initially. Future steps
  can add `Cargo.toml`, `go.mod`, `Gemfile`, etc.
- PEP 508 parsing is simplified. Complex environment markers, URL
  dependencies, and editable installs are not fully handled.
- npm lockfile parsing supports v1 and v2/v3 but does not handle every
  historical format.
- OSV does not cover all vulnerability databases. Some niche packages
  may have no advisories.
- The analyzer makes one HTTP request per dependency. For repositories
  with hundreds of dependencies, this may be slow. Future steps can add
  batching or caching.
- Version range matching is delegated to OSV. When no version is provided,
  OSV returns all known vulns (which may include fixed versions).

## Future Extensions

- Additional ecosystems: Cargo (Rust), Go modules, RubyGems, Maven
- Batch OSV queries for performance
- Offline vulnerability database caching
- Transitive dependency analysis
- License compliance checking
- Dependency age/freshness analysis
