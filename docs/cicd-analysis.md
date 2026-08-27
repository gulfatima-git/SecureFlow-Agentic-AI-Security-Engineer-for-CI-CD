# CI/CD Configuration Analysis

Step 10 of the SecureFlow execution plan. Adds deterministic security
analysis of CI/CD configuration files — GitHub Actions workflows,
Dockerfiles, and Docker Compose configurations.

## Purpose

SecureFlow's deterministic tools now cover four evidence sources:

- **Semgrep** (Step 7): pattern-based static analysis
- **Bandit** (Step 8): Python-specific security analysis
- **Dependency Analyzer** (Step 9): known vulnerability detection in dependencies
- **CI/CD Analyzer** (Step 10): configuration security analysis

The CI/CD analyzer answers three questions:
1. Which CI/CD configuration files are present?
2. Do they contain security anti-patterns?
3. Are they configured securely?

```
Repository
    ↓
RepositoryContext (Step 6)
    ↓
+--------+---------+------------------+----------------+
|        |         |                  |                |
Semgrep  Bandit   Dependency Analyzer  CI/CD Analyzer
(Step 7) (Step 8) (Step 9)           (Step 10)
|        |         |                  |                |
+--------+---------+------------------+----------------+
         ↓
Normalized Security Findings
         ↓
    Future AI Agents
```

## Supported CI/CD Files

| File Type | Patterns | Ecosystem |
|---|---|---|
| GitHub Actions workflows | `.github/workflows/*.yml`, `.github/workflows/*.yaml` | GitHub |
| Dockerfiles | `Dockerfile`, `Dockerfile.*` | Docker |
| Docker Compose | `docker-compose.yml`, `docker-compose.yaml` | Docker |

## Security Checks

### GitHub Actions

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `CICD.GHA.EXCESSIVE_PERMISSIONS` | WARNING | HIGH | Workflow grants broad write permissions |
| `CICD.GHA.PULL_REQUEST_TARGET` | ERROR | HIGH | Dangerous trigger: `pull_request_target` |
| `CICD.GHA.UNTRUSTED_INPUT` | ERROR | HIGH | Untrusted user input in `run:` commands |
| `CICD.GHA.SECRET_EXPOSURE` | ERROR | MEDIUM | Secrets passed to shell commands |
| `CICD.GHA.UNPINNED_ACTION` | WARNING | HIGH | Third-party actions using mutable tags |

### Dockerfiles

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `CICD.DOCKER.ROOT_USER` | WARNING | MEDIUM | No `USER` instruction (runs as root) |
| `CICD.DOCKER.REMOTE_SCRIPT` | ERROR | HIGH | `curl/wget | sh` pattern |
| `CICD.DOCKER.SECRET_ENV` | ERROR | MEDIUM | Credentials in `ENV` instructions |
| `CICD.DOCKER.SECRET_ARG` | ERROR | MEDIUM | Credentials in `ARG` instructions |
| `CICD.DOCKER.DANGEROUS_ADD` | WARNING | HIGH | `ADD` fetching remote URLs |

### Docker Compose

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `CICD.COMPOSE.PRIVILEGED` | ERROR | HIGH | `privileged: true` |
| `CICD.COMPOSE.HOST_MOUNT` | ERROR | HIGH | Host filesystem mounts (docker.sock, sensitive paths) |
| `CICD.COMPOSE.SECRET` | ERROR | MEDIUM | Plaintext secrets in environment |
| `CICD.COMPOSE.HOST_NETWORK` | WARNING | HIGH | `network_mode: host` |
| `CICD.COMPOSE.DANGEROUS_CAPABILITY` | ERROR | HIGH | `cap_add` with dangerous capabilities |
| `CICD.COMPOSE.SENSITIVE_PORT` | WARNING | MEDIUM | Sensitive ports exposed to host |

## API

Defined in `src/tools/cicd_analyzer.py`.

```python
from src.tools import CICDAnalyzer

analyzer = CICDAnalyzer()
result = analyzer.analyze("/path/to/repository")

if result.status == "success":
    for finding in result.findings:
        print(f"{finding.severity}: {finding.message}")
```

### Constructor parameters

None — the analyzer is stateless.

## Severity and Confidence Decisions

**Severity:**
- **ERROR**: High-impact issues that could lead to compromise
  - `pull_request_target`, untrusted input in commands, secrets in shell,
    `curl | sh`, `privileged: true`, dangerous capabilities, host mounts
- **WARNING**: Configuration issues that increase attack surface
  - Excessive permissions, unpinned actions, no USER instruction,
    dangerous ADD, host networking, sensitive ports
- **MEDIUM**: Secrets in ENV/ARG (confidence varies), sensitive ports

**Confidence:**
- **HIGH**: Deterministic pattern matches (regex, boolean checks)
- **MEDIUM**: Heuristic matches (secret name patterns, root user detection)

## GitHub Actions — The `on:` Key

GitHub Actions YAML has an unusual behavior: the `on:` key is parsed as
boolean `True` by PyYAML when unquoted. The analyzer handles this by
checking both `workflow.get("on")` and `workflow.get(True)`.

## Safe Parsing

All YAML is parsed with `yaml.safe_load()`. No `yaml.load()` with custom
loaders. Malformed YAML does not crash the scan — files are skipped
gracefully.

## Security Restrictions

The analyzer itself is safe:

- No subprocess calls
- No shell execution
- No Docker commands
- No workflow execution
- No network access
- No code execution
- Repository contents are treated as untrusted input
- Path validation before processing

## Testing

119 tests covering:

- **YAML parsing**: valid, malformed, non-dict, empty
- **File discovery**: invalid path, empty repo, secure/insecure repos
- **GitHub Actions permissions**: excessive, read-only, no permissions, multiple write, fixture detection
- **GitHub Actions triggers**: pull_request_target, workflow_dispatch (not flagged), safe triggers, string/list/dict forms, boolean key
- **Untrusted input**: github.event, github.pull_request, inputs, head_ref, safe commands, no steps
- **Secret exposure**: secrets in run, no secrets, fixture detection
- **Unpinned actions**: third-party mutable tag, SHA-pinned, official actions, fixture detection
- **Full workflow analysis**: all rule types, secure workflow, malformed YAML, field correctness
- **Dockerfile root user**: no USER, has USER, no CMD, ENTRYPOINT, fixtures
- **Dockerfile remote script**: curl|sh, wget|bash, safe curl, comments, line numbers
- **Dockerfile secrets**: ENV secrets, ARG secrets, safe ENV, multiple secrets, metadata
- **Dockerfile dangerous ADD**: remote URL, local file, comments
- **Docker Compose**: privileged, host mounts, secrets, host network, capabilities, sensitive ports
- **Full Compose analysis**: insecure/secure fixtures, no services, malformed YAML
- **Normalization**: Pydantic models, serialization, count
- **Determinism**: repeated results identical
- **Security**: no subprocess, no exec, no network, safe YAML, no shell=True

All analysis is deterministic and offline. No GitHub, Docker, or external APIs.

## Limitations

- Only three CI/CD file types are supported initially. Future steps can add
  GitLab CI, CircleCI, Jenkins, etc.
- GitHub Actions analysis does not resolve reusable workflow calls or
  composite actions.
- Dockerfile analysis does not parse multi-stage builds or health checks.
- Docker Compose analysis does not resolve `${VAR}` interpolations for
  secret detection (they are intentionally not flagged).
- The `ADD` check only catches remote URLs; it does not detect path
  traversal within local archives.
- Secret detection uses heuristic name matching, not actual credential
  analysis. Legitimate non-secret variables matching the pattern will
  produce false positives.

## Future Extensions

- Additional CI/CD platforms (GitLab CI, CircleCI, Jenkins, Azure Pipelines)
- GitHub Actions reusable workflow resolution
- Docker Compose secret interpolation resolution
- CI/CD security best-practice scoring
- Integration with repository ingestion for automatic scanning
