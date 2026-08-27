# Repository Ingestion

Step 6 of the SecureFlow execution plan. Provides the controlled boundary between
external repositories and SecureFlow's analysis components.

## Purpose

SecureFlow's agents must not directly wander an arbitrary filesystem. Repository
ingestion clones (or accepts) a repository, inspects its structure, and produces
a structured `RepositoryContext` that serves as the sole input for downstream
security tools and agents.

```
Repository URL or local path
    ↓
RepositoryIngestor.ingest()
    ↓
RepositoryContext
    ↓
Future security tools / agents
```

## RepositoryContext

The primary output data model. Defined in `src/models/repository.py`.

| Field | Type | Description |
|---|---|---|
| `repository_name` | `str` | Extracted name from URL or path |
| `repository_url` | `str` | Original URL or path provided |
| `local_path` | `str` | Filesystem path to the repository |
| `commit_sha` | `str` | Full SHA of the checked-out commit |
| `source_files` | `list[FileEntry]` | Files classified as source code |
| `dependency_files` | `list[FileEntry]` | Dependency manifests and lockfiles |
| `cicd_files` | `list[FileEntry]` | CI/CD configuration files |
| `config_files` | `list[FileEntry]` | General configuration files |
| `documentation_files` | `list[FileEntry]` | Documentation and license files |
| `other_files` | `list[FileEntry]` | Unclassified files |
| `changed_files` | `list[FileChange]` | Working-tree modifications |
| `diff` | `str` | Full diff of uncommitted changes |
| `git_history` | `list[GitHistoryEntry]` | Recent commit history |
| `metadata` | `dict[str, str]` | Additional repository metadata |

Helper properties: `all_files` (flat list), `total_file_count`.

## RepositoryIngestor API

Defined in `src/tools/repository_ingestor.py`.

```python
from src.tools import RepositoryIngestor

ingestor = RepositoryIngestor()
ctx = ingestor.ingest(
    repository_url="https://github.com/user/repo.git",
    local_path="/optional/local/path",  # skips clone if provided
)
# ... use ctx ...
ingestor.cleanup()  # removes cloned repo if applicable
```

### Methods

- `ingest(repository_url, local_path=None)` → `RepositoryContext`
- `cleanup()` — removes any cloned repository from the workspace

### Constructor

- `RepositoryIngestor(workspace=None)` — custom workspace directory for clones;
  defaults to `<tempdir>/secureflow_workspaces`.

## File Classification

Files are classified by deterministic extension/name matching into six categories:

| Category | Examples |
|---|---|
| **Source** | `.py`, `.js`, `.ts`, `.tsx`, `.go`, `.java`, `.c`, `.cpp`, `.rs`, `.rb` |
| **Dependency** | `requirements.txt`, `package.json`, `go.mod`, `Cargo.toml`, `pom.xml`, lockfiles |
| **CI/CD** | `.github/workflows/*.yml`, `Dockerfile`, `docker-compose.yml`, `Makefile` |
| **Config** | `.yaml`, `.toml`, `.json`, `.editorconfig`, `tsconfig.json` |
| **Documentation** | `.md`, `.rst`, `LICENSE`, `README.md` |
| **Other** | Anything not matching the above |

## Excluded Directories

The following directories are excluded from file enumeration because they
contain generated/environment content with no security-relevant source:

`.git`, `.venv`, `venv`, `ENV`, `__pycache__`, `node_modules`, `build`,
`dist`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `.tox`, `.eggs`,
`*.egg-info`

Security-relevant paths (`.github/workflows/`, `Dockerfile`, dependency
manifests) are explicitly **preserved** regardless of directory depth.

## Git Metadata

### History

The 50 most recent commits are extracted with:

- Commit SHA
- Author name and email
- Timestamp
- Commit message

### Diff

The full working-tree diff (`git diff HEAD`) is captured as a string.
Uncommitted modifications are listed as `FileChange` objects with status:
`added`, `modified`, `deleted`, `renamed`, or `untracked`.

## Safety

Repository contents are **untrusted input**. The ingestion layer:

- **Never** executes repository code (no `setup.py`, `make`, scripts, etc.)
- **Never** installs repository dependencies
- **Never** builds Docker images or runs containers
- Treats all repository files as data only
- Uses controlled workspace directories for clones
- Handles cleanup explicitly via `cleanup()`

## Error Handling

Common failures raise `IngestionError` with descriptive messages:

- Invalid or inaccessible repository URL
- Non-existent local path
- Directory that is not a Git repository
- Clone failure
- Filesystem errors

## Dependencies

- **pydantic** — data validation and structured models for `RepositoryContext`
- **gitpython** — Git operations (clone, history, diff, metadata)
