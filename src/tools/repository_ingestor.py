"""Repository ingestion: clone, inspect, and produce structured RepositoryContext."""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path

from git import GitCommandError, InvalidGitRepositoryError, Repo

from src.models.repository import (
    ChangeStatus,
    FileCategory,
    FileChange,
    FileEntry,
    GitHistoryEntry,
    RepositoryContext,
)

# Directories excluded from file enumeration.
# These are generated/environment directories that contain no security-relevant
# source code. Security-relevant configuration (.github/workflows, Dockerfile,
# dependency manifests) is explicitly preserved.
EXCLUDED_DIRS: set[str] = {
    ".git",
    ".venv",
    "venv",
    "ENV",
    "__pycache__",
    "node_modules",
    "build",
    "dist",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".eggs",
    "*.egg-info",
}

# File extensions classified as source code.
SOURCE_EXTENSIONS: set[str] = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".java",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".rs",
    ".rb",
    ".php",
    ".cs",
    ".swift",
    ".kt",
    ".scala",
    ".sh",
    ".bash",
}

# Dependency manifest filenames (case-sensitive).
DEPENDENCY_FILENAMES: set[str] = {
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
}

# CI/CD file patterns (matched against the filename or path).
CICD_FILENAMES: set[str] = {
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".dockerignore",
    "Makefile",
    "Procfile",
    "Vagrantfile",
}

# Directories whose contents are classified as CI/CD.
CICD_DIRS: set[str] = {".github", ".gitlab-ci", ".circleci", ".travis.yml"}

# Configuration file extensions and names.
CONFIG_EXTENSIONS: set[str] = {".cfg", ".ini", ".toml", ".yaml", ".yml", ".json", ".xml"}
CONFIG_FILENAMES: set[str] = {
    ".editorconfig",
    ".eslintrc",
    ".eslintrc.js",
    ".eslintrc.json",
    ".prettierrc",
    ".prettierrc.json",
    "tsconfig.json",
    "ruff.toml",
    ".ruff.toml",
    "mypy.ini",
    ".mypy.ini",
    "tox.ini",
    "pytest.ini",
}

# Documentation extensions and filenames.
DOC_EXTENSIONS: set[str] = {".md", ".rst", ".txt"}
DOC_FILENAMES: set[str] = {
    "LICENSE", "LICENSE.txt", "LICENSE.md",
    "CONTRIBUTING.md", "CHANGELOG.md",
}


class IngestionError(Exception):
    """Raised when repository ingestion fails."""


class RepositoryIngestor:
    """Clones (or accepts) a repository and produces a structured RepositoryContext.

    The ingestor treats repository contents as untrusted data. It never executes
    repository code, installs dependencies, or runs build scripts.
    """

    def __init__(self, workspace: str | Path | None = None) -> None:
        """Initialize the ingestor.

        Args:
            workspace: Directory where repositories are cloned. If None, a
                system temporary directory is used.
        """
        if workspace:
            self._workspace = Path(workspace)
        else:
            self._workspace = Path(tempfile.gettempdir()) / "secureflow_workspaces"
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._cloned_path: Path | None = None

    @property
    def workspace(self) -> Path:
        return self._workspace

    def ingest(
        self,
        repository_url: str,
        local_path: str | Path | None = None,
    ) -> RepositoryContext:
        """Ingest a repository from a URL or local path.

        If ``local_path`` is provided, the repository at that path is used
        directly (no clone). Otherwise the repository is cloned into the workspace.

        Args:
            repository_url: The URL or local path of the repository.
            local_path: Optional local path to an already-cloned repository.
                When provided, ``repository_url`` is used only as metadata.

        Returns:
            A fully populated RepositoryContext.

        Raises:
            IngestionError: If ingestion fails for any reason.
        """
        try:
            if local_path is not None:
                repo_path = Path(local_path)
                if not repo_path.is_dir():
                    raise IngestionError(f"Local path does not exist: {repo_path}")
                if not (repo_path / ".git").is_dir():
                    raise IngestionError(f"Not a Git repository (no .git directory): {repo_path}")
                self._cloned_path = None  # We did not clone; do not clean up.
            else:
                repo_path = self._clone(repository_url)
                self._cloned_path = repo_path

            repo = Repo(repo_path)
            return self._build_context(repo, repository_url, repo_path)

        except IngestionError:
            raise
        except InvalidGitRepositoryError as exc:
            raise IngestionError(f"Invalid Git repository: {exc}") from exc
        except GitCommandError as exc:
            raise IngestionError(f"Git command failed: {exc}") from exc
        except OSError as exc:
            raise IngestionError(f"Filesystem error during ingestion: {exc}") from exc

    def cleanup(self) -> None:
        """Remove any repository that was cloned by this ingestor."""
        if self._cloned_path and self._cloned_path.is_dir():
            shutil.rmtree(self._cloned_path, ignore_errors=True)
            self._cloned_path = None

    # -- Internal helpers ---------------------------------------------------

    def _clone(self, url: str) -> Path:
        """Clone a repository into the workspace and return its path."""
        name = self._extract_repo_name(url)
        dest = self._workspace / name
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        try:
            Repo.clone_from(url, str(dest))
        except GitCommandError as exc:
            raise IngestionError(f"Failed to clone {url}: {exc}") from exc
        return dest

    @staticmethod
    def _extract_repo_name(url: str) -> str:
        """Extract a repository name from a URL or local path."""
        # Strip trailing .git suffix and slashes.
        cleaned = re.sub(r"\.git$", "", url)
        cleaned = cleaned.rstrip("/")
        name = Path(cleaned).name
        if not name:
            raise IngestionError(f"Cannot extract repository name from: {url}")
        return name

    @staticmethod
    def _build_context(repo: Repo, url: str, path: Path) -> RepositoryContext:
        """Build a RepositoryContext from an opened GitPython Repo."""
        commit_sha = repo.head.commit.hexsha
        repo_name = Path(path).name

        all_repo_files = _enumerate_files(path)
        classified = _classify_files(all_repo_files, path)

        history = _extract_history(repo)
        diff, changed = _extract_diff_and_changes(repo)

        # Gather metadata.
        try:
            default_branch = repo.active_branch.name
        except TypeError:
            default_branch = "HEAD (detached)"

        metadata: dict[str, str] = {
            "default_branch": default_branch,
            "commit_count": str(len(list(repo.iter_commits("HEAD")))),
        }

        return RepositoryContext(
            repository_name=repo_name,
            repository_url=url,
            local_path=str(path),
            commit_sha=commit_sha,
            source_files=classified.get(FileCategory.SOURCE, []),
            dependency_files=classified.get(FileCategory.DEPENDENCY, []),
            cicd_files=classified.get(FileCategory.CICD, []),
            config_files=classified.get(FileCategory.CONFIG, []),
            documentation_files=classified.get(FileCategory.DOCUMENTATION, []),
            other_files=classified.get(FileCategory.OTHER, []),
            changed_files=changed,
            diff=diff,
            git_history=history,
            metadata=metadata,
        )


# -- Module-level helpers ---------------------------------------------------


def _is_excluded(rel_path: Path) -> bool:
    """Check if a relative path should be excluded from enumeration."""
    parts = rel_path.parts
    for part in parts:
        if part in EXCLUDED_DIRS:
            return True
        # Handle glob-style patterns like *.egg-info.
        if part.endswith(".egg-info"):
            return True
    return False


def _enumerate_files(repo_path: Path) -> list[Path]:
    """Enumerate all non-excluded files in the repository."""
    result: list[Path] = []
    for item in sorted(repo_path.rglob("*")):
        if not item.is_file():
            continue
        rel = item.relative_to(repo_path)
        if _is_excluded(rel):
            continue
        result.append(rel)
    return result


def _classify_single_file(rel_path: Path) -> FileCategory:
    """Classify a single file by its extension and name."""
    name = rel_path.name
    suffix = rel_path.suffix.lower()
    parts = rel_path.parts

    # CI/CD: check directory membership first.
    if any(d in CICD_DIRS for d in parts):
        return FileCategory.CICD

    # Dependency manifests.
    if name in DEPENDENCY_FILENAMES:
        return FileCategory.DEPENDENCY

    # CI/CD files.
    if name in CICD_FILENAMES:
        return FileCategory.CICD

    # Documentation.
    if name in DOC_FILENAMES:
        return FileCategory.DOCUMENTATION
    if suffix in DOC_EXTENSIONS:
        return FileCategory.DOCUMENTATION

    # Config files.
    if name in CONFIG_FILENAMES:
        return FileCategory.CONFIG
    if suffix in CONFIG_EXTENSIONS:
        return FileCategory.CONFIG

    # Source files.
    if suffix in SOURCE_EXTENSIONS:
        return FileCategory.SOURCE

    return FileCategory.OTHER


def _classify_files(
    files: list[Path], repo_path: Path
) -> dict[FileCategory, list[FileEntry]]:
    """Classify a list of repository files into categories."""
    result: dict[FileCategory, list[FileEntry]] = {cat: [] for cat in FileCategory}
    for rel_path in files:
        category = _classify_single_file(rel_path)
        entry = FileEntry(
            path=str(rel_path),
            category=category,
            extension=rel_path.suffix.lower(),
        )
        result[category].append(entry)
    return result


def _extract_history(repo: Repo, max_entries: int = 50) -> list[GitHistoryEntry]:
    """Extract recent Git history as structured entries."""
    entries: list[GitHistoryEntry] = []
    for commit in repo.iter_commits("HEAD", max_count=max_entries):
        entries.append(
            GitHistoryEntry(
                sha=commit.hexsha,
                author=str(commit.author),
                author_email=commit.author.email or "",
                timestamp=str(commit.committed_datetime),
                message=str(commit.message).strip(),
            )
        )
    return entries


def _map_status(flag: str) -> ChangeStatus:
    """Map a GitPython diff flag to a ChangeStatus."""
    mapping: dict[str, ChangeStatus] = {
        "A": ChangeStatus.ADDED,
        "M": ChangeStatus.MODIFIED,
        "D": ChangeStatus.DELETED,
        "R": ChangeStatus.RENAMED,
    }
    return mapping.get(flag, ChangeStatus.MODIFIED)


def _extract_diff_and_changes(
    repo: Repo,
) -> tuple[str, list[FileChange]]:
    """Extract the working-tree diff and a list of changed files."""
    # Staged + unstaged changes against HEAD.
    try:
        diff_output: str = repo.git.diff("HEAD")
    except GitCommandError:
        diff_output = ""

    changed: list[FileChange] = []
    try:
        # index.diff(None) compares working tree against index (unstaged changes).
        diff_index = repo.index.diff(None)
        for diff_entry in diff_index:
            status_flag = diff_entry.new_file and "A" or diff_entry.deleted_file and "D" or "M"
            if diff_entry.renamed_file:
                status_flag = "R"
            changed.append(
                FileChange(
                    path=diff_entry.a_path or diff_entry.b_path or "",
                    status=_map_status(status_flag),
                )
            )
    except GitCommandError:
        pass

    # Also check for untracked files.
    try:
        untracked = repo.untracked_files
        for ut in untracked:
            changed.append(FileChange(path=ut, status=ChangeStatus.UNTRACKED))
    except GitCommandError:
        pass

    return diff_output, changed
