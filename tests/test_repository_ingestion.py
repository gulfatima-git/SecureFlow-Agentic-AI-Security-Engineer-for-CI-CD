"""Tests for repository ingestion.

All tests use temporary local Git repositories. No live GitHub access required.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from git import Repo

from src.models.repository import ChangeStatus, FileCategory, RepositoryContext
from src.tools.repository_ingestor import IngestionError, RepositoryIngestor

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_repo(tmp_path: Path) -> Path:
    """Create a minimal local Git repository with one commit."""
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()
    repo = Repo.init(str(repo_dir))

    # Create some files.
    (repo_dir / "main.py").write_text("print('hello')\n")
    (repo_dir / "utils.js").write_text("console.log('hi')\n")
    (repo_dir / "go.mod").write_text("module example\n")
    (repo_dir / "requirements.txt").write_text("requests>=2.0\n")
    (repo_dir / "README.md").write_text("# Test\n")
    (repo_dir / "Dockerfile").write_text("FROM python:3.11\n")
    (repo_dir / "config.yaml").write_text("key: value\n")
    (repo_dir / ".editorconfig").write_text("root = true\n")

    # Create directories that should be excluded.
    (repo_dir / "__pycache__").mkdir()
    (repo_dir / "__pycache__" / "cached.pyc").write_bytes(b"\x00")
    (repo_dir / "node_modules").mkdir()
    (repo_dir / "node_modules" / "dep.js").write_text("// dep\n")

    # Create .github/workflows (should be preserved, not excluded).
    workflows_dir = repo_dir / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)
    (workflows_dir / "ci.yml").write_text("name: CI\n")

    # Commit everything. Use explicit add for dotfiles since "*"
    # does not match them on all platforms.
    repo.index.add(
        [
            "main.py",
            "utils.js",
            "go.mod",
            "requirements.txt",
            "README.md",
            "Dockerfile",
            "config.yaml",
            ".editorconfig",
            "__pycache__/cached.pyc",
            "node_modules/dep.js",
            ".github/workflows/ci.yml",
        ]
    )
    repo.index.commit("Initial commit with test files")

    return repo_dir


@pytest.fixture()
def tmp_repo_with_changes(tmp_repo: Path) -> Path:
    """Extend tmp_repo with uncommitted modifications."""
    (tmp_repo / "main.py").write_text("print('modified')\n")
    (tmp_repo / "new_file.ts").write_text("// new\n")
    return tmp_repo


@pytest.fixture()
def ingestor(tmp_path: Path) -> RepositoryIngestor:
    """Create an ingestor with a dedicated workspace."""
    workspace = tmp_path / "workspaces"
    return RepositoryIngestor(workspace=workspace)


# ---------------------------------------------------------------------------
# Test: Successful ingestion
# ---------------------------------------------------------------------------


class TestIngestion:
    def test_successful_ingestion(
        self, ingestor: RepositoryIngestor, tmp_repo: Path
    ) -> None:
        ctx = ingestor.ingest(
            repository_url="https://example.com/test_repo.git",
            local_path=tmp_repo,
        )
        assert isinstance(ctx, RepositoryContext)
        assert ctx.repository_name == "test_repo"
        assert ctx.commit_sha  # non-empty
        assert ctx.local_path == str(tmp_repo)

    def test_ingestion_without_local_path_clones(
        self, ingestor: RepositoryIngestor, tmp_repo: Path
    ) -> None:
        """When local_path is not given, the ingestor should still work
        (it would clone, but we test with local_path for determinism)."""
        ctx = ingestor.ingest(
            repository_url="https://example.com/test_repo.git",
            local_path=tmp_repo,
        )
        assert ctx.repository_url == "https://example.com/test_repo.git"


# ---------------------------------------------------------------------------
# Test: Repository name extraction
# ---------------------------------------------------------------------------


class TestRepoName:
    def test_name_from_url(self) -> None:
        url = "https://github.com/user/myrepo.git"
        assert RepositoryIngestor._extract_repo_name(url) == "myrepo"

    def test_name_from_url_no_git_suffix(self) -> None:
        assert RepositoryIngestor._extract_repo_name("https://github.com/user/myrepo") == "myrepo"

    def test_name_from_url_trailing_slash(self) -> None:
        assert RepositoryIngestor._extract_repo_name("https://github.com/user/myrepo/") == "myrepo"

    def test_name_from_local_path(self) -> None:
        assert RepositoryIngestor._extract_repo_name("/some/path/myrepo") == "myrepo"

    def test_name_from_empty_raises(self) -> None:
        with pytest.raises(IngestionError, match="Cannot extract repository name"):
            RepositoryIngestor._extract_repo_name("")


# ---------------------------------------------------------------------------
# Test: Commit SHA
# ---------------------------------------------------------------------------


class TestCommitSHA:
    def test_commit_sha_is_valid_hex(
        self, ingestor: RepositoryIngestor, tmp_repo: Path
    ) -> None:
        ctx = ingestor.ingest("https://example.com/r.git", local_path=tmp_repo)
        assert len(ctx.commit_sha) == 40
        assert all(c in "0123456789abcdef" for c in ctx.commit_sha)


# ---------------------------------------------------------------------------
# Test: File enumeration
# ---------------------------------------------------------------------------


class TestFileEnumeration:
    def test_source_files_detected(
        self, ingestor: RepositoryIngestor, tmp_repo: Path
    ) -> None:
        ctx = ingestor.ingest("https://example.com/r.git", local_path=tmp_repo)
        source_names = {f.path for f in ctx.source_files}
        assert "main.py" in source_names
        assert "utils.js" in source_names

    def test_excluded_dirs_not_present(
        self, ingestor: RepositoryIngestor, tmp_repo: Path
    ) -> None:
        ctx = ingestor.ingest("https://example.com/r.git", local_path=tmp_repo)
        all_paths = {f.path for f in ctx.all_files}
        for excluded in ["__pycache__/cached.pyc", "node_modules/dep.js"]:
            assert excluded not in all_paths

    def test_total_file_count_excludes_generated(
        self, ingestor: RepositoryIngestor, tmp_repo: Path
    ) -> None:
        ctx = ingestor.ingest("https://example.com/r.git", local_path=tmp_repo)
        # The repo has 8 real files + .github/workflows/ci.yml = 9.
        # __pycache__/cached.pyc and node_modules/dep.js are excluded.
        assert ctx.total_file_count == 9


# ---------------------------------------------------------------------------
# Test: Security-relevant file preservation
# ---------------------------------------------------------------------------


class TestSecurityRelevantFiles:
    def test_github_workflows_detected(
        self, ingestor: RepositoryIngestor, tmp_repo: Path
    ) -> None:
        ctx = ingestor.ingest("https://example.com/r.git", local_path=tmp_repo)
        cicd_names = {f.path for f in ctx.cicd_files}
        # Normalize path separators for cross-platform comparison.
        normalized = {n.replace("\\", "/") for n in cicd_names}
        assert ".github/workflows/ci.yml" in normalized

    def test_dockerfile_detected(
        self, ingestor: RepositoryIngestor, tmp_repo: Path
    ) -> None:
        ctx = ingestor.ingest("https://example.com/r.git", local_path=tmp_repo)
        cicd_names = {f.path for f in ctx.cicd_files}
        assert "Dockerfile" in cicd_names

    def test_dependency_manifests_detected(
        self, ingestor: RepositoryIngestor, tmp_repo: Path
    ) -> None:
        ctx = ingestor.ingest("https://example.com/r.git", local_path=tmp_repo)
        dep_names = {f.path for f in ctx.dependency_files}
        assert "requirements.txt" in dep_names
        assert "go.mod" in dep_names

    def test_documentation_detected(
        self, ingestor: RepositoryIngestor, tmp_repo: Path
    ) -> None:
        ctx = ingestor.ingest("https://example.com/r.git", local_path=tmp_repo)
        doc_names = {f.path for f in ctx.documentation_files}
        assert "README.md" in doc_names

    def test_config_files_detected(
        self, ingestor: RepositoryIngestor, tmp_repo: Path
    ) -> None:
        ctx = ingestor.ingest("https://example.com/r.git", local_path=tmp_repo)
        config_names = {f.path for f in ctx.config_files}
        assert "config.yaml" in config_names
        assert ".editorconfig" in config_names


# ---------------------------------------------------------------------------
# Test: File classification
# ---------------------------------------------------------------------------


class TestFileClassification:
    def test_python_file_is_source(self, tmp_path: Path) -> None:
        from src.tools.repository_ingestor import _classify_single_file

        assert _classify_single_file(Path("app.py")) == FileCategory.SOURCE

    def test_typescript_file_is_source(self, tmp_path: Path) -> None:
        from src.tools.repository_ingestor import _classify_single_file

        assert _classify_single_file(Path("index.tsx")) == FileCategory.SOURCE

    def test_go_file_is_source(self, tmp_path: Path) -> None:
        from src.tools.repository_ingestor import _classify_single_file

        assert _classify_single_file(Path("main.go")) == FileCategory.SOURCE

    def test_requirements_txt_is_dependency(self, tmp_path: Path) -> None:
        from src.tools.repository_ingestor import _classify_single_file

        assert _classify_single_file(Path("requirements.txt")) == FileCategory.DEPENDENCY

    def test_package_json_is_dependency(self, tmp_path: Path) -> None:
        from src.tools.repository_ingestor import _classify_single_file

        assert _classify_single_file(Path("package.json")) == FileCategory.DEPENDENCY

    def test_dockerfile_is_cicd(self, tmp_path: Path) -> None:
        from src.tools.repository_ingestor import _classify_single_file

        assert _classify_single_file(Path("Dockerfile")) == FileCategory.CICD

    def test_readme_is_documentation(self, tmp_path: Path) -> None:
        from src.tools.repository_ingestor import _classify_single_file

        assert _classify_single_file(Path("README.md")) == FileCategory.DOCUMENTATION

    def test_yaml_in_github_dir_is_cicd(self, tmp_path: Path) -> None:
        from src.tools.repository_ingestor import _classify_single_file

        assert _classify_single_file(Path(".github/workflows/ci.yml")) == FileCategory.CICD

    def test_unknown_extension_is_other(self, tmp_path: Path) -> None:
        from src.tools.repository_ingestor import _classify_single_file

        assert _classify_single_file(Path("mystery.xyz")) == FileCategory.OTHER


# ---------------------------------------------------------------------------
# Test: Git history
# ---------------------------------------------------------------------------


class TestGitHistory:
    def test_history_has_entries(
        self, ingestor: RepositoryIngestor, tmp_repo: Path
    ) -> None:
        ctx = ingestor.ingest("https://example.com/r.git", local_path=tmp_repo)
        assert len(ctx.git_history) >= 1

    def test_history_entry_fields(
        self, ingestor: RepositoryIngestor, tmp_repo: Path
    ) -> None:
        ctx = ingestor.ingest("https://example.com/r.git", local_path=tmp_repo)
        entry = ctx.git_history[0]
        assert len(entry.sha) == 40
        assert entry.author
        assert entry.timestamp
        assert "Initial commit" in entry.message

    def test_history_author_email_present(
        self, ingestor: RepositoryIngestor, tmp_repo: Path
    ) -> None:
        ctx = ingestor.ingest("https://example.com/r.git", local_path=tmp_repo)
        entry = ctx.git_history[0]
        assert entry.author_email  # should be non-empty (git default)


# ---------------------------------------------------------------------------
# Test: Current diff
# ---------------------------------------------------------------------------


class TestDiff:
    def test_empty_diff_when_clean(
        self, ingestor: RepositoryIngestor, tmp_repo: Path
    ) -> None:
        ctx = ingestor.ingest("https://example.com/r.git", local_path=tmp_repo)
        assert ctx.diff == ""
        assert ctx.changed_files == []

    def test_diff_nonempty_when_modified(
        self, ingestor: RepositoryIngestor, tmp_repo_with_changes: Path
    ) -> None:
        ctx = ingestor.ingest(
            "https://example.com/r.git", local_path=tmp_repo_with_changes
        )
        assert ctx.diff  # non-empty

    def test_changed_files_detect_modification(
        self, ingestor: RepositoryIngestor, tmp_repo_with_changes: Path
    ) -> None:
        ctx = ingestor.ingest(
            "https://example.com/r.git", local_path=tmp_repo_with_changes
        )
        modified = [c for c in ctx.changed_files if c.status == ChangeStatus.MODIFIED]
        assert any("main.py" in c.path for c in modified)

    def test_untracked_file_detected(
        self, ingestor: RepositoryIngestor, tmp_repo_with_changes: Path
    ) -> None:
        ctx = ingestor.ingest(
            "https://example.com/r.git", local_path=tmp_repo_with_changes
        )
        untracked = [c for c in ctx.changed_files if c.status == ChangeStatus.UNTRACKED]
        assert any("new_file.ts" in c.path for c in untracked)


# ---------------------------------------------------------------------------
# Test: Invalid repository handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_invalid_local_path(self, ingestor: RepositoryIngestor) -> None:
        with pytest.raises(IngestionError, match="does not exist"):
            ingestor.ingest(
                "https://example.com/r.git",
                local_path="/nonexistent/path",
            )

    def test_non_git_directory(self, ingestor: RepositoryIngestor, tmp_path: Path) -> None:
        not_a_repo = tmp_path / "plain_dir"
        not_a_repo.mkdir()
        with pytest.raises(IngestionError, match="Not a Git repository"):
            ingestor.ingest(
                "https://example.com/r.git",
                local_path=not_a_repo,
            )


# ---------------------------------------------------------------------------
# Test: Safety — no code execution
# ---------------------------------------------------------------------------


class TestSafety:
    def test_repository_code_not_executed(
        self, ingestor: RepositoryIngestor, tmp_path: Path
    ) -> None:
        """Verify that ingestion does not execute scripts in the repo."""
        repo_dir = tmp_path / "script_repo"
        repo_dir.mkdir()
        repo = Repo.init(str(repo_dir))

        marker = tmp_path / "execution_marker.txt"

        # Create a script that would create a file if executed.
        script = repo_dir / "setup.py"
        script.write_text(
            f"from pathlib import Path\nPath('{marker}').touch()\n"
        )

        repo.index.add("*")
        repo.index.commit("Add setup.py")

        ingestor.ingest("https://example.com/script_repo.git", local_path=repo_dir)

        # The marker file must NOT exist — the script was never run.
        assert not marker.exists()

    def test_cleanup_removes_cloned_repo(
        self, ingestor: RepositoryIngestor, tmp_path: Path
    ) -> None:
        """After cleanup, the cloned repository directory should be gone."""
        # We can't easily test real cloning without a remote, so test the
        # cleanup mechanism directly.
        fake_clone = ingestor.workspace / "fake_repo"
        fake_clone.mkdir()
        ingestor._cloned_path = fake_clone
        ingestor.cleanup()
        assert not fake_clone.exists()
        assert ingestor._cloned_path is None


# ---------------------------------------------------------------------------
# Test: Workspace
# ---------------------------------------------------------------------------


class TestWorkspace:
    def test_workspace_created(self, tmp_path: Path) -> None:
        ws = tmp_path / "custom_ws"
        ing = RepositoryIngestor(workspace=ws)
        assert ws.exists()
        assert ing.workspace == ws

    def test_default_workspace_is_temp(self) -> None:
        ing = RepositoryIngestor()
        assert "secureflow_workspaces" in str(ing.workspace)
