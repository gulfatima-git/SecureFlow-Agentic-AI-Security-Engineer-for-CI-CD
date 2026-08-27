"""Data models for repository ingestion."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class FileCategory(StrEnum):
    """Classification of repository files by purpose."""

    SOURCE = "source"
    DEPENDENCY = "dependency"
    CICD = "cicd"
    CONFIG = "config"
    DOCUMENTATION = "documentation"
    OTHER = "other"


class ChangeStatus(StrEnum):
    """Git change status for a file."""

    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"
    UNTRACKED = "untracked"


class FileEntry(BaseModel):
    """A single file in the repository with classification metadata."""

    path: str
    category: FileCategory
    extension: str = ""


class FileChange(BaseModel):
    """A file change detected in the working tree."""

    path: str
    status: ChangeStatus


class GitHistoryEntry(BaseModel):
    """A single commit in the repository history."""

    sha: str
    author: str
    author_email: str
    timestamp: str
    message: str


class RepositoryContext(BaseModel):
    """Structured representation of an ingested repository.

    This is the primary output of RepositoryIngestor and serves as the
    controlled input for all downstream security analysis.
    """

    repository_name: str
    repository_url: str
    local_path: str
    commit_sha: str

    source_files: list[FileEntry] = Field(default_factory=list)
    dependency_files: list[FileEntry] = Field(default_factory=list)
    cicd_files: list[FileEntry] = Field(default_factory=list)
    config_files: list[FileEntry] = Field(default_factory=list)
    documentation_files: list[FileEntry] = Field(default_factory=list)
    other_files: list[FileEntry] = Field(default_factory=list)

    changed_files: list[FileChange] = Field(default_factory=list)
    diff: str = ""
    git_history: list[GitHistoryEntry] = Field(default_factory=list)

    metadata: dict[str, str] = Field(default_factory=dict)

    @property
    def all_files(self) -> list[FileEntry]:
        """Return all classified files as a flat list."""
        return (
            self.source_files
            + self.dependency_files
            + self.cicd_files
            + self.config_files
            + self.documentation_files
            + self.other_files
        )

    @property
    def total_file_count(self) -> int:
        """Return the total number of classified files."""
        return len(self.all_files)
