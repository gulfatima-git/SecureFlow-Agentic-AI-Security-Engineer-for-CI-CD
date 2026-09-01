"""Tests for the GitHub integration boundary (Step 21).

All tests are offline and deterministic.  They use synthetic JSON
payloads only; no network requests, no shell/subprocess execution, and
no repository modifications are performed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import src.github.webhook as webhook_module
from src.github import (
    GitHubPREvent,
    PRAction,
    PRFile,
    UnsupportedActionError,
    WebhookPayloadError,
    parse_pr_webhook,
    to_repository_context,
    webhook_handler,
)
from src.models.repository import ChangeStatus, RepositoryContext

# -- Helpers ---------------------------------------------------------------


def file_entry(filename: str, status: str = "modified", **kw) -> dict:
    """Build a single GitHub changed-file entry."""
    entry = {"filename": filename, "status": status}
    entry.update(kw)
    return entry


def pr_payload(
    *,
    action: str = "opened",
    full_name: str = "octocat/hello-world",
    pr_number: int = 42,
    head_sha: str = "a" * 40,
    base_sha: str = "b" * 40,
    files: list[dict] | None = None,
    title: str = "Fix vuln",
    author: str = "octocat",
    draft: bool = False,
    **extra,
) -> dict:
    """Build a synthetic, valid GitHub pull_request webhook payload."""
    files = files if files is not None else [file_entry("src/app.py")]
    payload = {
        "action": action,
        "repository": {
            "full_name": full_name,
        },
        "pull_request": {
            "number": pr_number,
            "title": title,
            "draft": draft,
            "user": {"login": author},
            "head": {"sha": head_sha},
            "base": {"sha": base_sha},
        },
        "files": files,
    }
    payload.update(extra)
    return payload


# -- Valid payloads --------------------------------------------------------


class TestValidPayloads:
    def test_opened(self):
        event = parse_pr_webhook(pr_payload(action="opened"))
        assert isinstance(event, GitHubPREvent)
        assert event.action == PRAction.OPENED
        assert event.pr_number == 42

    def test_synchronize(self):
        event = parse_pr_webhook(pr_payload(action="synchronize"))
        assert event.action == PRAction.SYNCHRONIZE

    def test_reopened(self):
        event = parse_pr_webhook(pr_payload(action="reopened"))
        assert event.action == PRAction.REOPENED

    def test_repository_fields_normalized(self):
        event = parse_pr_webhook(pr_payload(full_name="org/my-repo"))
        assert event.repository_full_name == "org/my-repo"
        assert event.repository_owner == "org"
        assert event.repository_name == "my-repo"

    def test_metadata(self):
        event = parse_pr_webhook(
            pr_payload(title="Fix XSS", author="dev", draft=True)
        )
        assert event.title == "Fix XSS"
        assert event.author == "dev"
        assert event.draft is True
        assert event.metadata["source"] == "github_webhook"

    def test_head_sha_normalized_to_lowercase(self):
        event = parse_pr_webhook(
            pr_payload(head_sha="A" * 40, base_sha="B" * 40)
        )
        assert event.head_sha == "a" * 40
        assert event.base_sha == "b" * 40

    def test_multiple_changed_files(self):
        payload = pr_payload(
            files=[
                file_entry("src/app.py", status="modified", additions=4, deletions=1),
                file_entry("requirements.txt", status="added", additions=3),
                file_entry("tests/test_app.py", status="modified"),
            ]
        )
        event = parse_pr_webhook(payload)
        assert len(event.changed_files) == 3
        assert [f.filename for f in event.changed_files] == [
            "src/app.py",
            "requirements.txt",
            "tests/test_app.py",
        ]

    def test_empty_changed_file_list(self):
        event = parse_pr_webhook(pr_payload(files=[]))
        assert event.changed_files == []

    def test_missing_files_field_treated_as_empty(self):
        payload = pr_payload()
        payload.pop("files", None)
        event = parse_pr_webhook(payload)
        assert event.changed_files == []

    def test_additions_and_deletions(self):
        event = parse_pr_webhook(
            pr_payload(
                files=[file_entry("a.py", additions=10, deletions=2, changes=12)]
            )
        )
        f = event.changed_files[0]
        assert f.additions == 10
        assert f.deletions == 2
        assert f.changes == 12


# -- Unsupported and invalid actions ---------------------------------------


class TestUnsupportedActions:
    def test_closed_raises_unsupported(self):
        with pytest.raises(UnsupportedActionError):
            parse_pr_webhook(pr_payload(action="closed"))

    def test_labeled_raises_unsupported(self):
        with pytest.raises(UnsupportedActionError):
            parse_pr_webhook(pr_payload(action="labeled"))

    def test_edited_raises_unsupported(self):
        with pytest.raises(UnsupportedActionError):
            parse_pr_webhook(pr_payload(action="edited"))

    def test_none_action_missing(self):
        payload = pr_payload()
        payload["action"] = None
        with pytest.raises(WebhookPayloadError):
            parse_pr_webhook(payload)

    def test_closed_does_not_trigger_via_handler(self):
        with pytest.raises(UnsupportedActionError):
            webhook_handler(pr_payload(action="closed"))


# -- Webhook handler -------------------------------------------------------


class TestWebhookHandler:
    def test_non_pull_request_event_returns_none(self):
        payload = pr_payload()
        result = webhook_handler(payload, event_type="ping")
        assert result is None

    def test_pull_request_event_parses(self):
        result = webhook_handler(pr_payload(action="opened"))
        assert isinstance(result, GitHubPREvent)
        assert result.pr_number == 42

    def test_synchronize_via_handler(self):
        result = webhook_handler(pr_payload(action="synchronize"))
        assert result is not None
        assert result.action == PRAction.SYNCHRONIZE


# -- Malformed payloads ----------------------------------------------------


class TestMalformedPayloads:
    def test_missing_repository(self):
        payload = pr_payload()
        payload.pop("repository", None)
        with pytest.raises(WebhookPayloadError):
            parse_pr_webhook(payload)

    def test_repository_not_dict(self):
        payload = pr_payload()
        payload["repository"] = "not-a-dict"
        with pytest.raises(WebhookPayloadError):
            parse_pr_webhook(payload)

    def test_missing_repository_full_name(self):
        payload = pr_payload()
        payload["repository"] = {}
        with pytest.raises(WebhookPayloadError):
            parse_pr_webhook(payload)

    def test_invalid_repository_full_name_single_part(self):
        payload = pr_payload(full_name="just-onepart")
        with pytest.raises(WebhookPayloadError):
            parse_pr_webhook(payload)

    def test_missing_pr_number(self):
        payload = pr_payload()
        payload["pull_request"].pop("number", None)
        with pytest.raises(WebhookPayloadError):
            parse_pr_webhook(payload)

    def test_pr_number_zero_rejected(self):
        payload = pr_payload(pr_number=0)
        payload["pull_request"]["number"] = 0
        with pytest.raises(WebhookPayloadError):
            parse_pr_webhook(payload)

    def test_pr_number_negative_rejected(self):
        payload = pr_payload()
        payload["pull_request"]["number"] = -5
        with pytest.raises(WebhookPayloadError):
            parse_pr_webhook(payload)

    def test_pr_number_non_int(self):
        payload = pr_payload()
        payload["pull_request"]["number"] = "42"
        with pytest.raises(WebhookPayloadError):
            parse_pr_webhook(payload)

    def test_missing_head_sha(self):
        payload = pr_payload()
        payload["pull_request"]["head"] = {}
        with pytest.raises(WebhookPayloadError):
            parse_pr_webhook(payload)

    def test_missing_pull_request_dict(self):
        payload = pr_payload()
        payload.pop("pull_request", None)
        with pytest.raises(WebhookPayloadError):
            parse_pr_webhook(payload)

    def test_empty_head_sha(self):
        payload = pr_payload(head_sha="")
        with pytest.raises(WebhookPayloadError):
            parse_pr_webhook(payload)

    def test_short_head_sha_rejected(self):
        payload = pr_payload(head_sha="abc")
        with pytest.raises(WebhookPayloadError):
            parse_pr_webhook(payload)

    def test_head_sha_non_hex(self):
        payload = pr_payload(head_sha="z" * 40)
        with pytest.raises(WebhookPayloadError):
            parse_pr_webhook(payload)

    def test_base_sha_optional(self):
        payload = pr_payload()
        payload["pull_request"]["base"] = {}
        event = parse_pr_webhook(payload)
        assert event.base_sha == ""

    def test_not_a_dict_payload(self):
        with pytest.raises(WebhookPayloadError):
            parse_pr_webhook("not-a-dict")  # type: ignore[arg-type]

    def test_empty_payload(self):
        with pytest.raises(WebhookPayloadError):
            parse_pr_webhook({})

    def test_none_payload(self):
        with pytest.raises(WebhookPayloadError):
            parse_pr_webhook(None)  # type: ignore[arg-type]


# -- Malformed changed-file data -------------------------------------------


class TestMalformedChangedFiles:
    def test_files_not_a_list_ignored(self):
        payload = pr_payload()
        payload["files"] = "not-a-list"
        event = parse_pr_webhook(payload)
        assert event.changed_files == []

    def test_file_entry_not_dict_skipped(self):
        payload = pr_payload(files=["not-a-dict", file_entry("a.py")])
        event = parse_pr_webhook(payload)
        assert event.changed_files == [PRFile(filename="a.py", status="modified")]

    def test_file_missing_filename_skipped(self):
        payload = pr_payload(files=[{"status": "modified"}])
        event = parse_pr_webhook(payload)
        assert event.changed_files == []

    def test_file_empty_filename_skipped(self):
        payload = pr_payload(files=[file_entry("")])
        event = parse_pr_webhook(payload)
        assert event.changed_files == []

    def test_negative_additions_clamped_to_zero(self):
        payload = pr_payload(files=[file_entry("a.py", additions=-5)])
        event = parse_pr_webhook(payload)
        assert event.changed_files[0].additions == 0

    def test_non_int_additions_coerced(self):
        payload = pr_payload(files=[file_entry("a.py", additions="5")])
        event = parse_pr_webhook(payload)
        assert event.changed_files[0].additions == 5


# -- Path traversal --------------------------------------------------------


class TestPathTraversal:
    def test_parent_directory_rejected(self):
        payload = pr_payload(files=[file_entry("../outside/file.py")])
        event = parse_pr_webhook(payload)
        assert event.changed_files == []

    def test_repeated_dotdot_rejected(self):
        payload = pr_payload(files=[file_entry("../../etc/passwd")])
        event = parse_pr_webhook(payload)
        assert event.changed_files == []

    def test_absolute_path_rejected(self):
        payload = pr_payload(files=[file_entry("/etc/passwd")])
        event = parse_pr_webhook(payload)
        assert event.changed_files == []

    def test_nested_dotdot_rejected(self):
        payload = pr_payload(files=[file_entry("src/../../config.yml")])
        event = parse_pr_webhook(payload)
        assert event.changed_files == []

    def test_backslash_dotdot_rejected(self):
        payload = pr_payload(files=[file_entry("..\\..\\evil.py")])
        event = parse_pr_webhook(payload)
        assert event.changed_files == []

    def test_null_byte_rejected(self):
        payload = pr_payload(files=[file_entry("a\x00b.py")])
        event = parse_pr_webhook(payload)
        assert event.changed_files == []

    def test_home_tilde_rejected(self):
        payload = pr_payload(files=[file_entry("~/secret")])
        event = parse_pr_webhook(payload)
        assert event.changed_files == []

    def test_legitimate_paths_preserved(self):
        payload = pr_payload(
            files=[
                file_entry(".github/workflows/ci.yml"),
                file_entry("src/app/__init__.py"),
                file_entry("README.md"),
            ]
        )
        event = parse_pr_webhook(payload)
        assert len(event.changed_files) == 3

    def test_mixed_traversal_and_valid_filtered(self):
        payload = pr_payload(
            files=[
                file_entry("../evil.py"),
                file_entry("src/good.py"),
            ]
        )
        event = parse_pr_webhook(payload)
        assert [f.filename for f in event.changed_files] == ["src/good.py"]


# -- Determinism -----------------------------------------------------------


class TestDeterminism:
    def test_same_input_same_output(self):
        payload = pr_payload()
        assert parse_pr_webhook(payload) == parse_pr_webhook(payload)

    def test_different_inputs_differ(self):
        a = parse_pr_webhook(pr_payload(pr_number=1))
        b = parse_pr_webhook(pr_payload(pr_number=2))
        assert a != b

    def test_model_serialization_round_trip(self):
        event = parse_pr_webhook(pr_payload())
        restored = GitHubPREvent.model_validate(event.model_dump())
        assert restored == event


# -- No execution / side effects -------------------------------------------


class TestNoExecution:
    def test_no_subprocess_import_in_webhook_module(self):
        assert not hasattr(webhook_module, "subprocess")

    def test_no_repository_access_in_src(self):
        github_dir = Path(webhook_module.__file__).parent
        patterns = [
            "import subprocess",
            "from subprocess",
            "os.system(",
            "os.popen(",
            "shutil.",
            "git clone ",
            "clone(",
            "requests.get(",
            "requests.post(",
            "urllib.request",
            "httpx.",
        ]
        for py_file in github_dir.glob("*.py"):
            source = py_file.read_text(encoding="utf-8")
            for pattern in patterns:
                assert pattern not in source, (
                    f"{pattern!r} found in {py_file.name}"
                )


# -- to_repository_context adapter ----------------------------------------


class TestRepositoryContextAdapter:
    def _event(self, **kw) -> GitHubPREvent:
        return parse_pr_webhook(pr_payload(**kw))

    def test_basic_conversion(self):
        ctx = to_repository_context(self._event())
        assert isinstance(ctx, RepositoryContext)
        assert ctx.repository_name == "octocat/hello-world"
        assert ctx.repository_url == "https://github.com/octocat/hello-world.git"
        assert ctx.commit_sha == "a" * 40

    def test_changed_files_mapped(self):
        event = parse_pr_webhook(
            pr_payload(
                files=[
                    file_entry("a.py", status="added"),
                    file_entry("b.py", status="modified"),
                    file_entry("del.py", status="removed"),
                ]
            )
        )
        ctx = to_repository_context(event)
        statuses = {f.path: f.status for f in ctx.changed_files}
        assert statuses["a.py"] == ChangeStatus.ADDED
        assert statuses["b.py"] == ChangeStatus.MODIFIED
        assert statuses["del.py"] == ChangeStatus.DELETED

    def test_metadata_carries_pr_info(self):
        ctx = to_repository_context(self._event(pr_number=7, title="T"))
        assert ctx.metadata["pr_number"] == "7"
        assert ctx.metadata["pr_title"] == "T"
        assert ctx.metadata["head_sha"] == "a" * 40

    def test_local_path_empty(self):
        ctx = to_repository_context(self._event())
        assert ctx.local_path == ""


# -- Signature verification ------------------------------------------------


class TestSignatureVerification:
    def test_valid_signature(self):
        payload = b'{"foo": "bar"}'
        secret = "s3cret"
        import hashlib
        import hmac

        header = "sha256=" + hmac.new(
            secret.encode(), payload, hashlib.sha256
        ).hexdigest()
        assert webhook_module.verify_signature(payload, header, secret) is True

    def test_empty_secret_returns_false(self):
        assert (
            webhook_module.verify_signature(b"x", "sha256=abc", "") is False
        )

    def test_empty_header_returns_false(self):
        assert webhook_module.verify_signature(b"x", "", "secret") is False

    def test_wrong_secret_returns_false(self):
        payload = b"data"
        import hashlib
        import hmac

        header = "sha256=" + hmac.new(
            b"right", payload, hashlib.sha256
        ).hexdigest()
        assert webhook_module.verify_signature(payload, header, "wrong") is False
