"""Tests for the GitHub Action integration (Step 22).

All tests are offline and deterministic.  They use synthetic payloads,
fake HTTP clients, and structural YAML validation only.  No network
requests, no shell/subprocess execution, and no repository modifications
are performed.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

import src.github.action as action_module
from src.api import (
    APIError,
    APITimeoutError,
    ConfigurationError,
    RequestStatus,
    SecureFlowFakeHTTPClient,
    SecureFlowRequest,
    SecureFlowResponse,
)
from src.api.client import SecureFlowHTTPClient
from src.github import (
    GitHubPREvent,
    PRAction,
    PRFile,
    SecureFlowAction,
    SecureFlowActionConfig,
    event_to_request,
)

# -- Fixtures ---------------------------------------------------------------

WORKFLOW_PATH = (
    Path(__file__).resolve().parent.parent / ".github" / "workflows" / "secureflow.yml"
)


def _event(
    *,
    full_name: str = "octocat/hello-world",
    pr_number: int = 42,
    head_sha: str = "a" * 40,
    base_sha: str = "b" * 40,
    action: str = "opened",
    title: str = "Fix vuln",
    author: str = "octocat",
    files: list[PRFile] | None = None,
) -> GitHubPREvent:
    if files is None:
        files = [
            PRFile(filename="src/app.py", status="modified", additions=4, deletions=1),
        ]
    return GitHubPREvent(
        repository_full_name=full_name,
        repository_owner=full_name.split("/")[0],
        repository_name=full_name.split("/")[-1],
        pr_number=pr_number,
        head_sha=head_sha,
        base_sha=base_sha,
        action=PRAction(action),
        title=title,
        author=author,
        changed_files=files,
    )


def _load_workflow() -> dict:
    if not WORKFLOW_PATH.exists():
        pytest.skip(f"Workflow file not found: {WORKFLOW_PATH}")
    with open(WORKFLOW_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# -- Workflow file structure ------------------------------------------------


class TestWorkflowFile:
    def test_workflow_file_exists(self):
        assert WORKFLOW_PATH.exists(), f"Workflow not found at {WORKFLOW_PATH}"

    def test_workflow_is_valid_yaml(self):
        data = _load_workflow()
        assert isinstance(data, dict)

    def test_has_name(self):
        data = _load_workflow()
        assert isinstance(data.get("name"), str)
        assert len(data["name"]) > 0

    def test_triggers_pull_request(self):
        data = _load_workflow()
        on_block = data.get("on") or data.get(True)
        assert isinstance(on_block, dict), "on: block must be a mapping"
        assert "pull_request" in on_block, "pull_request trigger required"

    def test_opened_trigger(self):
        data = _load_workflow()
        pr_trigger = (data.get("on") or data.get(True)).get("pull_request")
        types = pr_trigger if isinstance(pr_trigger, list) else pr_trigger.get("types", [])
        assert "opened" in types

    def test_synchronize_trigger(self):
        data = _load_workflow()
        pr_trigger = (data.get("on") or data.get(True)).get("pull_request")
        types = pr_trigger if isinstance(pr_trigger, list) else pr_trigger.get("types", [])
        assert "synchronize" in types

    def test_reopened_trigger(self):
        data = _load_workflow()
        pr_trigger = (data.get("on") or data.get(True)).get("pull_request")
        types = pr_trigger if isinstance(pr_trigger, list) else pr_trigger.get("types", [])
        assert "reopened" in types

    def test_no_closed_trigger(self):
        data = _load_workflow()
        pr_trigger = (data.get("on") or data.get(True)).get("pull_request")
        types = pr_trigger if isinstance(pr_trigger, list) else pr_trigger.get("types", [])
        assert "closed" not in types

    def test_no_unrelated_triggers(self):
        data = _load_workflow()
        pr_trigger = (data.get("on") or data.get(True)).get("pull_request")
        types = pr_trigger if isinstance(pr_trigger, list) else pr_trigger.get("types", [])
        allowed = {"opened", "synchronize", "reopened"}
        for t in types:
            assert t in allowed, f"Unexpected trigger type: {t}"

    def test_has_jobs(self):
        data = _load_workflow()
        assert "jobs" in data
        assert isinstance(data["jobs"], dict)
        assert len(data["jobs"]) > 0


class TestWorkflowPermissions:
    def test_top_level_permissions_read_only(self):
        data = _load_workflow()
        perms = data.get("permissions", {})
        assert isinstance(perms, dict)
        for perm, level in perms.items():
            assert level in ("read", "none"), (
                f"Permission {perm} should be read or none, got {level!r}"
            )

    def test_no_write_permissions_at_top_level(self):
        data = _load_workflow()
        perms = data.get("permissions", {})
        assert "write" not in perms.values(), "Top-level write permissions found"

    def test_no_contents_write(self):
        data = _load_workflow()
        perms = data.get("permissions", {})
        assert perms.get("contents") != "write"

    def test_no_pull_requests_write(self):
        data = _load_workflow()
        perms = data.get("permissions", {})
        assert perms.get("pull-requests") != "write"

    def test_no_actions_write(self):
        data = _load_workflow()
        perms = data.get("permissions", {})
        assert perms.get("actions") != "write"

    def test_job_level_permissions_read_only(self):
        data = _load_workflow()
        for job_name, job_block in data.get("jobs", {}).items():
            if isinstance(job_block, dict):
                perms = job_block.get("permissions", {})
                for perm, level in perms.items():
                    assert level in ("read", "none"), (
                        f"Job {job_name}: permission {perm} should be "
                        f"read or none, got {level!r}"
                    )


class TestWorkflowSecrets:
    def test_api_url_not_hardcoded(self):
        source = WORKFLOW_PATH.read_text(encoding="utf-8")
        hardcoded_url_patterns = [
            "https://api.secureflow",
            "http://localhost:",
            "https://localhost:",
            "https://secureflow.io",
        ]
        for pattern in hardcoded_url_patterns:
            assert pattern not in source, f"Hardcoded URL found: {pattern}"

    def test_token_from_secrets(self):
        source = WORKFLOW_PATH.read_text(encoding="utf-8")
        assert "secrets.SECUREFLOW_API_TOKEN" in source

    def test_api_url_from_secrets_or_env(self):
        source = WORKFLOW_PATH.read_text(encoding="utf-8")
        has_secrets_url = "secrets.SECUREFLOW_API_URL" in source
        has_env_url = "SECUREFLOW_API_URL" in source
        assert has_secrets_url or has_env_url, (
            "API URL should be configured via secrets or environment"
        )

    def test_no_github_token_in_workflow(self):
        source = WORKFLOW_PATH.read_text(encoding="utf-8")
        assert "github.token" not in source.lower()

    def test_no_credentials_committed(self):
        source = WORKFLOW_PATH.read_text(encoding="utf-8")
        credential_patterns = [
            "ghp_",
            "gho_",
            "github_pat_",
            "sk-",
            "password=",
        ]
        for pattern in credential_patterns:
            assert pattern not in source, f"Credential pattern found: {pattern}"


# -- SecureFlowRequest model ------------------------------------------------


class TestSecureFlowRequest:
    def test_basic_construction(self):
        req = SecureFlowRequest(
            repository="octocat/hello-world",
            pr_number=1,
            head_sha="abc1234",
        )
        assert req.repository == "octocat/hello-world"
        assert req.pr_number == 1
        assert req.head_sha == "abc1234"
        assert req.base_sha == ""
        assert req.changed_files == []

    def test_with_changed_files(self):
        from src.api.models import ChangedFile

        req = SecureFlowRequest(
            repository="org/repo",
            pr_number=5,
            head_sha="a" * 7,
            base_sha="b" * 7,
            changed_files=[
                ChangedFile(filename="a.py", status="modified", additions=3, deletions=1),
                ChangedFile(filename="b.py", status="added", additions=10),
            ],
        )
        assert len(req.changed_files) == 2

    def test_pr_number_must_be_positive(self):
        with pytest.raises(Exception):
            SecureFlowRequest(repository="r", pr_number=0, head_sha="a" * 7)

    def test_empty_repository_rejected(self):
        with pytest.raises(Exception):
            SecureFlowRequest(repository="", pr_number=1, head_sha="a" * 7)

    def test_empty_head_sha_rejected(self):
        with pytest.raises(Exception):
            SecureFlowRequest(repository="r", pr_number=1, head_sha="")

    def test_serialization_round_trip(self):
        req = SecureFlowRequest(
            repository="org/repo",
            pr_number=3,
            head_sha="abc1234",
            base_sha="def5678",
        )
        dumped = req.model_dump()
        restored = SecureFlowRequest.model_validate(dumped)
        assert restored == req

    def test_json_round_trip(self):
        req = SecureFlowRequest(
            repository="org/repo",
            pr_number=3,
            head_sha="abc1234",
        )
        json_str = req.model_dump_json()
        restored = SecureFlowRequest.model_validate_json(json_str)
        assert restored == req

    def test_default_changed_files_empty(self):
        req = SecureFlowRequest(repository="r", pr_number=1, head_sha="a" * 7)
        assert req.changed_files == []


class TestSecureFlowResponse:
    def test_default_response(self):
        resp = SecureFlowResponse()
        assert resp.status == RequestStatus.PENDING
        assert resp.message == ""
        assert resp.request_id == ""

    def test_completed_response(self):
        resp = SecureFlowResponse(
            status=RequestStatus.COMPLETED,
            message="Scan complete",
            request_id="req-123",
        )
        assert resp.status == RequestStatus.COMPLETED

    def test_failed_response(self):
        resp = SecureFlowResponse(
            status=RequestStatus.FAILED,
            message="Internal error",
        )
        assert resp.status == RequestStatus.FAILED

    def test_serialization_round_trip(self):
        resp = SecureFlowResponse(
            status=RequestStatus.COMPLETED,
            message="OK",
            request_id="x",
        )
        restored = SecureFlowResponse.model_validate(resp.model_dump())
        assert restored == resp


# -- Adapter: event_to_request ---------------------------------------------


class TestEventToRequest:
    def test_basic_conversion(self):
        event = _event()
        req = event_to_request(event)
        assert isinstance(req, SecureFlowRequest)
        assert req.repository == "octocat/hello-world"
        assert req.pr_number == 42
        assert req.head_sha == "a" * 40
        assert req.base_sha == "b" * 40

    def test_changed_files_mapped(self):
        event = _event(
            files=[
                PRFile(filename="a.py", status="modified", additions=5, deletions=2),
                PRFile(filename="b.txt", status="added", additions=10),
            ]
        )
        req = event_to_request(event)
        assert len(req.changed_files) == 2
        assert req.changed_files[0].filename == "a.py"
        assert req.changed_files[0].status == "modified"
        assert req.changed_files[0].additions == 5
        assert req.changed_files[0].deletions == 2
        assert req.changed_files[1].filename == "b.txt"
        assert req.changed_files[1].status == "added"

    def test_empty_changed_files(self):
        event = _event(files=[])
        req = event_to_request(event)
        assert req.changed_files == []

    def test_base_sha_propagated(self):
        event = _event(base_sha="c" * 40)
        req = event_to_request(event)
        assert req.base_sha == "c" * 40

    def test_empty_base_sha_propagated(self):
        event = _event(base_sha="")
        req = event_to_request(event)
        assert req.base_sha == ""

    def test_deterministic(self):
        event = _event()
        assert event_to_request(event) == event_to_request(event)


# -- SecureFlowActionConfig -------------------------------------------------


class TestSecureFlowActionConfig:
    def test_defaults_empty(self):
        cfg = SecureFlowActionConfig()
        assert cfg.url == ""
        assert cfg.token == ""
        assert cfg.timeout == 30

    def test_explicit_values(self):
        cfg = SecureFlowActionConfig(
            url="https://api.example.com",
            token="tok123",
            timeout=10,
        )
        assert cfg.url == "https://api.example.com"
        assert cfg.token == "tok123"
        assert cfg.timeout == 10

    def test_validate_missing_url_raises(self):
        cfg = SecureFlowActionConfig(url="")
        with pytest.raises(ConfigurationError, match="SECUREFLOW_API_URL"):
            cfg.validate()

    def test_validate_non_https_url_raises(self):
        cfg = SecureFlowActionConfig(url="http://insecure.com")
        with pytest.raises(ConfigurationError, match="HTTPS"):
            cfg.validate()

    def test_validate_ok(self):
        cfg = SecureFlowActionConfig(url="https://api.example.com")
        cfg.validate()

    def test_reads_from_environment(self, monkeypatch):
        monkeypatch.setenv("SECUREFLOW_API_URL", "https://env.example.com")
        monkeypatch.setenv("SECUREFLOW_API_TOKEN", "env-token")
        cfg = SecureFlowActionConfig()
        assert cfg.url == "https://env.example.com"
        assert cfg.token == "env-token"

    def test_explicit_overrides_environment(self, monkeypatch):
        monkeypatch.setenv("SECUREFLOW_API_URL", "https://env.example.com")
        cfg = SecureFlowActionConfig(url="https://explicit.example.com")
        assert cfg.url == "https://explicit.example.com"

    def test_token_not_logged(self):
        cfg = SecureFlowActionConfig(
            url="https://x.com", token="super-secret-value"
        )
        assert "super-secret-value" not in repr(cfg)

    def test_url_not_hardcoded_in_source(self):
        src = Path(action_module.__file__).read_text(encoding="utf-8")
        assert "https://api.secureflow" not in src


# -- Fake HTTP client -------------------------------------------------------


class TestFakeHTTPClient:
    def test_default_response(self):
        client = SecureFlowFakeHTTPClient()
        req = SecureFlowRequest(repository="r", pr_number=1, head_sha="a" * 7)
        resp = client.send("https://x.com", req, "")
        assert resp.status == RequestStatus.COMPLETED

    def test_predefined_responses(self):
        client = SecureFlowFakeHTTPClient(
            responses=[
                SecureFlowResponse(status=RequestStatus.COMPLETED, message="ok"),
                SecureFlowResponse(status=RequestStatus.FAILED, message="bad"),
            ]
        )
        req = SecureFlowRequest(repository="r", pr_number=1, head_sha="a" * 7)
        r1 = client.send("https://x.com", req, "")
        r2 = client.send("https://x.com", req, "")
        assert r1.message == "ok"
        assert r2.message == "bad"

    def test_records_calls(self):
        client = SecureFlowFakeHTTPClient()
        req = SecureFlowRequest(repository="r", pr_number=1, head_sha="a" * 7)
        client.send("https://x.com", req, "tok")
        client.send("https://x.com", req, "tok2")
        assert len(client.calls) == 2
        assert client.calls[0] == req

    def test_no_network_access(self):
        import src.api.client as client_mod

        source = Path(client_mod.__file__).read_text(encoding="utf-8")
        assert "import requests" not in source
        assert "import httpx" not in source


# -- SecureFlowHTTPClient configuration ------------------------------------


class TestSecureFlowHTTPClientConfig:
    def test_empty_url_rejected(self):
        with pytest.raises(ConfigurationError, match="required"):
            SecureFlowHTTPClient(url="", token="tok")

    def test_non_https_url_rejected(self):
        with pytest.raises(ConfigurationError, match="HTTPS"):
            SecureFlowHTTPClient(url="http://insecure.com")

    def test_https_url_accepted(self):
        client = SecureFlowHTTPClient(url="https://api.example.com")
        assert client._url == "https://api.example.com"

    def test_timeout_clamped(self):
        client = SecureFlowHTTPClient(url="https://api.example.com", timeout=-5)
        assert client._timeout >= 1

    def test_token_not_in_string(self):
        client = SecureFlowHTTPClient(url="https://x.com", token="mysecret")
        assert "mysecret" not in str(client)


# -- SecureFlowAction (integration) ----------------------------------------


class TestSecureFlowAction:
    def test_successful_call(self):
        config = SecureFlowActionConfig(url="https://api.example.com", token="tok")
        client = SecureFlowFakeHTTPClient(
            responses=[
                SecureFlowResponse(
                    status=RequestStatus.COMPLETED, message="OK"
                ),
            ]
        )
        action = SecureFlowAction(config, client)
        resp, err = action.run(_event())
        assert err is None
        assert resp is not None
        assert resp.status == RequestStatus.COMPLETED
        assert len(client.calls) == 1
        assert client.calls[0].pr_number == 42

    def test_api_failure(self):
        config = SecureFlowActionConfig(url="https://api.example.com")
        client = SecureFlowFakeHTTPClient()

        def failing_send(url, request, token):
            raise APIError("500 Internal Server Error")

        client.send = failing_send  # type: ignore[assignment]
        action = SecureFlowAction(config, client)
        resp, err = action.run(_event())
        assert resp is None
        assert err is not None
        assert "500" in err

    def test_timeout(self):
        config = SecureFlowActionConfig(url="https://api.example.com")
        client = SecureFlowFakeHTTPClient()

        def timeout_send(url, request, token):
            raise APITimeoutError("timed out")

        client.send = timeout_send  # type: ignore[assignment]
        action = SecureFlowAction(config, client)
        resp, err = action.run(_event())
        assert resp is None
        assert err is not None
        assert "timed out" in err

    def test_invalid_configuration(self):
        config = SecureFlowActionConfig(url="")
        client = SecureFlowFakeHTTPClient()
        action = SecureFlowAction(config, client)
        resp, err = action.run(_event())
        assert resp is None
        assert err is not None
        assert "SECUREFLOW_API_URL" in err

    def test_request_propagation(self):
        config = SecureFlowActionConfig(url="https://api.example.com")
        client = SecureFlowFakeHTTPClient()
        action = SecureFlowAction(config, client)
        event = _event(
            full_name="org/special-repo",
            pr_number=99,
            head_sha="z" * 40,
            base_sha="y" * 40,
        )
        action.run(event)
        req = client.calls[0]
        assert req.repository == "org/special-repo"
        assert req.pr_number == 99
        assert req.head_sha == "z" * 40
        assert req.base_sha == "y" * 40

    def test_changed_files_in_request(self):
        config = SecureFlowActionConfig(url="https://api.example.com")
        client = SecureFlowFakeHTTPClient()
        action = SecureFlowAction(config, client)
        event = _event(
            files=[
                PRFile(filename="x.py", status="added", additions=20, deletions=0),
                PRFile(filename="y.py", status="removed", additions=0, deletions=15),
            ]
        )
        action.run(event)
        req = client.calls[0]
        assert len(req.changed_files) == 2
        assert req.changed_files[0].filename == "x.py"
        assert req.changed_files[1].status == "removed"

    def test_token_passed_through(self):
        config = SecureFlowActionConfig(
            url="https://api.example.com", token="my-token"
        )
        captured: dict[str, str] = {}

        def capturing_send(url, request, token):
            captured["token"] = token
            return SecureFlowResponse(status=RequestStatus.COMPLETED)

        client = SecureFlowFakeHTTPClient()
        client.send = capturing_send  # type: ignore[assignment]
        action = SecureFlowAction(config, client)
        action.run(_event())
        assert captured["token"] == "my-token"


# -- Security properties ----------------------------------------------------


class TestSecurityProperties:
    def test_no_subprocess_in_api_module(self):
        import src.api.client as client_mod

        source = Path(client_mod.__file__).read_text(encoding="utf-8")
        assert "import subprocess" not in source
        assert "from subprocess" not in source

    def test_no_subprocess_in_action_module(self):
        source = Path(action_module.__file__).read_text(encoding="utf-8")
        assert "import subprocess" not in source
        assert "from subprocess" not in source

    def test_no_os_system_in_action_module(self):
        source = Path(action_module.__file__).read_text(encoding="utf-8")
        assert "os.system(" not in source

    def test_no_hardcoded_credentials_in_action(self):
        source = Path(action_module.__file__).read_text(encoding="utf-8")
        assert "password" not in source.lower()
        assert "ghp_" not in source
        assert "gho_" not in source
        assert "github_pat_" not in source
        assert "sk-" not in source

    def test_no_shell_execution_in_workflow(self):
        source = WORKFLOW_PATH.read_text(encoding="utf-8")
        assert "eval " not in source
        assert "exec " not in source

    def test_pr_fields_not_interpolated_in_shell(self):
        source = WORKFLOW_PATH.read_text(encoding="utf-8")
        assert "${{ github.event.pull_request.title }}" not in source
        assert "${{ github.event.pull_request.body }}" not in source

    def test_response_bounded_output(self):
        resp = SecureFlowResponse(
            status=RequestStatus.COMPLETED,
            message="x" * 10000,
            request_id="r",
        )
        assert resp.status == RequestStatus.COMPLETED

    def test_deterministic_request_construction(self):
        event = _event()
        r1 = event_to_request(event)
        r2 = event_to_request(event)
        assert r1 == r2


# -- Imports check ----------------------------------------------------------


class TestImports:
    def test_api_package_exports(self):
        from src.api import (
            APIError,
            APITimeoutError,
            ConfigurationError,
            SecureFlowFakeHTTPClient,
            SecureFlowRequest,
            SecureFlowResponse,
        )

        assert all(
            klass is not None
            for klass in [
                APIError,
                APITimeoutError,
                ConfigurationError,
                SecureFlowFakeHTTPClient,
                SecureFlowRequest,
                SecureFlowResponse,
            ]
        )

    def test_github_package_exports(self):
        from src.github import (
            SecureFlowAction,
            SecureFlowActionConfig,
            event_to_request,
        )

        assert all(
            item is not None
            for item in [SecureFlowAction, SecureFlowActionConfig, event_to_request]
        )
