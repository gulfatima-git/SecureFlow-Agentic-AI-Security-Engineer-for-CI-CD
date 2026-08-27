"""Tests for CI/CD configuration analysis.

All analysis is deterministic and offline. No GitHub, Docker, or external APIs.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from src.models.security_finding import Confidence, ScanResult, SecurityFinding, Severity
from src.tools.cicd_analyzer import (
    CICDAnalyzer,
    _analyze_compose,
    _analyze_dockerfile,
    _analyze_gha_workflow,
    _check_compose_capabilities,
    _check_compose_host_mounts,
    _check_compose_host_network,
    _check_compose_privileged,
    _check_compose_secrets,
    _check_compose_sensitive_ports,
    _check_dockerfile_dangerous_add,
    _check_dockerfile_remote_script,
    _check_dockerfile_root_user,
    _check_dockerfile_secrets,
    _check_gha_permissions,
    _check_gha_secret_exposure,
    _check_gha_triggers,
    _check_gha_unpinned_actions,
    _check_gha_untrusted_input,
    _safe_load_yaml,
)

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures"
INSECURE_REPO = FIXTURES / "cicd_insecure"
SECURE_REPO = FIXTURES / "cicd_secure"


# ---------------------------------------------------------------------------
# YAML helpers
# ---------------------------------------------------------------------------


class TestSafeLoadYaml:
    def test_valid_yaml(self) -> None:
        result = _safe_load_yaml("key: value")
        assert result == {"key": "value"}

    def test_malformed_yaml(self) -> None:
        result = _safe_load_yaml("{{invalid yaml: [")
        assert result is None

    def test_non_dict_yaml(self) -> None:
        result = _safe_load_yaml("- item1\n- item2")
        assert result is None

    def test_empty_string(self) -> None:
        result = _safe_load_yaml("")
        assert result is None


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


class TestFileDiscovery:
    def test_analyze_invalid_path(self) -> None:
        analyzer = CICDAnalyzer()
        result = analyzer.analyze("/nonexistent/path")
        assert result.status == "error"
        assert "does not exist" in result.error_message

    def test_analyze_empty_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CICDAnalyzer()
            result = analyzer.analyze(tmpdir)
            assert result.status == "success"
            assert result.findings_count == 0
            assert "No supported CI/CD" in result.error_message

    def test_analyze_insecure_repo(self) -> None:
        analyzer = CICDAnalyzer()
        result = analyzer.analyze(INSECURE_REPO)
        assert result.status == "success"
        assert result.findings_count > 0

    def test_analyze_secure_repo(self) -> None:
        analyzer = CICDAnalyzer()
        result = analyzer.analyze(SECURE_REPO)
        assert result.status == "success"

    def test_scan_duration_recorded(self) -> None:
        analyzer = CICDAnalyzer()
        result = analyzer.analyze(INSECURE_REPO)
        assert result.scan_duration_seconds >= 0

    def test_tool_version_recorded(self) -> None:
        analyzer = CICDAnalyzer()
        result = analyzer.analyze(INSECURE_REPO)
        assert result.tool_version == "0.1.0"

    def test_tool_name(self) -> None:
        analyzer = CICDAnalyzer()
        result = analyzer.analyze(INSECURE_REPO)
        assert result.tool == "cicd-analyzer"


# ---------------------------------------------------------------------------
# GitHub Actions — excessive permissions
# ---------------------------------------------------------------------------


class TestGHAPermissions:
    def test_excessive_permissions_detected(self) -> None:
        result = _check_gha_permissions(
            {"permissions": {"contents": "write", "packages": "write"}},
            "test.yml",
        )
        assert len(result) == 1
        assert result[0].rule_id == "CICD.GHA.EXCESSIVE_PERMISSIONS"

    def test_read_only_permissions_clean(self) -> None:
        result = _check_gha_permissions(
            {"permissions": {"contents": "read"}},
            "test.yml",
        )
        assert len(result) == 0

    def test_no_permissions_block(self) -> None:
        result = _check_gha_permissions({}, "test.yml")
        assert len(result) == 0

    def test_none_permissions(self) -> None:
        result = _check_gha_permissions({"permissions": None}, "test.yml")
        assert len(result) == 0

    def test_multiple_write_permissions(self) -> None:
        result = _check_gha_permissions(
            {
                "permissions": {
                    "contents": "write",
                    "issues": "write",
                    "pull-requests": "write",
                }
            },
            "test.yml",
        )
        assert len(result) == 1
        assert "issues" in result[0].metadata["permissions"]

    def test_fixture_detected(self) -> None:
        content = (INSECURE_REPO / ".github/workflows/excessive_permissions.yml").read_text()
        import yaml

        workflow = yaml.safe_load(content)
        result = _check_gha_permissions(workflow, "excessive_permissions.yml")
        assert len(result) >= 1


# ---------------------------------------------------------------------------
# GitHub Actions — dangerous triggers
# ---------------------------------------------------------------------------


class TestGHATriggers:
    def test_pull_request_target(self) -> None:
        result = _check_gha_triggers(
            {"on": {"pull_request_target": {"branches": ["main"]}}},
            "test.yml",
        )
        assert len(result) == 1
        assert result[0].rule_id == "CICD.GHA.PULL_REQUEST_TARGET"
        assert result[0].severity == Severity.ERROR

    def test_workflow_dispatch_not_flagged(self) -> None:
        result = _check_gha_triggers(
            {"on": {"workflow_dispatch": {}}},
            "test.yml",
        )
        assert len(result) == 0

    def test_safe_triggers(self) -> None:
        result = _check_gha_triggers(
            {"on": {"push": {}, "pull_request": {}}},
            "test.yml",
        )
        assert len(result) == 0

    def test_string_trigger(self) -> None:
        result = _check_gha_triggers({"on": "push"}, "test.yml")
        assert len(result) == 0

    def test_list_triggers(self) -> None:
        result = _check_gha_triggers({"on": ["push", "pull_request"]}, "test.yml")
        assert len(result) == 0

    def test_none_on(self) -> None:
        result = _check_gha_triggers({"on": None}, "test.yml")
        assert len(result) == 0

    def test_boolean_key_on(self) -> None:
        result = _check_gha_triggers({True: {"push": {}}}, "test.yml")
        assert len(result) == 0


# ---------------------------------------------------------------------------
# GitHub Actions — untrusted input
# ---------------------------------------------------------------------------


class TestGHAUntrustedInput:
    def test_github_event_head_commit(self) -> None:
        result = _check_gha_untrusted_input(
            {
                "jobs": {
                    "build": {
                        "steps": [
                            {"run": 'echo "${{ github.event.head_commit.message }}"'}
                        ]
                    }
                }
            },
            "test.yml",
        )
        assert len(result) == 1
        assert result[0].rule_id == "CICD.GHA.UNTRUSTED_INPUT"

    def test_github_pull_request_body(self) -> None:
        result = _check_gha_untrusted_input(
            {
                "jobs": {
                    "build": {
                        "steps": [
                            {"run": "echo ${{ github.event.pull_request.body }}"}
                        ]
                    }
                }
            },
            "test.yml",
        )
        assert len(result) == 1

    def test_inputs_expression(self) -> None:
        result = _check_gha_untrusted_input(
            {
                "jobs": {
                    "build": {
                        "steps": [
                            {"run": "echo ${{ inputs.my_input }}"}
                        ]
                    }
                }
            },
            "test.yml",
        )
        assert len(result) == 1

    def test_head_ref(self) -> None:
        result = _check_gha_untrusted_input(
            {
                "jobs": {
                    "build": {
                        "steps": [
                            {"run": "echo ${{ github.head_ref }}"}
                        ]
                    }
                }
            },
            "test.yml",
        )
        assert len(result) == 1

    def test_safe_run_command(self) -> None:
        result = _check_gha_untrusted_input(
            {
                "jobs": {
                    "build": {
                        "steps": [
                            {"run": "make build"}
                        ]
                    }
                }
            },
            "test.yml",
        )
        assert len(result) == 0

    def test_no_run_step(self) -> None:
        result = _check_gha_untrusted_input(
            {
                "jobs": {
                    "build": {
                        "steps": [
                            {"uses": "actions/checkout@v4"}
                        ]
                    }
                }
            },
            "test.yml",
        )
        assert len(result) == 0

    def test_no_steps(self) -> None:
        result = _check_gha_untrusted_input(
            {"jobs": {"build": {}}},
            "test.yml",
        )
        assert len(result) == 0

    def test_non_dict_jobs(self) -> None:
        result = _check_gha_untrusted_input({"jobs": "not-a-dict"}, "test.yml")
        assert len(result) == 0

    def test_fixture_detected(self) -> None:
        content = (INSECURE_REPO / ".github/workflows/untrusted_input.yml").read_text()
        import yaml

        workflow = yaml.safe_load(content)
        result = _check_gha_untrusted_input(workflow, "untrusted_input.yml")
        assert len(result) >= 1


# ---------------------------------------------------------------------------
# GitHub Actions — secret exposure
# ---------------------------------------------------------------------------


class TestGHASecretExposure:
    def test_secret_in_run(self) -> None:
        result = _check_gha_secret_exposure(
            {
                "jobs": {
                    "build": {
                        "steps": [
                            {"run": "deploy.sh ${{ secrets.API_KEY }}"}
                        ]
                    }
                }
            },
            "test.yml",
        )
        assert len(result) == 1
        assert result[0].rule_id == "CICD.GHA.SECRET_EXPOSURE"

    def test_no_secret_in_run(self) -> None:
        result = _check_gha_secret_exposure(
            {
                "jobs": {
                    "build": {
                        "steps": [
                            {"run": "make build"}
                        ]
                    }
                }
            },
            "test.yml",
        )
        assert len(result) == 0

    def test_secret_in_env_step(self) -> None:
        result = _check_gha_secret_exposure(
            {
                "jobs": {
                    "build": {
                        "steps": [
                            {"run": "echo done"}
                        ]
                    }
                }
            },
            "test.yml",
        )
        assert len(result) == 0

    def test_fixture_detected(self) -> None:
        content = (INSECURE_REPO / ".github/workflows/secret_exposure.yml").read_text()
        import yaml

        workflow = yaml.safe_load(content)
        result = _check_gha_secret_exposure(workflow, "secret_exposure.yml")
        assert len(result) >= 1


# ---------------------------------------------------------------------------
# GitHub Actions — unpinned actions
# ---------------------------------------------------------------------------


class TestGHAUnpinnedActions:
    def test_unpinned_third_party(self) -> None:
        result = _check_gha_unpinned_actions(
            {
                "jobs": {
                    "build": {
                        "steps": [
                            {"uses": "some-org/some-action@v1"}
                        ]
                    }
                }
            },
            "test.yml",
        )
        assert len(result) == 1
        assert result[0].rule_id == "CICD.GHA.UNPINNED_ACTION"

    def test_pinned_to_sha(self) -> None:
        result = _check_gha_unpinned_actions(
            {
                "jobs": {
                    "build": {
                        "steps": [
                            {
                                "uses": (
                                    "some-org/some-action@"
                                    "abc123def456789012345678901234567890abcd"
                                )
                            }
                        ]
                    }
                }
            },
            "test.yml",
        )
        assert len(result) == 0

    def test_official_action_not_flagged(self) -> None:
        result = _check_gha_unpinned_actions(
            {
                "jobs": {
                    "build": {
                        "steps": [
                            {"uses": "actions/checkout@v4"}
                        ]
                    }
                }
            },
            "test.yml",
        )
        assert len(result) == 0

    def test_uses_step(self) -> None:
        result = _check_gha_unpinned_actions(
            {
                "jobs": {
                    "build": {
                        "steps": [
                            {"name": "build", "run": "make build"}
                        ]
                    }
                }
            },
            "test.yml",
        )
        assert len(result) == 0

    def test_fixture_detected(self) -> None:
        content = (INSECURE_REPO / ".github/workflows/unpinned_action.yml").read_text()
        import yaml

        workflow = yaml.safe_load(content)
        result = _check_gha_unpinned_actions(workflow, "unpinned_action.yml")
        assert len(result) >= 1


# ---------------------------------------------------------------------------
# GitHub Actions — full workflow analysis
# ---------------------------------------------------------------------------


class TestGHAFullWorkflow:
    def test_analyze_excessive_permissions(self) -> None:
        content = (INSECURE_REPO / ".github/workflows/excessive_permissions.yml").read_text()
        findings = _analyze_gha_workflow(
            INSECURE_REPO / ".github/workflows/excessive_permissions.yml",
            content,
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CICD.GHA.EXCESSIVE_PERMISSIONS" in rule_ids

    def test_analyze_pr_target(self) -> None:
        content = (INSECURE_REPO / ".github/workflows/pr_target.yml").read_text()
        findings = _analyze_gha_workflow(
            INSECURE_REPO / ".github/workflows/pr_target.yml",
            content,
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CICD.GHA.PULL_REQUEST_TARGET" in rule_ids

    def test_analyze_untrusted_input(self) -> None:
        content = (INSECURE_REPO / ".github/workflows/untrusted_input.yml").read_text()
        findings = _analyze_gha_workflow(
            INSECURE_REPO / ".github/workflows/untrusted_input.yml",
            content,
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CICD.GHA.UNTRUSTED_INPUT" in rule_ids

    def test_analyze_unpinned_action(self) -> None:
        content = (INSECURE_REPO / ".github/workflows/unpinned_action.yml").read_text()
        findings = _analyze_gha_workflow(
            INSECURE_REPO / ".github/workflows/unpinned_action.yml",
            content,
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CICD.GHA.UNPINNED_ACTION" in rule_ids

    def test_analyze_secret_exposure(self) -> None:
        content = (INSECURE_REPO / ".github/workflows/secret_exposure.yml").read_text()
        findings = _analyze_gha_workflow(
            INSECURE_REPO / ".github/workflows/secret_exposure.yml",
            content,
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CICD.GHA.SECRET_EXPOSURE" in rule_ids

    def test_analyze_secure_workflow(self) -> None:
        content = (SECURE_REPO / ".github/workflows/secure.yml").read_text()
        findings = _analyze_gha_workflow(
            SECURE_REPO / ".github/workflows/secure.yml",
            content,
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CICD.GHA.EXCESSIVE_PERMISSIONS" not in rule_ids
        assert "CICD.GHA.PULL_REQUEST_TARGET" not in rule_ids
        assert "CICD.GHA.UNTRUSTED_INPUT" not in rule_ids
        assert "CICD.GHA.SECRET_EXPOSURE" not in rule_ids
        assert "CICD.GHA.UNPINNED_ACTION" not in rule_ids

    def test_malformed_yaml(self) -> None:
        findings = _analyze_gha_workflow(
            Path("test.yml"),
            "{{invalid yaml: [",
        )
        assert len(findings) == 0

    def test_all_findings_have_correct_fields(self) -> None:
        content = (INSECURE_REPO / ".github/workflows/excessive_permissions.yml").read_text()
        findings = _analyze_gha_workflow(
            INSECURE_REPO / ".github/workflows/excessive_permissions.yml",
            content,
        )
        for finding in findings:
            assert finding.tool == "cicd-analyzer"
            assert finding.rule_id.startswith("CICD.GHA.")
            assert finding.category == "cicd-security"
            valid_sev = (Severity.ERROR, Severity.WARNING, Severity.INFO, Severity.UNKNOWN)
            assert finding.severity in valid_sev
            valid_conf = (Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW, Confidence.UNKNOWN)
            assert finding.confidence in valid_conf


# ---------------------------------------------------------------------------
# Dockerfile — root user
# ---------------------------------------------------------------------------


class TestDockerfileRootUser:
    def test_no_user_instruction(self) -> None:
        lines = [
            "FROM python:3.11",
            "COPY . /app",
            "CMD [\"python\", \"app.py\"]",
        ]
        result = _check_dockerfile_root_user(lines, "Dockerfile")
        assert len(result) == 1
        assert result[0].rule_id == "CICD.DOCKER.ROOT_USER"

    def test_has_user_instruction(self) -> None:
        lines = [
            "FROM python:3.11",
            "COPY . /app",
            "USER appuser",
            "CMD [\"python\", \"app.py\"]",
        ]
        result = _check_dockerfile_root_user(lines, "Dockerfile")
        assert len(result) == 0

    def test_no_cmd_no_issue(self) -> None:
        lines = [
            "FROM python:3.11",
            "COPY . /app",
        ]
        result = _check_dockerfile_root_user(lines, "Dockerfile")
        assert len(result) == 0

    def test_entrypoint_also_checked(self) -> None:
        lines = [
            "FROM python:3.11",
            "COPY . /app",
            "ENTRYPOINT [\"python\"]",
        ]
        result = _check_dockerfile_root_user(lines, "Dockerfile")
        assert len(result) == 1

    def test_fixture_detected(self) -> None:
        content = (INSECURE_REPO / "Dockerfile.insecure").read_text()
        lines = content.splitlines()
        result = _check_dockerfile_root_user(lines, "Dockerfile.insecure")
        assert len(result) == 1

    def test_secure_fixture_no_issue(self) -> None:
        content = (SECURE_REPO / "Dockerfile.secure").read_text()
        lines = content.splitlines()
        result = _check_dockerfile_root_user(lines, "Dockerfile.secure")
        assert len(result) == 0


# ---------------------------------------------------------------------------
# Dockerfile — remote script execution
# ---------------------------------------------------------------------------


class TestDockerfileRemoteScript:
    def test_curl_pipe_sh(self) -> None:
        lines = ["RUN curl https://example.com/install.sh | sh"]
        result = _check_dockerfile_remote_script(lines, "Dockerfile")
        assert len(result) == 1
        assert result[0].rule_id == "CICD.DOCKER.REMOTE_SCRIPT"
        assert result[0].severity == Severity.ERROR

    def test_wget_pipe_bash(self) -> None:
        lines = ["RUN wget -qO- https://example.com/setup | bash"]
        result = _check_dockerfile_remote_script(lines, "Dockerfile")
        assert len(result) == 1

    def test_safe_curl(self) -> None:
        lines = ["RUN curl -o /tmp/file.tar.gz https://example.com/file.tar.gz"]
        result = _check_dockerfile_remote_script(lines, "Dockerfile")
        assert len(result) == 0

    def test_comment_not_flagged(self) -> None:
        lines = ["# RUN curl https://example.com/install.sh | sh"]
        result = _check_dockerfile_remote_script(lines, "Dockerfile")
        assert len(result) == 0

    def test_fixture_detected(self) -> None:
        content = (INSECURE_REPO / "Dockerfile.insecure").read_text()
        lines = content.splitlines()
        result = _check_dockerfile_remote_script(lines, "Dockerfile.insecure")
        assert len(result) == 1

    def test_line_numbers_correct(self) -> None:
        lines = [
            "FROM python:3.11",
            "RUN curl https://example.com/install.sh | sh",
        ]
        result = _check_dockerfile_remote_script(lines, "Dockerfile")
        assert result[0].start_line == 2


# ---------------------------------------------------------------------------
# Dockerfile — secrets in ENV/ARG
# ---------------------------------------------------------------------------


class TestDockerfileSecrets:
    def test_secret_in_env(self) -> None:
        lines = ["ENV DB_PASSWORD=supersecret123"]
        result = _check_dockerfile_secrets(lines, "Dockerfile")
        assert len(result) == 1
        assert result[0].rule_id == "CICD.DOCKER.SECRET_ENV"

    def test_secret_in_arg(self) -> None:
        lines = ["ARG API_KEY=sk-12345"]
        result = _check_dockerfile_secrets(lines, "Dockerfile")
        assert len(result) == 1
        assert result[0].rule_id == "CICD.DOCKER.SECRET_ARG"

    def test_safe_env(self) -> None:
        lines = ["ENV APP_ENV=production"]
        result = _check_dockerfile_secrets(lines, "Dockerfile")
        assert len(result) == 0

    def test_multiple_secrets(self) -> None:
        lines = [
            "ENV DB_PASSWORD=secret1",
            "ARG API_KEY=secret2",
        ]
        result = _check_dockerfile_secrets(lines, "Dockerfile")
        assert len(result) == 2

    def test_fixture_secrets_detected(self) -> None:
        content = (INSECURE_REPO / "Dockerfile.secrets").read_text()
        lines = content.splitlines()
        result = _check_dockerfile_secrets(lines, "Dockerfile.secrets")
        assert len(result) >= 2

    def test_fixture_arg_secrets_detected(self) -> None:
        content = (INSECURE_REPO / "Dockerfile.arg_secrets").read_text()
        lines = content.splitlines()
        result = _check_dockerfile_secrets(lines, "Dockerfile.arg_secrets")
        assert len(result) >= 1

    def test_metadata_populated(self) -> None:
        lines = ["ENV DB_PASSWORD=secret"]
        result = _check_dockerfile_secrets(lines, "Dockerfile")
        assert result[0].metadata["instruction"] == "ENV"
        assert result[0].metadata["variable"] == "DB_PASSWORD"


# ---------------------------------------------------------------------------
# Dockerfile — dangerous ADD
# ---------------------------------------------------------------------------


class TestDockerfileDangerousAdd:
    def test_add_remote_url(self) -> None:
        lines = ["ADD https://example.com/file.tar.gz /opt/"]
        result = _check_dockerfile_dangerous_add(lines, "Dockerfile")
        assert len(result) == 1
        assert result[0].rule_id == "CICD.DOCKER.DANGEROUS_ADD"

    def test_add_local_file(self) -> None:
        lines = ["ADD requirements.txt /app/"]
        result = _check_dockerfile_dangerous_add(lines, "Dockerfile")
        assert len(result) == 0

    def test_add_http_url(self) -> None:
        lines = ["ADD http://example.com/file.tar.gz /opt/"]
        result = _check_dockerfile_dangerous_add(lines, "Dockerfile")
        assert len(result) == 1

    def test_comment_not_flagged(self) -> None:
        lines = ["# ADD https://example.com/file.tar.gz /opt/"]
        result = _check_dockerfile_dangerous_add(lines, "Dockerfile")
        assert len(result) == 0

    def test_fixture_detected(self) -> None:
        content = (INSECURE_REPO / "Dockerfile.dangerous_add").read_text()
        lines = content.splitlines()
        result = _check_dockerfile_dangerous_add(lines, "Dockerfile.dangerous_add")
        assert len(result) >= 1


# ---------------------------------------------------------------------------
# Dockerfile — full analysis
# ---------------------------------------------------------------------------


class TestDockerfileFull:
    def test_analyze_insecure_dockerfile(self) -> None:
        content = (INSECURE_REPO / "Dockerfile.insecure").read_text()
        findings = _analyze_dockerfile(INSECURE_REPO / "Dockerfile.insecure", content)
        rule_ids = [f.rule_id for f in findings]
        assert "CICD.DOCKER.ROOT_USER" in rule_ids
        assert "CICD.DOCKER.REMOTE_SCRIPT" in rule_ids

    def test_analyze_secrets_dockerfile(self) -> None:
        content = (INSECURE_REPO / "Dockerfile.secrets").read_text()
        findings = _analyze_dockerfile(INSECURE_REPO / "Dockerfile.secrets", content)
        rule_ids = [f.rule_id for f in findings]
        assert "CICD.DOCKER.SECRET_ENV" in rule_ids

    def test_analyze_arg_secrets_dockerfile(self) -> None:
        content = (INSECURE_REPO / "Dockerfile.arg_secrets").read_text()
        findings = _analyze_dockerfile(INSECURE_REPO / "Dockerfile.arg_secrets", content)
        rule_ids = [f.rule_id for f in findings]
        assert "CICD.DOCKER.SECRET_ARG" in rule_ids

    def test_analyze_dangerous_add_dockerfile(self) -> None:
        content = (INSECURE_REPO / "Dockerfile.dangerous_add").read_text()
        findings = _analyze_dockerfile(INSECURE_REPO / "Dockerfile.dangerous_add", content)
        rule_ids = [f.rule_id for f in findings]
        assert "CICD.DOCKER.DANGEROUS_ADD" in rule_ids

    def test_analyze_secure_dockerfile(self) -> None:
        content = (SECURE_REPO / "Dockerfile.secure").read_text()
        findings = _analyze_dockerfile(SECURE_REPO / "Dockerfile.secure", content)
        rule_ids = [f.rule_id for f in findings]
        assert "CICD.DOCKER.ROOT_USER" not in rule_ids
        assert "CICD.DOCKER.REMOTE_SCRIPT" not in rule_ids
        assert "CICD.DOCKER.SECRET_ENV" not in rule_ids
        assert "CICD.DOCKER.SECRET_ARG" not in rule_ids
        assert "CICD.DOCKER.DANGEROUS_ADD" not in rule_ids

    def test_all_findings_have_correct_fields(self) -> None:
        content = (INSECURE_REPO / "Dockerfile.insecure").read_text()
        findings = _analyze_dockerfile(INSECURE_REPO / "Dockerfile.insecure", content)
        for finding in findings:
            assert finding.tool == "cicd-analyzer"
            assert finding.rule_id.startswith("CICD.DOCKER.")
            assert finding.category == "cicd-security"


# ---------------------------------------------------------------------------
# Docker Compose — privileged
# ---------------------------------------------------------------------------


class TestComposePrivileged:
    def test_privileged_detected(self) -> None:
        services = {"web": {"image": "nginx", "privileged": True}}
        result = _check_compose_privileged(services, "docker-compose.yml")
        assert len(result) == 1
        assert result[0].rule_id == "CICD.COMPOSE.PRIVILEGED"
        assert result[0].severity == Severity.ERROR

    def test_not_privileged(self) -> None:
        services = {"web": {"image": "nginx"}}
        result = _check_compose_privileged(services, "docker-compose.yml")
        assert len(result) == 0

    def test_privileged_false(self) -> None:
        services = {"web": {"image": "nginx", "privileged": False}}
        result = _check_compose_privileged(services, "docker-compose.yml")
        assert len(result) == 0

    def test_fixture_detected(self) -> None:
        content = (INSECURE_REPO / "docker-compose.insecure.yml").read_text()
        import yaml

        doc = yaml.safe_load(content)
        result = _check_compose_privileged(doc["services"], "docker-compose.insecure.yml")
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Docker Compose — host mounts
# ---------------------------------------------------------------------------


class TestComposeHostMounts:
    def test_docker_sock_mount(self) -> None:
        services = {"web": {"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]}}
        result = _check_compose_host_mounts(services, "docker-compose.yml")
        assert len(result) == 1
        assert result[0].rule_id == "CICD.COMPOSE.HOST_MOUNT"

    def test_sensitive_path(self) -> None:
        services = {"web": {"volumes": ["/etc/shadow:/host/shadow:ro"]}}
        result = _check_compose_host_mounts(services, "docker-compose.yml")
        assert len(result) == 1

    def test_safe_volume(self) -> None:
        services = {"web": {"volumes": ["app_data:/data"]}}
        result = _check_compose_host_mounts(services, "docker-compose.yml")
        assert len(result) == 0

    def test_fixture_detected(self) -> None:
        content = (INSECURE_REPO / "docker-compose.insecure.yml").read_text()
        import yaml

        doc = yaml.safe_load(content)
        result = _check_compose_host_mounts(doc["services"], "docker-compose.insecure.yml")
        assert len(result) >= 1


# ---------------------------------------------------------------------------
# Docker Compose — secrets
# ---------------------------------------------------------------------------


class TestComposeSecrets:
    def test_plaintext_secret(self) -> None:
        services = {"web": {"environment": ["DB_PASSWORD=supersecret"]}}
        result = _check_compose_secrets(services, "docker-compose.yml")
        assert len(result) == 1
        assert result[0].rule_id == "CICD.COMPOSE.SECRET"

    def test_env_var_not_secret(self) -> None:
        services = {"web": {"environment": ["APP_ENV=production"]}}
        result = _check_compose_secrets(services, "docker-compose.yml")
        assert len(result) == 0

    def test_interpolated_not_flagged(self) -> None:
        services = {"web": {"environment": ["DB_PASSWORD=${DB_PASSWORD}"]}}
        result = _check_compose_secrets(services, "docker-compose.yml")
        assert len(result) == 0

    def test_fixture_detected(self) -> None:
        content = (INSECURE_REPO / "docker-compose.insecure.yml").read_text()
        import yaml

        doc = yaml.safe_load(content)
        result = _check_compose_secrets(doc["services"], "docker-compose.insecure.yml")
        assert len(result) >= 1


# ---------------------------------------------------------------------------
# Docker Compose — host network
# ---------------------------------------------------------------------------


class TestComposeHostNetwork:
    def test_host_network_detected(self) -> None:
        services = {"web": {"network_mode": "host"}}
        result = _check_compose_host_network(services, "docker-compose.yml")
        assert len(result) == 1
        assert result[0].rule_id == "CICD.COMPOSE.HOST_NETWORK"

    def test_bridge_network(self) -> None:
        services = {"web": {"network_mode": "bridge"}}
        result = _check_compose_host_network(services, "docker-compose.yml")
        assert len(result) == 0

    def test_no_network_mode(self) -> None:
        services = {"web": {"image": "nginx"}}
        result = _check_compose_host_network(services, "docker-compose.yml")
        assert len(result) == 0


# ---------------------------------------------------------------------------
# Docker Compose — capabilities
# ---------------------------------------------------------------------------


class TestComposeCapabilities:
    def test_dangerous_capability(self) -> None:
        services = {"web": {"cap_add": ["SYS_ADMIN"]}}
        result = _check_compose_capabilities(services, "docker-compose.yml")
        assert len(result) == 1
        assert result[0].rule_id == "CICD.COMPOSE.DANGEROUS_CAPABILITY"
        assert result[0].severity == Severity.ERROR

    def test_safe_capability(self) -> None:
        services = {"web": {"cap_add": ["NET_BIND_SERVICE"]}}
        result = _check_compose_capabilities(services, "docker-compose.yml")
        assert len(result) == 0

    def test_multiple_dangerous(self) -> None:
        services = {"web": {"cap_add": ["SYS_ADMIN", "NET_ADMIN"]}}
        result = _check_compose_capabilities(services, "docker-compose.yml")
        assert len(result) == 2

    def test_fixture_detected(self) -> None:
        content = (INSECURE_REPO / "docker-compose.insecure.yml").read_text()
        import yaml

        doc = yaml.safe_load(content)
        result = _check_compose_capabilities(doc["services"], "docker-compose.insecure.yml")
        assert len(result) >= 1


# ---------------------------------------------------------------------------
# Docker Compose — sensitive ports
# ---------------------------------------------------------------------------


class TestComposeSensitivePorts:
    def test_redis_port(self) -> None:
        services = {"redis": {"ports": ["6379:6379"]}}
        result = _check_compose_sensitive_ports(services, "docker-compose.yml")
        assert len(result) == 1
        assert result[0].rule_id == "CICD.COMPOSE.SENSITIVE_PORT"

    def test_safe_port(self) -> None:
        services = {"web": {"ports": ["8080:80"]}}
        result = _check_compose_sensitive_ports(services, "docker-compose.yml")
        assert len(result) == 0

    def test_multiple_sensitive_ports(self) -> None:
        services = {"db": {"ports": ["5432:5432", "3306:3306"]}}
        result = _check_compose_sensitive_ports(services, "docker-compose.yml")
        assert len(result) == 2

    def test_fixture_detected(self) -> None:
        content = (INSECURE_REPO / "docker-compose.insecure.yml").read_text()
        import yaml

        doc = yaml.safe_load(content)
        result = _check_compose_sensitive_ports(doc["services"], "docker-compose.insecure.yml")
        assert len(result) >= 1


# ---------------------------------------------------------------------------
# Docker Compose — full analysis
# ---------------------------------------------------------------------------


class TestComposeFull:
    def test_analyze_insecure_compose(self) -> None:
        content = (INSECURE_REPO / "docker-compose.insecure.yml").read_text()
        findings = _analyze_compose(INSECURE_REPO / "docker-compose.insecure.yml", content)
        rule_ids = [f.rule_id for f in findings]
        assert "CICD.COMPOSE.PRIVILEGED" in rule_ids
        assert "CICD.COMPOSE.HOST_MOUNT" in rule_ids
        assert "CICD.COMPOSE.SECRET" in rule_ids
        assert "CICD.COMPOSE.DANGEROUS_CAPABILITY" in rule_ids
        assert "CICD.COMPOSE.SENSITIVE_PORT" in rule_ids

    def test_analyze_secure_compose(self) -> None:
        content = (SECURE_REPO / "docker-compose.secure.yml").read_text()
        findings = _analyze_compose(SECURE_REPO / "docker-compose.secure.yml", content)
        rule_ids = [f.rule_id for f in findings]
        assert "CICD.COMPOSE.PRIVILEGED" not in rule_ids
        assert "CICD.COMPOSE.HOST_MOUNT" not in rule_ids
        assert "CICD.COMPOSE.SECRET" not in rule_ids
        assert "CICD.COMPOSE.HOST_NETWORK" not in rule_ids
        assert "CICD.COMPOSE.DANGEROUS_CAPABILITY" not in rule_ids

    def test_no_services(self) -> None:
        findings = _analyze_compose(Path("docker-compose.yml"), "version: '3'\n")
        assert len(findings) == 0

    def test_malformed_yaml(self) -> None:
        findings = _analyze_compose(Path("docker-compose.yml"), "{{invalid: [")
        assert len(findings) == 0

    def test_all_findings_have_correct_fields(self) -> None:
        content = (INSECURE_REPO / "docker-compose.insecure.yml").read_text()
        findings = _analyze_compose(INSECURE_REPO / "docker-compose.insecure.yml", content)
        for finding in findings:
            assert finding.tool == "cicd-analyzer"
            assert finding.rule_id.startswith("CICD.COMPOSE.")
            assert finding.category == "cicd-security"


# ---------------------------------------------------------------------------
# SecurityFinding / ScanResult normalization
# ---------------------------------------------------------------------------


class TestNormalization:
    def test_finding_is_pydantic_model(self) -> None:
        analyzer = CICDAnalyzer()
        result = analyzer.analyze(INSECURE_REPO)
        for finding in result.findings:
            assert isinstance(finding, SecurityFinding)

    def test_scan_result_is_pydantic_model(self) -> None:
        analyzer = CICDAnalyzer()
        result = analyzer.analyze(INSECURE_REPO)
        assert isinstance(result, ScanResult)

    def test_findings_serializable_to_dict(self) -> None:
        analyzer = CICDAnalyzer()
        result = analyzer.analyze(INSECURE_REPO)
        for finding in result.findings:
            d = finding.model_dump()
            assert "rule_id" in d
            assert "severity" in d
            assert "tool" in d

    def test_scan_result_serializable(self) -> None:
        analyzer = CICDAnalyzer()
        result = analyzer.analyze(INSECURE_REPO)
        d = result.model_dump()
        assert "findings" in d
        assert "status" in d

    def test_findings_count_matches(self) -> None:
        analyzer = CICDAnalyzer()
        result = analyzer.analyze(INSECURE_REPO)
        assert result.findings_count == len(result.findings)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_repeated_analysis_same_results(self) -> None:
        analyzer = CICDAnalyzer()
        result1 = analyzer.analyze(INSECURE_REPO)
        result2 = analyzer.analyze(INSECURE_REPO)
        assert result1.findings_count == result2.findings_count
        rules1 = sorted(f.rule_id for f in result1.findings)
        rules2 = sorted(f.rule_id for f in result2.findings)
        assert rules1 == rules2


# ---------------------------------------------------------------------------
# Security restrictions
# ---------------------------------------------------------------------------


class TestSecurity:
    def test_analyzer_uses_no_subprocess(self) -> None:
        import inspect

        from src.tools import cicd_analyzer

        source = inspect.getsource(cicd_analyzer)
        assert "subprocess" not in source

    def test_analyzer_uses_no_exec(self) -> None:
        import inspect

        from src.tools import cicd_analyzer

        source = inspect.getsource(cicd_analyzer)
        assert "exec(" not in source
        assert "eval(" not in source

    def test_analyzer_uses_no_network(self) -> None:
        import inspect

        from src.tools import cicd_analyzer

        source = inspect.getsource(cicd_analyzer)
        assert "urllib" not in source
        assert "requests" not in source
        assert "httpx" not in source

    def test_analyzer_uses_safe_yaml(self) -> None:
        import inspect

        from src.tools import cicd_analyzer

        source = inspect.getsource(cicd_analyzer)
        assert "yaml.safe_load" in source
        assert "yaml.load(" not in source

    def test_no_shell_true(self) -> None:
        import inspect

        from src.tools import cicd_analyzer

        source = inspect.getsource(cicd_analyzer)
        assert "shell=True" not in source
        assert "shell = True" not in source
