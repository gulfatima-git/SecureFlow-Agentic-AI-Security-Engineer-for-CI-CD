"""CI/CD configuration analyzer.

Statically analyzes GitHub Actions, Dockerfiles, and Docker Compose
configuration files for security issues.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, cast

import yaml

from src.models.security_finding import (
    Confidence,
    ScanResult,
    SecurityFinding,
    Severity,
)

ANALYZER_TOOL_NAME = "cicd-analyzer"

# ---------------------------------------------------------------------------
# GitHub Actions constants
# ---------------------------------------------------------------------------

_GHA_WORKFLOW_GLOB = ".github/workflows/*.yml"
_GHA_WORKFLOW_GLOB_YAML = ".github/workflows/*.yaml"

_DANGEROUS_GHA_TRIGGERS = {"pull_request_target"}

_UNTRUSTED_INPUT_PATTERNS = [
    r"\$\{\{\s*github\.event\.",
    r"\$\{\{\s*github\.pull_request\.",
    r"\$\{\{\s*inputs\.",
    r"\$\{\{\s*github\.head_ref",
    r"\$\{\{\s*github\.event\.comment\.body",
    r"\$\{\{\s*github\.event\.issue\.body",
    r"\$\{\{\s*github\.event\.review\.body",
]

_SECRET_IN_RUN_PATTERNS = [
    r"\$\{\{\s*secrets\.",
]

# ---------------------------------------------------------------------------
# Dockerfile constants
# ---------------------------------------------------------------------------

_DOCKERFILE_GLOBS = ["Dockerfile", "Dockerfile.*"]

_SECRET_NAME_PATTERNS = re.compile(
    r"(?:password|secret|token|key|credential|api_?key|auth)",
    re.IGNORECASE,
)

_CURL_PIPE_SHELL_RE = re.compile(r"(?:curl|wget)\s.*\|\s*(?:sh|bash|zsh|dash|ash)")

_DANGEROUS_ADD_URL_RE = re.compile(r"^ADD\s+https?://", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Docker Compose constants
# ---------------------------------------------------------------------------

_COMPOSE_FILE_GLOBS = ["docker-compose.yml", "docker-compose.yaml"]

_DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "SYS_RAWIO",
    "SYS_MODULE",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "NET_RAW",
    "SYS_CHROOT",
    "MKNOD",
    "AUDIT_WRITE",
    "SETFCAP",
    "SYS_BOOT",
}

_SENSITIVE_HOST_PATHS = [
    "/var/run/docker.sock",
    "/etc/shadow",
    "/etc/passwd",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/etc/ssl",
    "/etc/pki",
]

_SENSITIVE_PORTS = {"22", "3389", "6379", "27017", "5432", "3306", "1433", "1521"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_load_yaml(content: str) -> dict[str, Any] | None:
    """Safely parse YAML content. Returns None on failure."""
    try:
        result = yaml.safe_load(content)
        if isinstance(result, dict):
            return result
        return None
    except (yaml.YAMLError, ValueError):
        return None


def _read_file(path: Path) -> str | None:
    """Read file content, returning None on error."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _make_finding(
    *,
    rule_id: str,
    severity: Severity,
    confidence: Confidence,
    message: str,
    file_path: str,
    start_line: int = 0,
    end_line: int = 0,
    code_snippet: str = "",
    metadata: dict[str, str] | None = None,
) -> SecurityFinding:
    """Create a SecurityFinding with standardized cicd-analyzer tool name."""
    return SecurityFinding(
        tool=ANALYZER_TOOL_NAME,
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        message=message,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        code_snippet=code_snippet,
        category="cicd-security",
        metadata=metadata or {},
    )


# ---------------------------------------------------------------------------
# GitHub Actions checks
# ---------------------------------------------------------------------------


def _check_gha_permissions(
    workflow: dict[str, Any],
    file_path: str,
) -> list[SecurityFinding]:
    """Check GitHub Actions workflow permissions."""
    findings: list[SecurityFinding] = []

    permissions = workflow.get("permissions")
    if permissions is None:
        return findings

    if not isinstance(permissions, dict):
        return findings

    write_perms = {
        k: v
        for k, v in permissions.items()
        if isinstance(v, str) and v.lower() in ("write", "read-write")
    }

    if write_perms:
        top_level_write = {k for k, v in write_perms.items() if v.lower() == "write"}
        overly_broad = top_level_write - {"contents"}
        if overly_broad or len(top_level_write) > 1:
            perms_str = ", ".join(sorted(write_perms.keys()))
            findings.append(
                _make_finding(
                    rule_id="CICD.GHA.EXCESSIVE_PERMISSIONS",
                    severity=Severity.WARNING,
                    confidence=Confidence.HIGH,
                    message=f"Workflow grants write permissions: {perms_str}",
                    file_path=file_path,
                    metadata={"permissions": str(write_perms)},
                )
            )

    return findings


def _check_gha_triggers(
    workflow: dict[str, Any],
    file_path: str,
) -> list[SecurityFinding]:
    """Check GitHub Actions workflow triggers for dangerous patterns."""
    findings: list[SecurityFinding] = []

    # GitHub Actions YAML treats `on:` as boolean True when unquoted by PyYAML
    on_value: Any = workflow.get("on")
    if on_value is None:
        raw_workflow = cast(dict[Any, Any], workflow)
        on_value = raw_workflow.get(True)
    if on_value is None:
        return findings

    triggers: list[str] = []
    if isinstance(on_value, str):
        triggers = [on_value]
    elif isinstance(on_value, list):
        triggers = [str(t) for t in on_value]
    elif isinstance(on_value, dict):
        triggers = [str(k) for k in on_value.keys()]

    for trigger in triggers:
        if trigger in _DANGEROUS_GHA_TRIGGERS:
            findings.append(
                _make_finding(
                    rule_id="CICD.GHA.PULL_REQUEST_TARGET",
                    severity=Severity.ERROR,
                    confidence=Confidence.HIGH,
                    message=f"Workflow uses dangerous trigger: {trigger}",
                    file_path=file_path,
                    metadata={"trigger": trigger},
                )
            )

    return findings


def _check_gha_untrusted_input(
    workflow: dict[str, Any],
    file_path: str,
) -> list[SecurityFinding]:
    """Check for untrusted input reaching shell execution in jobs."""
    findings: list[SecurityFinding] = []

    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return findings

    for job_name, job_def in jobs.items():
        if not isinstance(job_def, dict):
            continue

        steps = job_def.get("steps")
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue

            run_cmd = step.get("run")
            if not isinstance(run_cmd, str):
                continue

            for pattern in _UNTRUSTED_INPUT_PATTERNS:
                if re.search(pattern, run_cmd):
                    step_name = step.get("name", f"step in job '{job_name}'")
                    findings.append(
                        _make_finding(
                            rule_id="CICD.GHA.UNTRUSTED_INPUT",
                            severity=Severity.ERROR,
                            confidence=Confidence.HIGH,
                            message=f"Untrusted input used in shell command in '{step_name}'",
                            file_path=file_path,
                            code_snippet=run_cmd[:200],
                            metadata={"job": str(job_name), "step_name": str(step_name)},
                        )
                    )
                    break

    return findings


def _check_gha_secret_exposure(
    workflow: dict[str, Any],
    file_path: str,
) -> list[SecurityFinding]:
    """Check for secrets passed to unsafe contexts (run commands)."""
    findings: list[SecurityFinding] = []

    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return findings

    for job_name, job_def in jobs.items():
        if not isinstance(job_def, dict):
            continue

        steps = job_def.get("steps")
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue

            run_cmd = step.get("run")
            if not isinstance(run_cmd, str):
                continue

            for pattern in _SECRET_IN_RUN_PATTERNS:
                if re.search(pattern, run_cmd):
                    step_name = step.get("name", f"step in job '{job_name}'")
                    findings.append(
                        _make_finding(
                            rule_id="CICD.GHA.SECRET_EXPOSURE",
                            severity=Severity.ERROR,
                            confidence=Confidence.MEDIUM,
                            message=f"Secret passed to shell command in '{step_name}'",
                            file_path=file_path,
                            code_snippet=run_cmd[:200],
                            metadata={"job": str(job_name), "step_name": str(step_name)},
                        )
                    )
                    break

    return findings


def _check_gha_unpinned_actions(
    workflow: dict[str, Any],
    file_path: str,
) -> list[SecurityFinding]:
    """Check for third-party actions using mutable tags instead of SHA."""
    findings: list[SecurityFinding] = []

    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return findings

    for job_name, job_def in jobs.items():
        if not isinstance(job_def, dict):
            continue

        steps = job_def.get("steps")
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue

            uses_value = step.get("uses")
            if not isinstance(uses_value, str):
                continue

            parts = uses_value.split("@")
            if len(parts) != 2:
                continue

            action_ref = parts[1]

            is_sha = re.match(r"^[0-9a-f]{40}$", action_ref)
            if is_sha:
                continue

            is_official = uses_value.startswith("actions/")
            if is_official:
                continue

            findings.append(
                _make_finding(
                    rule_id="CICD.GHA.UNPINNED_ACTION",
                    severity=Severity.WARNING,
                    confidence=Confidence.HIGH,
                    message=f"Third-party action not pinned to commit SHA: {uses_value}",
                    file_path=file_path,
                    metadata={"action": uses_value, "ref": action_ref},
                )
            )

    return findings


def _analyze_gha_workflow(file_path: Path, content: str) -> list[SecurityFinding]:
    """Analyze a single GitHub Actions workflow file."""
    workflow = _safe_load_yaml(content)
    if workflow is None:
        return []

    rel_path = str(file_path).replace("\\", "/")
    findings: list[SecurityFinding] = []

    findings.extend(_check_gha_permissions(workflow, rel_path))
    findings.extend(_check_gha_triggers(workflow, rel_path))
    findings.extend(_check_gha_untrusted_input(workflow, rel_path))
    findings.extend(_check_gha_secret_exposure(workflow, rel_path))
    findings.extend(_check_gha_unpinned_actions(workflow, rel_path))

    return findings


# ---------------------------------------------------------------------------
# Dockerfile checks
# ---------------------------------------------------------------------------


def _check_dockerfile_root_user(
    lines: list[str],
    file_path: str,
) -> list[SecurityFinding]:
    """Check if Dockerfile runs as root (no USER instruction)."""
    has_user = False
    has_cmd_or_entrypoint = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if stripped.upper().startswith("USER "):
            has_user = True
        if stripped.upper().startswith(("CMD ", "CMD [", "ENTRYPOINT ")):
            has_cmd_or_entrypoint = True

    if not has_user and has_cmd_or_entrypoint:
        return [
            _make_finding(
                rule_id="CICD.DOCKER.ROOT_USER",
                severity=Severity.WARNING,
                confidence=Confidence.MEDIUM,
                message="Dockerfile does not specify a USER instruction; container runs as root",
                file_path=file_path,
                metadata={"issue": "no USER instruction"},
            )
        ]

    return []


def _check_dockerfile_remote_script(
    lines: list[str],
    file_path: str,
) -> list[SecurityFinding]:
    """Check for curl/wget piped to shell in Dockerfile."""
    findings: list[SecurityFinding] = []

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if _CURL_PIPE_SHELL_RE.search(stripped):
            findings.append(
                _make_finding(
                    rule_id="CICD.DOCKER.REMOTE_SCRIPT",
                    severity=Severity.ERROR,
                    confidence=Confidence.HIGH,
                    message="Remote script execution via curl/wget piped to shell",
                    file_path=file_path,
                    start_line=i,
                    end_line=i,
                    code_snippet=stripped,
                )
            )

    return findings


def _check_dockerfile_secrets(
    lines: list[str],
    file_path: str,
) -> list[SecurityFinding]:
    """Check for secrets in ENV and ARG instructions."""
    findings: list[SecurityFinding] = []

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        upper = stripped.upper()

        is_env = upper.startswith("ENV ")
        is_arg = upper.startswith("ARG ")

        if not (is_env or is_arg):
            continue

        instruction_type = "ENV" if is_env else "ARG"
        rule_id = "CICD.DOCKER.SECRET_ENV" if is_env else "CICD.DOCKER.SECRET_ARG"

        parts = stripped.split(None, 2)
        if len(parts) < 2:
            continue

        var_name = parts[1].split("=", 1)[0]

        if _SECRET_NAME_PATTERNS.search(var_name):
            findings.append(
                _make_finding(
                    rule_id=rule_id,
                    severity=Severity.ERROR,
                    confidence=Confidence.MEDIUM,
                    message=f"Possible secret in {instruction_type} instruction: {var_name}",
                    file_path=file_path,
                    start_line=i,
                    end_line=i,
                    code_snippet=stripped,
                    metadata={"instruction": instruction_type, "variable": var_name},
                )
            )

    return findings


def _check_dockerfile_dangerous_add(
    lines: list[str],
    file_path: str,
) -> list[SecurityFinding]:
    """Check for ADD instructions fetching remote URLs."""
    findings: list[SecurityFinding] = []

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if _DANGEROUS_ADD_URL_RE.match(stripped):
            findings.append(
                _make_finding(
                    rule_id="CICD.DOCKER.DANGEROUS_ADD",
                    severity=Severity.WARNING,
                    confidence=Confidence.HIGH,
                    message="ADD instruction fetches a remote URL",
                    file_path=file_path,
                    start_line=i,
                    end_line=i,
                    code_snippet=stripped,
                )
            )

    return findings


def _analyze_dockerfile(file_path: Path, content: str) -> list[SecurityFinding]:
    """Analyze a single Dockerfile."""
    lines = content.splitlines()
    rel_path = str(file_path).replace("\\", "/")
    findings: list[SecurityFinding] = []

    findings.extend(_check_dockerfile_root_user(lines, rel_path))
    findings.extend(_check_dockerfile_remote_script(lines, rel_path))
    findings.extend(_check_dockerfile_secrets(lines, rel_path))
    findings.extend(_check_dockerfile_dangerous_add(lines, rel_path))

    return findings


# ---------------------------------------------------------------------------
# Docker Compose checks
# ---------------------------------------------------------------------------


def _check_compose_privileged(
    services: dict[str, Any],
    file_path: str,
) -> list[SecurityFinding]:
    """Check for privileged containers."""
    findings: list[SecurityFinding] = []

    for svc_name, svc_def in services.items():
        if not isinstance(svc_def, dict):
            continue
        if svc_def.get("privileged") is True:
            findings.append(
                _make_finding(
                    rule_id="CICD.COMPOSE.PRIVILEGED",
                    severity=Severity.ERROR,
                    confidence=Confidence.HIGH,
                    message=f"Service '{svc_name}' runs in privileged mode",
                    file_path=file_path,
                    metadata={"service": str(svc_name)},
                )
            )

    return findings


def _check_compose_host_mounts(
    services: dict[str, Any],
    file_path: str,
) -> list[SecurityFinding]:
    """Check for dangerous host filesystem mounts."""
    findings: list[SecurityFinding] = []

    for svc_name, svc_def in services.items():
        if not isinstance(svc_def, dict):
            continue

        volumes = svc_def.get("volumes")
        if not isinstance(volumes, list):
            continue

        for vol in volumes:
            vol_str = str(vol) if not isinstance(vol, str) else vol
            if ":" not in vol_str:
                continue

            host_part = vol_str.split(":")[0].strip()

            is_sock = host_part.endswith(".sock")
            is_sensitive = any(host_part.startswith(p) for p in _SENSITIVE_HOST_PATHS)

            if is_sock or is_sensitive:
                findings.append(
                    _make_finding(
                        rule_id="CICD.COMPOSE.HOST_MOUNT",
                        severity=Severity.ERROR,
                        confidence=Confidence.HIGH,
                        message=f"Service '{svc_name}' mounts sensitive host path: {host_part}",
                        file_path=file_path,
                        code_snippet=vol_str,
                        metadata={"service": str(svc_name), "host_path": host_part},
                    )
                )

    return findings


def _check_compose_secrets(
    services: dict[str, Any],
    file_path: str,
) -> list[SecurityFinding]:
    """Check for plaintext secrets in environment."""
    findings: list[SecurityFinding] = []

    for svc_name, svc_def in services.items():
        if not isinstance(svc_def, dict):
            continue

        env = svc_def.get("environment")
        if not isinstance(env, list):
            continue

        for entry in env:
            entry_str = str(entry) if not isinstance(entry, str) else entry
            if "=" not in entry_str:
                continue

            key, _, value = entry_str.partition("=")
            key = key.strip()
            value = value.strip()

            if _SECRET_NAME_PATTERNS.search(key) and value and not value.startswith("${"):
                findings.append(
                    _make_finding(
                        rule_id="CICD.COMPOSE.SECRET",
                        severity=Severity.ERROR,
                        confidence=Confidence.MEDIUM,
                        message=f"Plaintext secret in environment variable: {key}",
                        file_path=file_path,
                        code_snippet=entry_str,
                        metadata={"service": str(svc_name), "variable": key},
                    )
                )

    return findings


def _check_compose_host_network(
    services: dict[str, Any],
    file_path: str,
) -> list[SecurityFinding]:
    """Check for host network mode."""
    findings: list[SecurityFinding] = []

    for svc_name, svc_def in services.items():
        if not isinstance(svc_def, dict):
            continue

        network_mode = svc_def.get("network_mode")
        if isinstance(network_mode, str) and network_mode == "host":
            findings.append(
                _make_finding(
                    rule_id="CICD.COMPOSE.HOST_NETWORK",
                    severity=Severity.WARNING,
                    confidence=Confidence.HIGH,
                    message=f"Service '{svc_name}' uses host network mode",
                    file_path=file_path,
                    metadata={"service": str(svc_name)},
                )
            )

    return findings


def _check_compose_capabilities(
    services: dict[str, Any],
    file_path: str,
) -> list[SecurityFinding]:
    """Check for dangerous capabilities."""
    findings: list[SecurityFinding] = []

    for svc_name, svc_def in services.items():
        if not isinstance(svc_def, dict):
            continue

        cap_add = svc_def.get("cap_add")
        if not isinstance(cap_add, list):
            continue

        for cap in cap_add:
            cap_str = str(cap).upper()
            if cap_str in _DANGEROUS_CAPABILITIES:
                findings.append(
                    _make_finding(
                        rule_id="CICD.COMPOSE.DANGEROUS_CAPABILITY",
                        severity=Severity.ERROR,
                        confidence=Confidence.HIGH,
                        message=f"Service '{svc_name}' adds dangerous capability: {cap_str}",
                        file_path=file_path,
                        metadata={"service": str(svc_name), "capability": cap_str},
                    )
                )

    return findings


def _check_compose_sensitive_ports(
    services: dict[str, Any],
    file_path: str,
) -> list[SecurityFinding]:
    """Check for sensitive ports exposed to the host."""
    findings: list[SecurityFinding] = []

    for svc_name, svc_def in services.items():
        if not isinstance(svc_def, dict):
            continue

        ports = svc_def.get("ports")
        if not isinstance(ports, list):
            continue

        for port_entry in ports:
            port_str = str(port_entry) if not isinstance(port_entry, str) else port_entry
            if ":" not in port_str:
                continue

            host_port = port_str.split(":")[0].strip()
            if host_port in _SENSITIVE_PORTS:
                findings.append(
                    _make_finding(
                        rule_id="CICD.COMPOSE.SENSITIVE_PORT",
                        severity=Severity.WARNING,
                        confidence=Confidence.MEDIUM,
                        message=f"Service '{svc_name}' exposes sensitive port {host_port} to host",
                        file_path=file_path,
                        code_snippet=port_str,
                        metadata={"service": str(svc_name), "port": host_port},
                    )
                )

    return findings


def _analyze_compose(file_path: Path, content: str) -> list[SecurityFinding]:
    """Analyze a single docker-compose file."""
    doc = _safe_load_yaml(content)
    if doc is None:
        return []

    rel_path = str(file_path).replace("\\", "/")
    findings: list[SecurityFinding] = []

    services = doc.get("services")
    if not isinstance(services, dict):
        return findings

    findings.extend(_check_compose_privileged(services, rel_path))
    findings.extend(_check_compose_host_mounts(services, rel_path))
    findings.extend(_check_compose_secrets(services, rel_path))
    findings.extend(_check_compose_host_network(services, rel_path))
    findings.extend(_check_compose_capabilities(services, rel_path))
    findings.extend(_check_compose_sensitive_ports(services, rel_path))

    return findings


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------


class CICDAnalyzer:
    """Statically analyzes CI/CD configuration files for security issues.

    Supports GitHub Actions workflows, Dockerfiles, and Docker Compose files.
    All analysis is deterministic and never executes repository content.

    Example::

        analyzer = CICDAnalyzer()
        result = analyzer.analyze("/path/to/repo")
        for finding in result.findings:
            print(f"{finding.severity}: {finding.message}")
    """

    def analyze(self, repository_path: str | Path) -> ScanResult:
        """Analyze CI/CD configuration in a repository.

        Args:
            repository_path: Path to the repository root.

        Returns:
            A ScanResult with CI/CD security findings.
        """
        repo_path = Path(repository_path)
        if not repo_path.is_dir():
            return ScanResult(
                tool=ANALYZER_TOOL_NAME,
                status="error",
                error_message=f"Repository path does not exist or is not a directory: {repo_path}",
            )

        start_time = time.monotonic()

        findings: list[SecurityFinding] = []
        files_analyzed = 0

        # GitHub Actions workflows
        for pattern in [_GHA_WORKFLOW_GLOB, _GHA_WORKFLOW_GLOB_YAML]:
            for workflow_file in repo_path.glob(pattern):
                content = _read_file(workflow_file)
                if content is not None:
                    findings.extend(_analyze_gha_workflow(workflow_file, content))
                    files_analyzed += 1

        # Dockerfiles
        for glob_pattern in _DOCKERFILE_GLOBS:
            for dockerfile in repo_path.glob(glob_pattern):
                if dockerfile.is_file():
                    content = _read_file(dockerfile)
                    if content is not None:
                        findings.extend(_analyze_dockerfile(dockerfile, content))
                        files_analyzed += 1

        # Docker Compose files
        for glob_pattern in _COMPOSE_FILE_GLOBS:
            for compose_file in repo_path.glob(glob_pattern):
                if compose_file.is_file():
                    content = _read_file(compose_file)
                    if content is not None:
                        findings.extend(_analyze_compose(compose_file, content))
                        files_analyzed += 1

        elapsed = time.monotonic() - start_time

        error_message = ""
        if files_analyzed == 0:
            error_message = "No supported CI/CD configuration files found"

        return ScanResult(
            tool=ANALYZER_TOOL_NAME,
            findings=findings,
            status="success",
            error_message=error_message,
            findings_count=len(findings),
            scan_duration_seconds=elapsed,
            tool_version="0.1.0",
        )
