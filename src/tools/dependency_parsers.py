"""Dependency file parsers: requirements.txt, pyproject.toml, package.json, package-lock.json."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Dependency:
    """A single parsed dependency from a dependency file."""

    name: str
    ecosystem: str
    declared_version: str = ""
    resolved_version: str = ""
    dependency_file: str = ""
    source: str = ""  # e.g., "requirements.txt", "package.json#dependencies"


def parse_requirements_txt(file_path: Path) -> list[Dependency]:
    """Parse a requirements.txt file into Dependency objects.

    Handles common forms:
      requests==2.31.0
      requests>=2.0
      flask
      django~=4.2
      requests[security]>=2.0,<3.0
    """
    deps: list[Dependency] = []
    if not file_path.is_file():
        return deps

    try:
        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return deps

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        dep = _parse_requirement_line(line)
        if dep:
            dep.dependency_file = "requirements.txt"
            deps.append(dep)

    return deps


def _parse_requirement_line(line: str) -> Dependency | None:
    """Parse a single PEP 508-style requirement line."""
    # Strip environment markers (e.g., "; python_version >= '3.8'")
    line = re.split(r"\s*;", line)[0].strip()
    # Strip extras (e.g., requests[security])
    name_match = re.match(r"^([A-Za-z0-9_.-]+)", line)
    if not name_match:
        return None

    name = name_match.group(1)
    # Extract version constraint after the name (skip extras like [security])
    rest = line[name_match.end():]
    # Skip extras: [...]
    extras_match = re.match(r"\[.*?\]", rest)
    if extras_match:
        rest = rest[extras_match.end():]

    version = rest.strip()
    # Strip trailing comments
    if " #" in version:
        version = version[:version.index(" #")].strip()

    return Dependency(
        name=name,
        ecosystem="PyPI",
        declared_version=version if version else "",
    )


def parse_pyproject_toml(file_path: Path) -> list[Dependency]:
    """Parse a pyproject.toml file for [project] dependencies."""
    deps: list[Dependency] = []
    if not file_path.is_file():
        return deps

    try:
        content = file_path.read_bytes()
        data = tomllib.loads(content.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return deps

    project = data.get("project", {})
    dep_list = project.get("dependencies", [])

    for dep_str in dep_list:
        if not isinstance(dep_str, str):
            continue
        dep = _parse_requirement_line(dep_str)
        if dep:
            dep.dependency_file = "pyproject.toml"
            deps.append(dep)

    return deps


def parse_package_json(file_path: Path) -> list[Dependency]:
    """Parse a package.json file for dependencies and devDependencies."""
    deps: list[Dependency] = []
    if not file_path.is_file():
        return deps

    try:
        content = file_path.read_text(encoding="utf-8")
        data = json.loads(content)
    except (OSError, json.JSONDecodeError):
        return deps

    if not isinstance(data, dict):
        return deps

    for section in ("dependencies", "devDependencies"):
        section_data = data.get(section, {})
        if not isinstance(section_data, dict):
            continue
        for name, version in section_data.items():
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            deps.append(Dependency(
                name=name,
                ecosystem="npm",
                declared_version=version,
                dependency_file="package.json",
                source=f"package.json#{section}",
            ))

    return deps


def parse_package_lock(file_path: Path) -> dict[str, str]:
    """Parse a package-lock.json and return a mapping of package name → resolved version.

    Only returns packages with concrete resolved versions.
    """
    resolved: dict[str, str] = {}
    if not file_path.is_file():
        return resolved

    try:
        content = file_path.read_text(encoding="utf-8")
        data = json.loads(content)
    except (OSError, json.JSONDecodeError):
        return resolved

    if not isinstance(data, dict):
        return resolved

    # npm lockfile v2/v3: packages dict with "" as root
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, info in packages.items():
            if not isinstance(info, dict) or key == "":
                continue
            # key is like "node_modules/lodash"
            name = key.split("node_modules/")[-1] if "node_modules/" in key else key
            ver = info.get("version", "")
            if isinstance(ver, str) and ver:
                resolved[name] = ver
        return resolved

    # npm lockfile v1: dependencies dict
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        for name, info in dependencies.items():
            if not isinstance(info, dict):
                continue
            ver = info.get("version", "")
            if isinstance(ver, str) and ver:
                resolved[name] = ver

    return resolved
