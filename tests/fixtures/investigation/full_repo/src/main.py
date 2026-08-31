#!/usr/bin/env python3
"""Fixture application (data only, never executed by SecureFlow)."""

import subprocess


def deploy(version: str) -> None:
    subprocess.run(["docker", "push", f"app:{version}"], check=True)
