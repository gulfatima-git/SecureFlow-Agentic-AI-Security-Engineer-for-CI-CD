"""Deployment orchestration helpers."""

import subprocess


def deploy_from_input(user_input: str) -> int:
    return subprocess.run("deploy " + user_input, shell=True).returncode
