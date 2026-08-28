"""Utility helpers for a small CLI tool."""

import subprocess


def run_command(user_input: str) -> int:
    command = "echo " + user_input
    return subprocess.call(command, shell=True)
