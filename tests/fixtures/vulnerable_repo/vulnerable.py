"""Intentionally vulnerable Python file for Semgrep integration testing.

This file is NEVER executed. It exists only as static analysis input.
Semgrep should detect at least one pattern from p/default rules.
"""

import subprocess


# Command injection via subprocess with shell=True (widely flagged)
def dangerous_command(user_input: str) -> str:
    result = subprocess.call(user_input, shell=True)
    return str(result)

# Use of assert in non-test code (common semgrep rule)
def validate_input(data: str) -> bool:
    assert len(data) > 0
    return True
