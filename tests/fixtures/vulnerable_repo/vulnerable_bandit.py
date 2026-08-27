"""Intentionally vulnerable Python file for Bandit integration testing.

This file is NEVER executed. It exists only as static analysis input.
Bandit should detect multiple findings from built-in rules.
"""

import subprocess

# Hardcoded password (B105)
password = "super_secret_123"

# Command injection via subprocess with shell=True (B602)
def dangerous_command(user_input: str) -> str:
    result = subprocess.call(user_input, shell=True)
    return str(result)
