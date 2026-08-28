import subprocess


def run_deploy(command: str) -> int:
    return subprocess.call(command, shell=True)
