"""Deployment worker."""

import subprocess


def archive(path: str) -> None:
    subprocess.run("tar -czf archive.tgz " + path, shell=True)
