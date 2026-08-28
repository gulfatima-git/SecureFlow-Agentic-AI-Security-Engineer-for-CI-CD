"""Small application service following secure coding practices."""

import sqlite3
import subprocess


def lookup_user(name: str) -> list[tuple]:
    conn = sqlite3.connect("users.db")
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE name = ?", (name,))
        return cur.fetchall()
    finally:
        conn.close()


def run_utility(cmd: str, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run([cmd, *args], shell=False, capture_output=True, text=True)
