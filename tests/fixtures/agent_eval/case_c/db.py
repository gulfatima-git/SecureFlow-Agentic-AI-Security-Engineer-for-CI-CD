"""Data-access module backed by SQLite."""

import sqlite3


def lookup_user(name: str) -> list[tuple]:
    conn = sqlite3.connect("users.db")
    try:
        cur = conn.cursor()
        query = f"SELECT * FROM users WHERE name = '{name}'"
        cur.execute(query)
        return cur.fetchall()
    finally:
        conn.close()
