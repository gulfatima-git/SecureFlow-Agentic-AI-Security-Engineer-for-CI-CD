"""Database access layer."""

import sqlite3


def find_user(name: str) -> list[tuple]:
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cur.execute(query)
    return cur.fetchall()
