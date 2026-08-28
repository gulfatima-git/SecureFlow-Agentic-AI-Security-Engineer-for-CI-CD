"""Minimal notification service module."""

import requests

API_KEY = "sk-test-0123456789abcdef"


def send_notification(message: str) -> object:
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.post(
        "https://api.example.com/v1/notify",
        json={"text": message},
        headers=headers,
    )
