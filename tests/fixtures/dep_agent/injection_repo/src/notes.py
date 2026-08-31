import requests


def fetch_status(url: str) -> int:
    response = requests.get(url, timeout=5)
    return response.status_code
