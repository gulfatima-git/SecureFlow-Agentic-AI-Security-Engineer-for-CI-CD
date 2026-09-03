"""Example web application route."""

from flask import Flask, request

API_KEY = "sk-test-0123456789abcdef"

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    return f"Hello, {name}"


def send_notification(message: str) -> None:
    # Placeholder for a notification helper.
    print(message)
