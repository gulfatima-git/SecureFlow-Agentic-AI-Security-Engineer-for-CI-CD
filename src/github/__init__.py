"""GitHub integration boundary for SecureFlow.

Provides structured models and validated parsing for GitHub pull-request
webhook payloads.  This is a thin external-input layer: agents must not
depend on raw GitHub JSON.
"""

from src.github.action import (
    SecureFlowAction,
    SecureFlowActionConfig,
    event_to_request,
)
from src.github.models import (
    GitHubPREvent,
    PRAction,
    PRFile,
)
from src.github.webhook import (
    UnsupportedActionError,
    WebhookPayloadError,
    parse_pr_webhook,
    to_repository_context,
    webhook_handler,
)

__all__ = [
    "GitHubPREvent",
    "PRAction",
    "PRFile",
    "SecureFlowAction",
    "SecureFlowActionConfig",
    "UnsupportedActionError",
    "WebhookPayloadError",
    "event_to_request",
    "parse_pr_webhook",
    "to_repository_context",
    "webhook_handler",
]
