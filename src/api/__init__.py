"""SecureFlow API boundary.

Provides the structured request/response models and HTTP client
interface used by external integrations such as the GitHub Action.
"""

from src.api.client import (
    APIError,
    APITimeoutError,
    ConfigurationError,
    HTTPClientProtocol,
    SecureFlowFakeHTTPClient,
    SecureFlowHTTPClient,
)
from src.api.models import (
    ChangedFile,
    RequestStatus,
    SecureFlowRequest,
    SecureFlowResponse,
)

__all__ = [
    "APIError",
    "APITimeoutError",
    "ChangedFile",
    "ConfigurationError",
    "HTTPClientProtocol",
    "RequestStatus",
    "SecureFlowFakeHTTPClient",
    "SecureFlowHTTPClient",
    "SecureFlowRequest",
    "SecureFlowResponse",
]
