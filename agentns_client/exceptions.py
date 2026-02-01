"""Custom exceptions for AgentNS client."""

from typing import Any


class AgentNSError(Exception):
    """Base exception for AgentNS client errors."""

    def __init__(self, message: str, status_code: int | None = None, response: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class AuthenticationError(AgentNSError):
    """Authentication failed (401)."""

    pass


class PaymentRequiredError(AgentNSError):
    """Payment required (402). Contains payment details."""

    def __init__(
        self,
        message: str,
        payment_requirement: dict,
        status_code: int = 402,
        response: Any = None,
    ):
        super().__init__(message, status_code, response)
        self.payment_requirement = payment_requirement


class NotFoundError(AgentNSError):
    """Resource not found (404)."""

    pass


class ConflictError(AgentNSError):
    """Conflict error (409)."""

    pass


class ValidationError(AgentNSError):
    """Validation error (400)."""

    pass


class RateLimitError(AgentNSError):
    """Rate limit exceeded (429)."""

    pass


class RegistrationFailedError(AgentNSError):
    """Domain registration failed after payment."""

    def __init__(
        self,
        message: str,
        domain: str,
        payment_tx_hash: str | None = None,
        failure_reason: str | None = None,
    ):
        super().__init__(message)
        self.domain = domain
        self.payment_tx_hash = payment_tx_hash
        self.failure_reason = failure_reason
