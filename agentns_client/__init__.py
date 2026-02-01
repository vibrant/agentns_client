"""AgentNS Python Client Library.

A complete Python client for the AgentNS domain registration API.

Usage:
    from agentns_client import AgentNSClient, load_or_create_wallet

    # Create client with wallet
    account = load_or_create_wallet()
    client = AgentNSClient(account=account)

    # Check domain (no auth)
    result = client.check_domain("myagent.xyz")

    # Login and register
    client.login()
    client.create_registrant({...})
    domain = client.register_domain("myagent.xyz")
"""

from .client import AgentNSClient
from .exceptions import (
    AgentNSError,
    AuthenticationError,
    ConflictError,
    NotFoundError,
    PaymentRequiredError,
    RateLimitError,
    RegistrationFailedError,
    ValidationError,
)
from .models import (
    DNSRecord,
    DNSRecordCreate,
    DNSRecordUpdate,
    DomainCheck,
    DomainInfo,
    DomainSearchResult,
    RegistrantCreate,
    RegistrantProfile,
    RegistrantUpdate,
)
from .payment import (
    CHAIN_ID,
    USDC_CONTRACT,
    load_or_create_wallet,
    load_wallet,
    sign_eip3009_authorization,
)

__version__ = "0.1.0"

__all__ = [
    # Version
    "__version__",
    # Client
    "AgentNSClient",
    # Exceptions
    "AgentNSError",
    "AuthenticationError",
    "PaymentRequiredError",
    "NotFoundError",
    "ConflictError",
    "RateLimitError",
    "ValidationError",
    "RegistrationFailedError",
    # Models
    "RegistrantCreate",
    "RegistrantProfile",
    "RegistrantUpdate",
    "DomainCheck",
    "DomainSearchResult",
    "DomainInfo",
    "DNSRecord",
    "DNSRecordCreate",
    "DNSRecordUpdate",
    # Payment utilities
    "load_wallet",
    "load_or_create_wallet",
    "sign_eip3009_authorization",
    "CHAIN_ID",
    "USDC_CONTRACT",
]
