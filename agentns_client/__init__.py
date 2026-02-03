"""AgentNS Python Client Library.

A complete Python client for the AgentNS domain registration API.
Supports both EVM (Base mainnet) and Solana wallets.

Usage with EVM:
    from agentns_client import AgentNSClient, load_or_create_wallet

    account = load_or_create_wallet()
    client = AgentNSClient(account=account)
    client.login()
    domain = client.register_domain("myagent.xyz")

Usage with Solana:
    from agentns_client import AgentNSClient
    from agentns_client.solana_wallet import load_or_create_solana_wallet

    keypair = load_or_create_solana_wallet()
    client = AgentNSClient(account=keypair)
    client.login()
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
from .networks import (
    EVM_CAIP2_ID,
    EVM_CHAIN_ID,
    EVM_USDC_CONTRACT,
    SOLANA_CAIP2_ID,
    SOLANA_USDC_MINT,
    NetworkType,
    detect_network,
    is_evm_address,
    is_solana_address,
)
from .payment import (
    CHAIN_ID,
    USDC_CONTRACT,
    get_wallet_address,
    load_or_create_wallet,
    load_wallet,
    sign_eip3009_authorization,
)

# Solana exports (optional - only if solders is installed)
_SOLANA_EXPORTS: list[str] = []
try:
    from .solana_auth import (  # noqa: F401
        SolanaAuthSession,
        create_siws_message,
        sign_solana_message,
    )
    from .solana_payment import sign_solana_payment  # noqa: F401
    from .solana_wallet import (  # noqa: F401
        get_solana_address,
        load_or_create_solana_wallet,
        load_solana_wallet,
    )

    _SOLANA_EXPORTS = [
        "load_solana_wallet",
        "load_or_create_solana_wallet",
        "get_solana_address",
        "SolanaAuthSession",
        "create_siws_message",
        "sign_solana_message",
        "sign_solana_payment",
    ]
except ImportError:
    pass

__version__ = "0.2.0"

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
    # Network utilities
    "NetworkType",
    "detect_network",
    "is_evm_address",
    "is_solana_address",
    "EVM_CHAIN_ID",
    "EVM_USDC_CONTRACT",
    "EVM_CAIP2_ID",
    "SOLANA_USDC_MINT",
    "SOLANA_CAIP2_ID",
    # EVM payment utilities (backward compat)
    "load_wallet",
    "load_or_create_wallet",
    "sign_eip3009_authorization",
    "get_wallet_address",
    "CHAIN_ID",
    "USDC_CONTRACT",
] + _SOLANA_EXPORTS
