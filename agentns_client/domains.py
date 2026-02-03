"""Domain operations for AgentNS."""

import base64
import json
import secrets
import time
from typing import TYPE_CHECKING, Any, Union

import httpx
from eth_account import Account

from .auth import AuthSession
from .exceptions import (
    ConflictError,
    NotFoundError,
    RegistrationFailedError,
    ValidationError,
)
from .models import DomainCheck, DomainInfo, DomainSearchResult, PaymentRequired
from .networks import EVM_CAIP2_ID, SOLANA_CAIP2_ID, NetworkType, detect_network
from .payment import get_wallet_address, sign_eip3009_authorization

if TYPE_CHECKING:
    from solders.keypair import Keypair

    from .solana_auth import SolanaAuthSession

# Type aliases
WalletType = Union[Account, "Keypair"]
SessionType = Union[AuthSession, "SolanaAuthSession"]


def check_domain(client: httpx.Client, base_url: str, domain: str) -> DomainCheck:
    """Check domain availability and price.

    Args:
        client: httpx client
        base_url: API base URL
        domain: Domain to check (e.g., "example.xyz")

    Returns:
        DomainCheck with availability and price
    """
    response = client.post(
        f"{base_url}/domains/check",
        json={"domain": domain},
    )
    response.raise_for_status()
    return DomainCheck(**response.json())


def search_domains(
    client: httpx.Client,
    base_url: str,
    name: str,
) -> list[DomainSearchResult]:
    """Search domain availability across TLDs.

    Args:
        client: httpx client
        base_url: API base URL
        name: Domain name without TLD (e.g., "mycompany")

    Returns:
        List of DomainSearchResult across 20 TLDs
    """
    response = client.post(
        f"{base_url}/domains/search",
        json={"name": name},
    )
    response.raise_for_status()
    data = response.json()
    return [DomainSearchResult(**r) for r in data["results"]]


def list_domains(client: httpx.Client, session: SessionType) -> list[DomainInfo]:
    """List domains owned by authenticated wallet.

    Args:
        client: httpx client
        session: Authenticated session (AuthSession or SolanaAuthSession)

    Returns:
        List of owned domains
    """
    response = client.get(
        f"{session.base_url}/domains",
        headers=session.headers,
    )
    response.raise_for_status()
    data = response.json()
    return [DomainInfo(**d) for d in data["domains"]]


def _parse_payment_requirement(response: httpx.Response) -> PaymentRequired:
    """Parse X-PAYMENT-REQUIRED header."""
    header = response.headers.get("X-PAYMENT-REQUIRED")
    if not header:
        raise ValueError("No X-PAYMENT-REQUIRED header in 402 response")
    decoded = json.loads(base64.b64decode(header))
    return PaymentRequired(**decoded)


def _build_payment_header(
    wallet: WalletType,
    requirement: PaymentRequired,
) -> str:
    """Build X-PAYMENT header with signed authorization/transaction.

    Handles both EVM (EIP-3009) and Solana (serialized transaction) payments.

    Args:
        wallet: Wallet for signing (Account or Keypair)
        requirement: Payment requirement from server

    Returns:
        Base64-encoded X-PAYMENT header value
    """
    wallet_address = get_wallet_address(wallet)
    network_type = detect_network(wallet_address)

    if network_type == NetworkType.EVM:
        return _build_evm_payment_header(wallet, requirement)
    else:
        return _build_solana_payment_header(wallet, requirement)


def _build_evm_payment_header(
    account: Account,
    requirement: PaymentRequired,
) -> str:
    """Build X-PAYMENT header for EVM (EIP-3009 authorization)."""
    # Generate authorization nonce
    auth_nonce = "0x" + secrets.token_hex(32)
    valid_after = 0
    valid_before = int(time.time()) + requirement.maxTimeoutSeconds

    # Sign EIP-3009 authorization
    payment_payload = sign_eip3009_authorization(
        account=account,
        to_address=requirement.payTo,
        value=requirement.maxAmountRequired,
        valid_after=valid_after,
        valid_before=valid_before,
        nonce=auth_nonce,
    )

    # Build X-PAYMENT structure
    x_payment = {
        "x402Version": 1,
        "scheme": "exact",
        "network": EVM_CAIP2_ID,
        "payload": payment_payload,
    }

    return base64.b64encode(json.dumps(x_payment).encode()).decode()


def _build_solana_payment_header(
    keypair: Any,  # Keypair type, but avoiding import
    requirement: PaymentRequired,
) -> str:
    """Build X-PAYMENT header for Solana (serialized transaction).

    Solana x402 uses version 2 format which requires:
    - x402Version: 2
    - resource: URL/description/mimeType of the protected resource
    - accepted: The payment requirements the client accepted
    - payload: Contains the base64-encoded partially-signed transaction
    """
    from .solana_payment import sign_solana_payment

    # Get fee payer from requirement.extra (provided by CDP facilitator)
    fee_payer = None
    if requirement.extra:
        fee_payer = requirement.extra.get("feePayer")

    # Sign Solana payment transaction
    payment_payload = sign_solana_payment(
        keypair=keypair,
        to_address=requirement.payTo,
        value=requirement.maxAmountRequired,
        fee_payer=fee_payer,
    )

    # Build x402 v2 payment structure for Solana
    # The 'accepted' field mirrors the payment requirements
    x_payment = {
        "x402Version": 2,
        "resource": {
            "url": requirement.resource,
            "description": requirement.description,
            "mimeType": requirement.mimeType,
        },
        "accepted": {
            "scheme": requirement.scheme,
            "network": requirement.network,
            "maxAmountRequired": requirement.maxAmountRequired,
            "asset": requirement.asset,
            "payTo": requirement.payTo,
            "maxTimeoutSeconds": requirement.maxTimeoutSeconds,
            "extra": requirement.extra,
        },
        "payload": payment_payload,
    }

    return base64.b64encode(json.dumps(x_payment).encode()).decode()


def register_domain(
    client: httpx.Client,
    session: SessionType,
    wallet: WalletType,
    domain: str,
    years: int = 1,
) -> DomainInfo:
    """Register a domain with x402 payment.

    This handles the full x402 flow for both EVM and Solana:
    1. Initial request returns 402 with payment requirement
    2. Sign payment (EIP-3009 for EVM, serialized tx for Solana)
    3. Resubmit with X-PAYMENT header

    Args:
        client: httpx client
        session: Authenticated session (AuthSession or SolanaAuthSession)
        wallet: Wallet for signing payment (Account or Keypair)
        domain: Domain to register
        years: Registration period (1-10)

    Returns:
        DomainInfo for registered domain

    Raises:
        PaymentRequiredError: If payment flow fails
        RegistrationFailedError: If registration fails after payment
        NotFoundError: If registrant profile missing
        ValidationError: If domain invalid
        ConflictError: If domain already registered
    """
    # Phase 1: Initial request
    response = client.post(
        f"{session.base_url}/domains/register",
        headers=session.headers,
        json={"domain": domain, "years": years},
    )

    # Handle non-402 responses
    if response.status_code == 201:
        # Already registered (shouldn't happen normally)
        return DomainInfo(**response.json())

    if response.status_code == 404:
        raise NotFoundError(
            "Registrant profile not found - create one first",
            status_code=404,
        )

    if response.status_code == 400:
        raise ValidationError(
            f"Invalid domain or parameters: {response.json().get('detail', '')}",
            status_code=400,
            response=response.json() if response.content else None,
        )

    if response.status_code == 409:
        raise ConflictError(
            f"Domain {domain} already registered or pending",
            status_code=409,
        )

    if response.status_code != 402:
        response.raise_for_status()

    # Phase 2: Parse payment requirement and sign
    requirement = _parse_payment_requirement(response)
    payment_header = _build_payment_header(wallet, requirement)

    # Phase 3: Resubmit with payment
    headers = {**session.headers, "X-PAYMENT": payment_header}
    response = client.post(
        f"{session.base_url}/domains/register",
        headers=headers,
        json={"domain": domain, "years": years},
    )

    if response.status_code == 201:
        return DomainInfo(**response.json())

    # Check for registration failure (payment succeeded but NameSilo failed)
    if response.status_code == 200:
        data = response.json()
        if data.get("status") == "failed":
            raise RegistrationFailedError(
                f"Registration failed: {data.get('failure_reason', 'Unknown error')}",
                domain=domain,
                payment_tx_hash=data.get("payment_tx_hash"),
                failure_reason=data.get("failure_reason"),
            )
        return DomainInfo(**data)

    response.raise_for_status()
    return DomainInfo(**response.json())
