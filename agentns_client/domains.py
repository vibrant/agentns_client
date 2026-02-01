"""Domain operations for AgentNS."""

import base64
import json
import secrets
import time

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
from .payment import sign_eip3009_authorization


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


def list_domains(client: httpx.Client, session: AuthSession) -> list[DomainInfo]:
    """List domains owned by authenticated wallet.

    Args:
        client: httpx client
        session: Authenticated session

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
    account: Account,
    requirement: PaymentRequired,
) -> str:
    """Build X-PAYMENT header with signed authorization."""
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
        "network": requirement.network,
        "payload": payment_payload,
    }

    return base64.b64encode(json.dumps(x_payment).encode()).decode()


def register_domain(
    client: httpx.Client,
    session: AuthSession,
    account: Account,
    domain: str,
    years: int = 1,
) -> DomainInfo:
    """Register a domain with x402 payment.

    This handles the full x402 flow:
    1. Initial request returns 402 with payment requirement
    2. Sign EIP-3009 USDC authorization
    3. Resubmit with X-PAYMENT header

    Args:
        client: httpx client
        session: Authenticated session
        account: Ethereum account for signing payment
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
    payment_header = _build_payment_header(account, requirement)

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
