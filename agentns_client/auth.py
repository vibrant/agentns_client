"""SIWE authentication for AgentNS."""

import time
from dataclasses import dataclass

import httpx
from eth_account import Account
from eth_account.messages import encode_defunct
from siwe import SiweMessage

from .exceptions import AuthenticationError
from .models import TokenResponse
from .payment import CHAIN_ID


@dataclass
class AuthSession:
    """Holds authentication state."""

    base_url: str
    token: str
    expires_at: float
    account: Account

    @property
    def headers(self) -> dict[str, str]:
        """Get authorization headers."""
        return {"Authorization": f"Bearer {self.token}"}

    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        return time.time() >= self.expires_at


def get_nonce(client: httpx.Client, base_url: str) -> str:
    """Get SIWE nonce from API.

    Args:
        client: httpx client
        base_url: API base URL

    Returns:
        Nonce string
    """
    response = client.get(f"{base_url}/auth/nonce")
    response.raise_for_status()
    return response.json()["nonce"]


def create_siwe_message(
    address: str,
    nonce: str,
    domain: str = "agentns.xyz",
    uri: str = "https://agentns.xyz",
    statement: str = "Sign in to AgentNS",
) -> str:
    """Create SIWE message for signing.

    Args:
        address: Wallet address
        nonce: Nonce from server
        domain: SIWE domain
        uri: SIWE URI
        statement: Statement to sign

    Returns:
        Formatted SIWE message string
    """
    siwe_message = SiweMessage(
        domain=domain,
        address=address,
        statement=statement,
        uri=uri,
        version="1",
        chain_id=CHAIN_ID,
        nonce=nonce,
        issued_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )
    return siwe_message.prepare_message()


def sign_message(account: Account, message: str) -> str:
    """Sign a SIWE message.

    Args:
        account: Ethereum account
        message: SIWE message string

    Returns:
        Hex signature with 0x prefix
    """
    signable = encode_defunct(text=message)
    signed = account.sign_message(signable)
    return "0x" + signed.signature.hex()


def authenticate(
    client: httpx.Client,
    base_url: str,
    message: str,
    signature: str,
) -> TokenResponse:
    """Verify SIWE signature and get JWT token.

    Args:
        client: httpx client
        base_url: API base URL
        message: SIWE message
        signature: Signature hex string

    Returns:
        TokenResponse with access_token
    """
    response = client.post(
        f"{base_url}/auth/verify",
        json={"message": message, "signature": signature},
    )

    if response.status_code == 401:
        raise AuthenticationError(
            "SIWE verification failed",
            status_code=401,
            response=response.json() if response.content else None,
        )

    response.raise_for_status()
    return TokenResponse(**response.json())


def login(client: httpx.Client, base_url: str, account: Account) -> AuthSession:
    """Complete SIWE login flow.

    Args:
        client: httpx client
        base_url: API base URL
        account: Ethereum account

    Returns:
        AuthSession with token
    """
    # Get nonce
    nonce = get_nonce(client, base_url)

    # Create and sign message
    message = create_siwe_message(
        address=account.address,
        nonce=nonce,
        uri=base_url,
    )
    signature = sign_message(account, message)

    # Authenticate
    token_response = authenticate(client, base_url, message, signature)

    return AuthSession(
        base_url=base_url,
        token=token_response.access_token,
        expires_at=time.time() + token_response.expires_in,
        account=account,
    )
