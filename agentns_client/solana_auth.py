"""SIWS (Sign-In With Solana) authentication for AgentNS."""

import time
from dataclasses import dataclass

import base58
import httpx
from solders.keypair import Keypair

from .auth import get_nonce
from .exceptions import AuthenticationError
from .models import TokenResponse


@dataclass
class SolanaAuthSession:
    """Holds Solana authentication state."""

    base_url: str
    token: str
    expires_at: float
    keypair: Keypair

    @property
    def headers(self) -> dict[str, str]:
        """Get authorization headers."""
        return {"Authorization": f"Bearer {self.token}"}

    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        return time.time() >= self.expires_at

    @property
    def address(self) -> str:
        """Get wallet address."""
        return str(self.keypair.pubkey())


def create_siws_message(
    address: str,
    nonce: str,
    domain: str = "agentns.xyz",
    uri: str = "https://agentns.xyz",
    statement: str = "Sign in to AgentNS",
) -> str:
    """Create SIWS message for signing.

    SIWS message format (similar to SIWE but for Solana):

    {domain} wants you to sign in with your Solana account:
    {address}

    {statement}

    URI: {uri}
    Version: 1
    Nonce: {nonce}
    Issued At: {issued_at}

    Args:
        address: Solana wallet address (Base58 public key)
        nonce: Nonce from server
        domain: SIWS domain
        uri: SIWS URI
        statement: Statement to sign

    Returns:
        Formatted SIWS message string
    """
    issued_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    return f"""{domain} wants you to sign in with your Solana account:
{address}

{statement}

URI: {uri}
Version: 1
Nonce: {nonce}
Issued At: {issued_at}"""


def sign_solana_message(keypair: Keypair, message: str) -> str:
    """Sign a message with Solana keypair (Ed25519).

    Args:
        keypair: Solana keypair
        message: Message string to sign

    Returns:
        Base58-encoded signature
    """
    message_bytes = message.encode("utf-8")
    signature = keypair.sign_message(message_bytes)
    return base58.b58encode(bytes(signature)).decode()


def solana_authenticate(
    client: httpx.Client,
    base_url: str,
    message: str,
    signature: str,
) -> TokenResponse:
    """Verify SIWS signature and get JWT token.

    Args:
        client: httpx client
        base_url: API base URL
        message: SIWS message
        signature: Base58 signature string

    Returns:
        TokenResponse with access_token
    """
    response = client.post(
        f"{base_url}/auth/verify",
        json={"message": message, "signature": signature},
    )

    if response.status_code == 401:
        raise AuthenticationError(
            "SIWS verification failed",
            status_code=401,
            response=response.json() if response.content else None,
        )

    response.raise_for_status()
    return TokenResponse(**response.json())


def solana_login(
    client: httpx.Client,
    base_url: str,
    keypair: Keypair,
) -> SolanaAuthSession:
    """Complete SIWS login flow.

    Args:
        client: httpx client
        base_url: API base URL
        keypair: Solana keypair

    Returns:
        SolanaAuthSession with token
    """
    # Get nonce (same endpoint for both SIWE and SIWS)
    nonce = get_nonce(client, base_url)

    # Create and sign message
    address = str(keypair.pubkey())
    message = create_siws_message(
        address=address,
        nonce=nonce,
        uri=base_url,
    )
    signature = sign_solana_message(keypair, message)

    # Authenticate
    token_response = solana_authenticate(client, base_url, message, signature)

    return SolanaAuthSession(
        base_url=base_url,
        token=token_response.access_token,
        expires_at=time.time() + token_response.expires_in,
        keypair=keypair,
    )
