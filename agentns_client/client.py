"""Main AgentNS client with multi-network support."""

from typing import Any

import httpx
from eth_account import Account

from . import auth as auth_module
from . import dns as dns_module
from . import domains as domains_module
from . import registrant as registrant_module
from .auth import AuthSession
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
from .networks import NetworkType, detect_network
from .payment import get_wallet_address

# Try to import Solana support (optional dependency)
try:
    from solders.keypair import Keypair

    from . import solana_auth as solana_auth_module
    from .solana_auth import SolanaAuthSession

    SOLANA_AVAILABLE = True
except ImportError:
    SOLANA_AVAILABLE = False
    Keypair = None  # type: ignore
    SolanaAuthSession = None  # type: ignore
    solana_auth_module = None  # type: ignore

DEFAULT_BASE_URL = "https://agentns.xyz"

# Type aliases
WalletType = Account | Any  # Any for Keypair when not imported
SessionType = AuthSession | Any  # Any for SolanaAuthSession when not imported


class AgentNSClient:
    """Client for AgentNS domain registration API.

    Supports both EVM (Base mainnet) and Solana wallets.
    Network is auto-detected from wallet address format.

    Usage with EVM wallet:
        from agentns_client import AgentNSClient, load_or_create_wallet

        account = load_or_create_wallet()
        client = AgentNSClient(account=account)
        client.login()
        domain = client.register_domain("myagent.xyz")

    Usage with Solana wallet:
        from agentns_client import AgentNSClient
        from agentns_client.solana_wallet import load_or_create_solana_wallet

        keypair = load_or_create_solana_wallet()
        client = AgentNSClient(account=keypair)
        client.login()
        domain = client.register_domain("myagent.xyz")
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        account: WalletType | None = None,
        timeout: float = 60.0,
    ):
        """Initialize AgentNS client.

        Args:
            base_url: API base URL
            account: Wallet for auth and payments (EVM Account or Solana Keypair)
            timeout: HTTP timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.account = account
        self.timeout = timeout
        self._session: SessionType | None = None
        self._http_client: httpx.Client | None = None
        self._network_type: NetworkType | None = None

        # Detect network type if account provided
        if account is not None:
            address = get_wallet_address(account)
            self._network_type = detect_network(address)

    @property
    def http_client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._http_client is None:
            self._http_client = httpx.Client(timeout=self.timeout)
        return self._http_client

    @property
    def session(self) -> SessionType:
        """Get authenticated session (raises if not logged in)."""
        if self._session is None:
            raise RuntimeError("Not logged in. Call login() first.")
        return self._session

    @property
    def is_authenticated(self) -> bool:
        """Check if client is authenticated."""
        return self._session is not None and not self._session.is_expired

    @property
    def network_type(self) -> NetworkType | None:
        """Get the detected network type (EVM or Solana)."""
        return self._network_type

    @property
    def wallet_address(self) -> str | None:
        """Get the wallet address."""
        if self.account is None:
            return None
        return get_wallet_address(self.account)

    def close(self) -> None:
        """Close HTTP client."""
        if self._http_client is not None:
            self._http_client.close()
            self._http_client = None

    def __enter__(self) -> "AgentNSClient":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    # === Authentication ===

    def login(self) -> None:
        """Authenticate with SIWE (EVM) or SIWS (Solana).

        Network is auto-detected from wallet address format.
        Requires account to be set.
        """
        if self.account is None:
            raise ValueError("No account set. Pass account to constructor.")

        if self._network_type == NetworkType.SOLANA:
            if not SOLANA_AVAILABLE:
                raise ImportError(
                    "Solana support requires 'solders' and 'base58' packages. "
                    "Install with: pip install agentns-client[solana]"
                )
            self._session = solana_auth_module.solana_login(
                self.http_client,
                self.base_url,
                self.account,
            )
        else:
            # EVM (default)
            self._session = auth_module.login(
                self.http_client,
                self.base_url,
                self.account,
            )

    # === Registrant ===

    def get_registrant(self) -> RegistrantProfile | None:
        """Get registrant profile."""
        return registrant_module.get_profile(self.http_client, self.session)

    def create_registrant(self, data: RegistrantCreate | dict) -> RegistrantProfile:
        """Create registrant profile."""
        return registrant_module.create_profile(self.http_client, self.session, data)

    def update_registrant(self, data: RegistrantUpdate | dict) -> RegistrantProfile:
        """Update registrant profile."""
        return registrant_module.update_profile(self.http_client, self.session, data)

    def ensure_registrant(self, data: RegistrantCreate | dict) -> RegistrantProfile:
        """Get existing registrant or create new one."""
        return registrant_module.ensure_profile(self.http_client, self.session, data)

    # === Domains (Public) ===

    def check_domain(self, domain: str) -> DomainCheck:
        """Check domain availability and price (no auth required)."""
        return domains_module.check_domain(self.http_client, self.base_url, domain)

    def search_domains(self, name: str) -> list[DomainSearchResult]:
        """Search domain availability across TLDs (no auth required)."""
        return domains_module.search_domains(self.http_client, self.base_url, name)

    # === Domains (Auth Required) ===

    def list_domains(self) -> list[DomainInfo]:
        """List domains owned by authenticated wallet."""
        return domains_module.list_domains(self.http_client, self.session)

    def register_domain(self, domain: str, years: int = 1) -> DomainInfo:
        """Register a domain with x402 payment.

        Handles the full payment flow automatically.
        Payment method is auto-detected (EIP-3009 for EVM, SPL transfer for Solana).
        Requires account and authenticated session.
        """
        if self.account is None:
            raise ValueError("No account set. Pass account to constructor.")

        return domains_module.register_domain(
            self.http_client,
            self.session,
            self.account,
            domain,
            years,
        )

    # === DNS ===

    def list_dns(self, domain: str) -> list[DNSRecord]:
        """List DNS records for a domain."""
        return dns_module.list_records(self.http_client, self.session, domain)

    def add_dns(
        self,
        domain: str,
        type: str,
        host: str,
        value: str,
        ttl: int = 3600,
        distance: int | None = None,
    ) -> DNSRecord:
        """Add a DNS record."""
        record = DNSRecordCreate(
            type=type,  # type: ignore
            host=host,
            value=value,
            ttl=ttl,
            distance=distance,
        )
        return dns_module.add_record(self.http_client, self.session, domain, record)

    def update_dns(
        self,
        domain: str,
        record_id: str,
        host: str | None = None,
        value: str | None = None,
        ttl: int | None = None,
        distance: int | None = None,
    ) -> DNSRecord:
        """Update a DNS record."""
        updates = DNSRecordUpdate(host=host, value=value, ttl=ttl, distance=distance)
        return dns_module.update_record(
            self.http_client, self.session, domain, record_id, updates
        )

    def delete_dns(self, domain: str, record_id: str) -> None:
        """Delete a DNS record."""
        dns_module.delete_record(self.http_client, self.session, domain, record_id)

    # === Nameservers ===

    def get_nameservers(self, domain: str) -> list[str]:
        """Get nameservers for a domain."""
        return dns_module.get_nameservers(self.http_client, self.session, domain)

    def set_nameservers(self, domain: str, nameservers: list[str]) -> list[str]:
        """Change nameservers for a domain."""
        return dns_module.set_nameservers(
            self.http_client, self.session, domain, nameservers
        )
