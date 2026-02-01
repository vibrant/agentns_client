"""Main AgentNS client."""

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

DEFAULT_BASE_URL = "https://agentns.xyz"


class AgentNSClient:
    """Client for AgentNS domain registration API.

    Usage:
        from agentns_client import AgentNSClient, load_or_create_wallet

        # Create client with wallet
        account = load_or_create_wallet()
        client = AgentNSClient(account=account)

        # Check domain availability (no auth required)
        result = client.check_domain("myagent.xyz")
        print(f"Available: {result.available}, Price: {result.price_usdc}")

        # Login for authenticated operations
        client.login()

        # Create registrant profile (required before registration)
        client.create_registrant({
            "name": "Agent Smith",
            "street_address": "123 AI Street",
            "city": "San Francisco",
            "state_province": "CA",
            "postal_code": "94102",
            "country_code": "US",
            "email": "agent@example.com",
            "phone": "+14155551234",
        })

        # Register domain (handles x402 payment flow)
        domain = client.register_domain("myagent.xyz", years=1)
        print(f"Registered: {domain.domain}")

        # Manage DNS
        client.add_dns("myagent.xyz", type="A", host="@", value="192.0.2.1")
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        account: Account | None = None,
        timeout: float = 60.0,
    ):
        """Initialize AgentNS client.

        Args:
            base_url: API base URL
            account: Ethereum account for auth and payments
            timeout: HTTP timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.account = account
        self.timeout = timeout
        self._session: AuthSession | None = None
        self._http_client: httpx.Client | None = None

    @property
    def http_client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._http_client is None:
            self._http_client = httpx.Client(timeout=self.timeout)
        return self._http_client

    @property
    def session(self) -> AuthSession:
        """Get authenticated session (raises if not logged in)."""
        if self._session is None:
            raise RuntimeError("Not logged in. Call login() first.")
        return self._session

    @property
    def is_authenticated(self) -> bool:
        """Check if client is authenticated."""
        return self._session is not None and not self._session.is_expired

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
        """Authenticate with SIWE.

        Requires account to be set.
        """
        if self.account is None:
            raise ValueError("No account set. Pass account to constructor.")

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
