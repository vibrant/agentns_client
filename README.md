# AgentNS Python Client

Python client library for [AgentNS](https://agentns.xyz) - a wallet-based ICANN domain registrar for AI agents.

## Features

- **Multi-Chain Support**: EVM (Base) and Solana wallets
- **Wallet Authentication**: SIWE (Ethereum) and SIWS (Solana) authentication
- **Domain Registration**: Full x402 payment protocol support with USDC
- **DNS Management**: Create, update, delete DNS records
- **Nameserver Management**: Configure custom nameservers
- **Type Safety**: Full Pydantic models for all API types

## Installation

```bash
pip install agentns-client
```

For Solana support:

```bash
pip install agentns-client[solana]
```

Or install from source:

```bash
git clone https://github.com/vibrant/agentns_client.git
cd agentns_client
pip install -e ".[solana]"
```

## Quick Start

### EVM (Base) Wallet

```python
from agentns_client import AgentNSClient, load_or_create_wallet

# Create or load EVM wallet
account = load_or_create_wallet()
print(f"Wallet: {account.address}")

# Create client
client = AgentNSClient(account=account)

# Check domain availability (no auth required)
result = client.check_domain("myagent.xyz")
print(f"Available: {result.available}, Price: ${result.price_usdc} USDC")

# Search across TLDs
results = client.search_domains("myagent")
for r in results:
    if r.available:
        print(f"{r.domain}: ${r.price_usdc}")
```

### Solana Wallet

```python
from agentns_client import AgentNSClient, load_or_create_solana_wallet

# Create or load Solana wallet
keypair = load_or_create_solana_wallet()
print(f"Wallet: {keypair.pubkey()}")

# Create client (auto-detects Solana)
client = AgentNSClient(account=keypair)

# Same API as EVM
result = client.check_domain("myagent.xyz")
print(f"Available: {result.available}, Price: ${result.price_usdc} USDC")
```

## Full Registration Flow

```python
from agentns_client import AgentNSClient, load_or_create_wallet

account = load_or_create_wallet()

with AgentNSClient(account=account) as client:
    # 1. Check availability
    check = client.check_domain("myagent.xyz")
    if not check.available:
        print("Domain not available")
        exit(1)

    # 2. Authenticate (SIWE for EVM, SIWS for Solana)
    client.login()

    # 3. Create registrant profile (required by ICANN)
    client.create_registrant({
        "name": "Agent Smith",
        "street_address": "123 AI Street",
        "city": "San Francisco",
        "state_province": "CA",
        "postal_code": "94102",
        "country_code": "US",
        "email": "agent@example.com",
        "phone": "+14155551234",
        "whois_privacy": True,
    })

    # 4. Register domain (handles x402 payment automatically)
    domain = client.register_domain("myagent.xyz", years=1)
    print(f"Registered: {domain.domain}")
    print(f"Expires: {domain.expires_at}")
```

## DNS Management

```python
# List DNS records
records = client.list_dns("myagent.xyz")

# Add A record
client.add_dns("myagent.xyz", type="A", host="@", value="192.0.2.1")

# Add CNAME
client.add_dns("myagent.xyz", type="CNAME", host="www", value="myagent.xyz")

# Add MX record
client.add_dns("myagent.xyz", type="MX", host="@", value="mail.example.com", distance=10)

# Update record
client.update_dns("myagent.xyz", record_id="12345", value="192.0.2.2")

# Delete record
client.delete_dns("myagent.xyz", record_id="12345")
```

## Nameserver Management

```python
# Get current nameservers
ns = client.get_nameservers("myagent.xyz")
print(ns)  # ['ns1.namesilo.com', 'ns2.namesilo.com']

# Change to Cloudflare
client.set_nameservers("myagent.xyz", [
    "ns1.cloudflare.com",
    "ns2.cloudflare.com"
])
```

## API Reference

### AgentNSClient

```python
# EVM wallet
from eth_account import Account
client = AgentNSClient(
    base_url="https://agentns.xyz",  # API base URL
    account=account,                  # eth_account.Account
    timeout=60.0,                     # HTTP timeout
)

# Solana wallet
from solders.keypair import Keypair
client = AgentNSClient(
    base_url="https://agentns.xyz",
    account=keypair,                  # solders.Keypair
    timeout=60.0,
)
```

#### Public Methods (No Auth Required)

| Method | Description |
|--------|-------------|
| `check_domain(domain)` | Check availability and price |
| `search_domains(name)` | Search across 20 TLDs |

#### Authenticated Methods

| Method | Description |
|--------|-------------|
| `login()` | Authenticate with SIWE/SIWS |
| `get_registrant()` | Get registrant profile |
| `create_registrant(data)` | Create registrant profile |
| `update_registrant(data)` | Update registrant profile |
| `list_domains()` | List owned domains |
| `register_domain(domain, years)` | Register with x402 payment |
| `list_dns(domain)` | List DNS records |
| `add_dns(domain, **kwargs)` | Add DNS record |
| `update_dns(domain, record_id, **kwargs)` | Update DNS record |
| `delete_dns(domain, record_id)` | Delete DNS record |
| `get_nameservers(domain)` | Get nameservers |
| `set_nameservers(domain, nameservers)` | Change nameservers |

### Exceptions

```python
from agentns_client import (
    AgentNSError,           # Base exception
    AuthenticationError,    # 401 - Auth failed
    PaymentRequiredError,   # 402 - Payment needed
    NotFoundError,          # 404 - Resource not found
    ConflictError,          # 409 - Already exists
    ValidationError,        # 400 - Invalid input
    RateLimitError,         # 429 - Too many requests
    RegistrationFailedError # Registration failed after payment
)
```

### Wallet Utilities

```python
# EVM wallets
from agentns_client import load_wallet, load_or_create_wallet

account = load_wallet("path/to/wallet.json")           # Load existing
account = load_or_create_wallet("path/to/wallet.json") # Load or create

# Solana wallets
from agentns_client import load_solana_wallet, load_or_create_solana_wallet

keypair = load_solana_wallet("path/to/wallet.json")           # Load existing
keypair = load_or_create_solana_wallet("path/to/wallet.json") # Load or create
```

## Payment Details

AgentNS uses the [x402 protocol](https://www.x402.org/) for payments:

### EVM (Base)
- **Network**: Base (Chain ID: 8453)
- **Currency**: USDC
- **Contract**: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`
- **Method**: EIP-3009 `transferWithAuthorization`

### Solana
- **Network**: Solana Mainnet
- **Currency**: USDC
- **Mint**: `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`
- **Method**: SPL Token `TransferChecked`

The client handles the full payment flow automatically:
1. Request returns 402 with payment requirement
2. Client signs authorization (EIP-3009 for EVM, SPL transfer for Solana)
3. Client resubmits with X-PAYMENT header
4. Domain is registered atomically with payment

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AGENTNS_API` | API base URL | `https://agentns.xyz` |

## License

MIT License - see [LICENSE](LICENSE) for details.

## Links

- [AgentNS Website](https://agentns.xyz)
- [API Documentation](https://agentns.xyz/howtoagents.md)
- [GitHub Issues](https://github.com/vibrant/agentns_client/issues)
