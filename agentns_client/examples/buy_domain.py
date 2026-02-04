#!/usr/bin/env python3
"""
AgentNS Domain Purchase Example

Demonstrates the full domain registration flow using the AgentNS client library.
Supports both EVM (Base mainnet) and Solana wallets.

Usage:
    # With EVM wallet (default)
    python -m agentns_client.examples.buy_domain myagent.xyz

    # With Solana wallet
    python -m agentns_client.examples.buy_domain myagent.xyz --solana

Examples:
    python -m agentns_client.examples.buy_domain myagent.xyz
    python -m agentns_client.examples.buy_domain myagent.xyz --solana
    python -m agentns_client.examples.buy_domain myagent.xyz --years 2
    python -m agentns_client.examples.buy_domain myagent.xyz --check-only
    python -m agentns_client.examples.buy_domain myagent --search
"""

import argparse
import json
import os
import sys

from agentns_client import (
    AgentNSClient,
    NetworkType,
    NotFoundError,
    RegistrationFailedError,
    ValidationError,
    load_or_create_wallet,
)

# Configuration
API_BASE = os.getenv("AGENTNS_API", "https://agentns.xyz")

# Default registrant data (customize as needed)
DEFAULT_REGISTRANT = {
    "name": "Agent Smith",
    "organization": "AI Agents Inc",
    "street_address": "123 Agent Street",
    "city": "San Francisco",
    "state_province": "CA",
    "postal_code": "94102",
    "country_code": "US",
    "email": "contact@agentns.xyz",
    "phone": "+14155551234",
    "whois_privacy": True,
}


def main():
    parser = argparse.ArgumentParser(description="Register a domain via AgentNS")
    parser.add_argument("domain", help="Domain to register (e.g., myagent.xyz)")
    parser.add_argument("--years", type=int, default=1, help="Years to register (1-10)")
    parser.add_argument("--check-only", action="store_true", help="Only check availability")
    parser.add_argument("--search", action="store_true", help="Search across all TLDs")
    parser.add_argument(
        "--solana",
        action="store_true",
        help="Use Solana wallet instead of EVM",
    )
    parser.add_argument(
        "--wallet-file",
        help="Path to wallet file (default: wallet.json or solana_wallet.json)",
    )
    args = parser.parse_args()

    # Load wallet based on network choice
    if args.solana:
        try:
            from agentns_client.solana_wallet import load_or_create_solana_wallet
        except ImportError:
            print("Error: Solana support requires additional packages.")
            print("Install with: pip install agentns-client[solana]")
            sys.exit(1)

        print("Loading Solana wallet...")
        wallet_file = args.wallet_file or "solana_wallet.json"
        account = load_or_create_solana_wallet(wallet_file)
        print(f"Wallet address: {account.pubkey()}")
        print("Network: Solana")
    else:
        print("Loading EVM wallet...")
        wallet_file = args.wallet_file or "wallet.json"
        account = load_or_create_wallet(wallet_file)
        print(f"Wallet address: {account.address}")
        print("Network: Base (EVM)")

    # Create client
    with AgentNSClient(base_url=API_BASE, account=account) as client:
        # Show detected network
        network_name = "Solana" if client.network_type == NetworkType.SOLANA else "Base (EVM)"
        print(f"Detected network: {network_name}")

        # Search mode
        if args.search:
            # Extract name without TLD
            name = args.domain.split(".")[0]
            print(f"\nSearching for {name} across TLDs...")
            results = client.search_domains(name)

            print("\nAvailable domains:")
            for r in results:
                if r.available:
                    print(f"  {r.domain:<25} ${r.price_usdc} USDC")

            print("\nUnavailable:")
            for r in results:
                if not r.available:
                    print(f"  {r.domain}")
            return

        # Check domain availability
        print(f"\nChecking availability of {args.domain}...")
        result = client.check_domain(args.domain)

        if not result.available:
            print(f"Domain {args.domain} is not available")
            sys.exit(1)

        print(f"Domain available: {args.domain}")
        print(f"Price: ${result.price_usdc} USDC")

        if args.check_only:
            return

        # Login
        auth_method = "SIWS" if client.network_type == NetworkType.SOLANA else "SIWE"
        print(f"\nAuthenticating with {auth_method}...")
        client.login()
        print("Authenticated successfully")

        # Ensure registrant profile exists
        print("\nChecking registrant profile...")
        profile = client.get_registrant()
        if profile:
            print(f"Using existing profile: {profile.name}")
        else:
            print("Creating registrant profile...")
            profile = client.create_registrant(DEFAULT_REGISTRANT)
            print(f"Created profile: {profile.name}")

        # Register domain
        print(f"\nRegistering {args.domain} for {args.years} year(s)...")
        if client.network_type == NetworkType.SOLANA:
            print("This will sign a Solana SPL Token transfer transaction...")
        else:
            print("This will sign an EIP-3009 USDC authorization...")

        try:
            domain = client.register_domain(args.domain, years=args.years)
            print("\nDomain registered successfully!")
            print("\nDomain details:")
            print(json.dumps(domain.model_dump(), indent=2, default=str))

        except NotFoundError as e:
            print(f"\nError: {e}")
            print("Make sure you have a registrant profile set up.")
            sys.exit(1)

        except ValidationError as e:
            print(f"\nValidation error: {e}")
            if e.response:
                print(json.dumps(e.response, indent=2))
            sys.exit(1)

        except RegistrationFailedError as e:
            print("\nRegistration failed after payment!")
            print(f"Domain: {e.domain}")
            print(f"Payment TX: {e.payment_tx_hash}")
            print(f"Reason: {e.failure_reason}")
            print("\nContact support with this information.")
            sys.exit(1)


if __name__ == "__main__":
    main()
