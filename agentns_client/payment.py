"""Wallet utilities for AgentNS.

This module provides wallet loading and management functions.
Payment signing is handled by the x402 library via x402_client.py.
"""

import json
import sys
from pathlib import Path
from typing import Any

from eth_account import Account

DEFAULT_WALLET_FILE = Path.cwd() / "wallet.json"


def load_wallet(wallet_file: Path | str | None = None) -> Account:
    """Load wallet from wallet.json (must exist).

    Args:
        wallet_file: Path to wallet file. Defaults to ./wallet.json
    """
    wallet_path = Path(wallet_file) if wallet_file else DEFAULT_WALLET_FILE

    if not wallet_path.exists():
        print(f"Wallet file not found: {wallet_path}")
        print("  Run with load_or_create_wallet() first to create a wallet")
        sys.exit(1)

    with open(wallet_path) as f:
        data = json.load(f)
    account = Account.from_key(data["private_key"])
    return account


def load_or_create_wallet(wallet_file: Path | str | None = None) -> Account:
    """Load wallet from file or create new one.

    Args:
        wallet_file: Path to wallet file. Defaults to ./wallet.json
    """
    wallet_path = Path(wallet_file) if wallet_file else DEFAULT_WALLET_FILE

    if wallet_path.exists():
        with open(wallet_path) as f:
            data = json.load(f)
        account = Account.from_key(data["private_key"])
        return account

    print("Creating new wallet...")
    account = Account.create()
    data = {
        "address": account.address,
        "private_key": account.key.hex(),
    }
    with open(wallet_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Wallet saved to {wallet_path}")
    print(f"Wallet address: {account.address}")
    print("\nFund this wallet with USDC on Base before purchasing domains!")
    return account


def get_wallet_address(wallet: Account | Any) -> str:
    """Get address from either EVM Account or Solana Keypair.

    Args:
        wallet: Either an eth_account.Account or solders.Keypair

    Returns:
        Wallet address string

    Raises:
        TypeError: If wallet type is unknown
    """
    if hasattr(wallet, "address"):
        # EVM Account
        return wallet.address
    elif hasattr(wallet, "pubkey"):
        # Solana Keypair
        return str(wallet.pubkey())
    else:
        raise TypeError(f"Unknown wallet type: {type(wallet)}")
