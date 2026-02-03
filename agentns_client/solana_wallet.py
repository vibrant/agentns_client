"""Solana wallet management - keypair creation and loading."""

import json
import sys
from pathlib import Path

import base58
from solders.keypair import Keypair

DEFAULT_SOLANA_WALLET_FILE = Path.cwd() / "solana_wallet.json"


def load_solana_wallet(wallet_file: Path | str | None = None) -> Keypair:
    """Load Solana wallet from file (must exist).

    Args:
        wallet_file: Path to wallet file. Defaults to ./solana_wallet.json

    Returns:
        Solders Keypair object

    Raises:
        SystemExit: If wallet file not found
        ValueError: If wallet file format is invalid
    """
    wallet_path = Path(wallet_file) if wallet_file else DEFAULT_SOLANA_WALLET_FILE

    if not wallet_path.exists():
        print(f"Solana wallet file not found: {wallet_path}")
        print("  Run with load_or_create_solana_wallet() first to create a wallet")
        sys.exit(1)

    with open(wallet_path) as f:
        data = json.load(f)

    # Support multiple formats for compatibility
    if "secret_key" in data:
        # Array of bytes format (Solana CLI / Phantom compatible)
        secret_bytes = bytes(data["secret_key"])
        return Keypair.from_bytes(secret_bytes)
    elif "private_key" in data:
        # Base58 encoded format
        secret_bytes = base58.b58decode(data["private_key"])
        return Keypair.from_bytes(secret_bytes)
    else:
        raise ValueError("Wallet file must contain 'secret_key' or 'private_key'")


def load_or_create_solana_wallet(wallet_file: Path | str | None = None) -> Keypair:
    """Load Solana wallet from file or create new one.

    Args:
        wallet_file: Path to wallet file. Defaults to ./solana_wallet.json

    Returns:
        Solders Keypair object
    """
    wallet_path = Path(wallet_file) if wallet_file else DEFAULT_SOLANA_WALLET_FILE

    if wallet_path.exists():
        return load_solana_wallet(wallet_path)

    print("Creating new Solana wallet...")
    keypair = Keypair()

    # Store in multiple formats for compatibility
    data = {
        "address": str(keypair.pubkey()),
        "private_key": base58.b58encode(bytes(keypair)).decode(),
        "secret_key": list(bytes(keypair)),  # Phantom/Solana CLI compatible format
    }

    with open(wallet_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Wallet saved to {wallet_path}")
    print(f"Wallet address: {keypair.pubkey()}")
    print("\nFund this wallet with USDC on Solana before purchasing domains!")
    return keypair


def get_solana_address(keypair: Keypair) -> str:
    """Get the Base58 public key address from a keypair.

    Args:
        keypair: Solders Keypair object

    Returns:
        Base58-encoded public key string
    """
    return str(keypair.pubkey())
