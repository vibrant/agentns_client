"""Payment utilities for x402 protocol - EIP-3009 signing."""

import json
import sys
from pathlib import Path

from eth_account import Account

# Constants
CHAIN_ID = 8453  # Base mainnet
USDC_CONTRACT = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
DEFAULT_WALLET_FILE = Path.cwd() / "wallet.json"

# EIP-712 domain for USDC on Base
USDC_EIP712_DOMAIN = {
    "name": "USD Coin",
    "version": "2",
}


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
    print(f"\nFund this wallet with USDC on Base before purchasing domains!")
    return account


def sign_eip3009_authorization(
    account: Account,
    to_address: str,
    value: str,
    valid_after: int,
    valid_before: int,
    nonce: str,
) -> dict:
    """Sign EIP-3009 transferWithAuthorization.

    Args:
        account: Ethereum account to sign with
        to_address: Recipient address
        value: Amount in smallest unit (string)
        valid_after: Unix timestamp (int)
        valid_before: Unix timestamp (int)
        nonce: 32-byte nonce as hex string (0x...)

    Returns:
        dict with:
        - signature: "0x..." prefixed hex string
        - authorization: dict with from, to, value, validAfter (str), validBefore (str), nonce
    """
    domain_data = {
        "name": USDC_EIP712_DOMAIN["name"],
        "version": USDC_EIP712_DOMAIN["version"],
        "chainId": CHAIN_ID,
        "verifyingContract": USDC_CONTRACT,
    }

    message_data = {
        "from": account.address,
        "to": to_address,
        "value": int(value),
        "validAfter": valid_after,
        "validBefore": valid_before,
        "nonce": bytes.fromhex(nonce[2:] if nonce.startswith("0x") else nonce),
    }

    signed = account.sign_typed_data(
        domain_data,
        {
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"},
            ]
        },
        message_data,
    )

    return {
        "signature": "0x" + signed.signature.hex(),
        "authorization": {
            "from": account.address,
            "to": to_address,
            "value": value,
            "validAfter": str(valid_after),
            "validBefore": str(valid_before),
            "nonce": nonce,
        },
    }
