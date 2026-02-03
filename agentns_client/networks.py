"""Network detection and constants for multi-chain support."""

from enum import Enum

# EVM Constants (Base Mainnet)
EVM_CHAIN_ID = 8453
EVM_USDC_CONTRACT = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
EVM_CAIP2_ID = "eip155:8453"

# Solana Constants
SOLANA_USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
SOLANA_CAIP2_ID = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"


class NetworkType(Enum):
    """Supported blockchain networks."""

    EVM = "evm"
    SOLANA = "solana"


def detect_network(address: str) -> NetworkType:
    """Detect blockchain network from wallet address format.

    Args:
        address: Wallet address string

    Returns:
        NetworkType.EVM or NetworkType.SOLANA

    Raises:
        ValueError: If address format is unrecognized
    """
    if is_evm_address(address):
        return NetworkType.EVM
    if is_solana_address(address):
        return NetworkType.SOLANA
    raise ValueError(f"Unknown wallet address format: {address}")


def is_evm_address(address: str) -> bool:
    """Check if address is EVM format (0x-prefixed, 42 chars)."""
    return address.startswith("0x") and len(address) == 42


def is_solana_address(address: str) -> bool:
    """Check if address is Solana format (Base58, 32-44 chars)."""
    if address.startswith("0x"):
        return False
    if not 32 <= len(address) <= 44:
        return False
    # Basic Base58 character check
    base58_chars = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    return all(c in base58_chars for c in address)
