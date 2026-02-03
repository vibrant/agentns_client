"""Solana payment utilities for x402 protocol - SPL Token transfers.

x402 SVM specification requires:
1. Compute Budget: Set Compute Unit Limit
2. Compute Budget: Set Compute Unit Price
3. SPL Token TransferChecked instruction
4. Memo instruction with random nonce
"""

import base64
import secrets
from typing import Any

import httpx
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction

from .networks import SOLANA_USDC_MINT

# Memo Program ID
MEMO_PROGRAM_ID = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")

# Solana RPC endpoint
SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com"

# SPL Token Program ID
TOKEN_PROGRAM_ID = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")

# Associated Token Account Program ID
ATA_PROGRAM_ID = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")

# Compute Budget Program ID
COMPUTE_BUDGET_PROGRAM_ID = Pubkey.from_string("ComputeBudget111111111111111111111111111111")

# USDC decimals for TransferChecked
USDC_DECIMALS = 6


def get_associated_token_address(owner: Pubkey, mint: Pubkey) -> Pubkey:
    """Derive the associated token account address for a wallet and mint.

    This computes the PDA (Program Derived Address) for the ATA.

    Args:
        owner: Wallet public key
        mint: Token mint public key

    Returns:
        Associated token account address
    """
    seeds = [
        bytes(owner),
        bytes(TOKEN_PROGRAM_ID),
        bytes(mint),
    ]

    pda, _bump = Pubkey.find_program_address(seeds, ATA_PROGRAM_ID)
    return pda


def create_set_compute_unit_limit_instruction(units: int) -> Instruction:
    """Create instruction to set compute unit limit.

    Args:
        units: Number of compute units to allocate

    Returns:
        Compute budget instruction
    """
    # Instruction discriminator 2 = SetComputeUnitLimit
    # Followed by u32 units (little endian)
    data = bytes([2]) + units.to_bytes(4, "little")
    return Instruction(COMPUTE_BUDGET_PROGRAM_ID, data, [])


def create_memo_instruction(nonce: str) -> Instruction:
    """Create a memo instruction with a nonce.

    x402 SVM requires a memo instruction with a random nonce for uniqueness.

    Args:
        nonce: Hex-encoded random nonce

    Returns:
        Memo program instruction
    """
    # Memo instruction just has the message as data, no accounts needed
    data = nonce.encode("utf-8")
    return Instruction(MEMO_PROGRAM_ID, data, [])


def get_recent_blockhash() -> Hash:
    """Fetch a recent blockhash from Solana RPC.

    Returns:
        Recent blockhash
    """
    response = httpx.post(
        SOLANA_RPC_URL,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": [{"commitment": "finalized"}],
        },
        timeout=30.0,
    )
    response.raise_for_status()
    result = response.json()["result"]["value"]["blockhash"]
    return Hash.from_string(result)


def create_set_compute_unit_price_instruction(micro_lamports: int) -> Instruction:
    """Create instruction to set compute unit price.

    Args:
        micro_lamports: Price per compute unit in micro-lamports

    Returns:
        Compute budget instruction
    """
    # Instruction discriminator 3 = SetComputeUnitPrice
    # Followed by u64 micro-lamports (little endian)
    data = bytes([3]) + micro_lamports.to_bytes(8, "little")
    return Instruction(COMPUTE_BUDGET_PROGRAM_ID, data, [])


def create_transfer_checked_instruction(
    source_ata: Pubkey,
    mint: Pubkey,
    dest_ata: Pubkey,
    owner: Pubkey,
    amount: int,
    decimals: int,
) -> Instruction:
    """Create an SPL Token TransferChecked instruction.

    x402 SVM requires TransferChecked (not plain Transfer) for payments.

    Args:
        source_ata: Source associated token account
        mint: Token mint address
        dest_ata: Destination associated token account
        owner: Owner of the source account (signer)
        amount: Amount in smallest units
        decimals: Token decimals for verification

    Returns:
        Solana instruction for the transfer
    """
    # SPL Token TransferChecked instruction layout:
    # - Instruction discriminator: 12 (TransferChecked)
    # - Amount: u64 (little endian)
    # - Decimals: u8
    data = bytes([12]) + amount.to_bytes(8, "little") + bytes([decimals])

    accounts = [
        AccountMeta(source_ata, is_signer=False, is_writable=True),
        AccountMeta(mint, is_signer=False, is_writable=False),
        AccountMeta(dest_ata, is_signer=False, is_writable=True),
        AccountMeta(owner, is_signer=True, is_writable=False),
    ]

    return Instruction(TOKEN_PROGRAM_ID, data, accounts)


def build_solana_payment_transaction(
    keypair: Keypair,
    to_address: str,
    amount: int,
    fee_payer: str | None = None,
) -> VersionedTransaction:
    """Build a Solana SPL Token transfer transaction for x402.

    x402 SVM spec requires versioned transactions (V0) with:
    1. Compute Budget: Set Compute Unit Limit
    2. Compute Budget: Set Compute Unit Price
    3. SPL Token TransferChecked instruction
    4. Memo instruction with random nonce

    Args:
        keypair: Sender's keypair
        to_address: Recipient's wallet address (Base58)
        amount: Amount in smallest units (USDC has 6 decimals)
        fee_payer: CDP facilitator's fee payer address (will pay tx fees)

    Returns:
        Partially signed Solana versioned transaction (V0)
    """
    sender = keypair.pubkey()
    recipient = Pubkey.from_string(to_address)
    mint = Pubkey.from_string(SOLANA_USDC_MINT)

    # Use CDP fee payer if provided, otherwise sender pays fees
    payer = Pubkey.from_string(fee_payer) if fee_payer else sender

    # Derive ATAs
    source_ata = get_associated_token_address(sender, mint)
    dest_ata = get_associated_token_address(recipient, mint)

    # Generate random nonce for memo (16 bytes as hex)
    nonce = secrets.token_hex(16)

    # Fetch recent blockhash from Solana RPC
    blockhash = get_recent_blockhash()

    # Build instruction sequence per x402 SVM spec
    instructions = [
        # 1. Set compute unit limit (200k should be sufficient)
        create_set_compute_unit_limit_instruction(200_000),
        # 2. Set compute unit price (1 micro-lamport, within 5 lamport cap)
        create_set_compute_unit_price_instruction(1),
        # 3. TransferChecked instruction
        create_transfer_checked_instruction(
            source_ata=source_ata,
            mint=mint,
            dest_ata=dest_ata,
            owner=sender,
            amount=amount,
            decimals=USDC_DECIMALS,
        ),
        # 4. Memo instruction with random nonce for uniqueness
        create_memo_instruction(nonce),
    ]

    # Build V0 message (versioned transaction required by x402)
    # CDP fee payer is set as the transaction fee payer
    # address_lookup_table_accounts is empty since we don't use lookup tables
    message = MessageV0.try_compile(
        payer,  # fee payer (CDP facilitator or sender)
        instructions,  # instructions
        [],  # address_lookup_table_accounts
        blockhash,  # recent_blockhash
    )

    # Create versioned transaction and partially sign with sender's keypair
    # CDP facilitator will add their signature for the fee payer
    tx = VersionedTransaction(message, [keypair])

    return tx


def sign_solana_payment(
    keypair: Keypair,
    to_address: str,
    value: str,
    fee_payer: str | None = None,
) -> dict[str, Any]:
    """Sign a Solana USDC payment for x402.

    Unlike EVM which uses EIP-3009 authorization signatures,
    Solana x402 requires a fully serialized and signed transaction.

    Args:
        keypair: Solana keypair
        to_address: Payment recipient address
        value: Amount in smallest units (string)
        fee_payer: CDP facilitator's fee payer address

    Returns:
        dict with:
        - transaction: Base64-encoded serialized signed transaction
    """
    amount = int(value)

    # Build and sign the transaction
    tx = build_solana_payment_transaction(
        keypair=keypair,
        to_address=to_address,
        amount=amount,
        fee_payer=fee_payer,
    )

    # Serialize to bytes and encode as base64
    tx_bytes = bytes(tx)
    tx_base64 = base64.b64encode(tx_bytes).decode()

    return {
        "transaction": tx_base64,
    }
