"""Solana payment utilities for x402 protocol - SPL Token transfers.

x402 SVM specification requires:
1. Compute Budget: Set Compute Unit Limit
2. Compute Budget: Set Compute Unit Price
3. SPL Token TransferChecked instruction
"""

import base64
from typing import Any

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.transaction import Transaction

from .networks import SOLANA_USDC_MINT

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
    recent_blockhash: str | None = None,
) -> Transaction:
    """Build a Solana SPL Token transfer transaction for x402.

    x402 SVM spec requires the following instruction sequence:
    1. Compute Budget: Set Compute Unit Limit
    2. Compute Budget: Set Compute Unit Price
    3. SPL Token TransferChecked instruction

    Args:
        keypair: Sender's keypair
        to_address: Recipient's wallet address (Base58)
        amount: Amount in smallest units (USDC has 6 decimals)
        recent_blockhash: Optional blockhash (CDP will use a valid one)

    Returns:
        Partially signed Solana transaction (CDP facilitator adds their signature)
    """
    sender = keypair.pubkey()
    recipient = Pubkey.from_string(to_address)
    mint = Pubkey.from_string(SOLANA_USDC_MINT)

    # Derive ATAs
    source_ata = get_associated_token_address(sender, mint)
    dest_ata = get_associated_token_address(recipient, mint)

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
    ]

    # Use a placeholder blockhash if not provided
    # CDP facilitator will handle the actual blockhash
    if recent_blockhash is None:
        blockhash = Hash.default()
    else:
        blockhash = Hash.from_string(recent_blockhash)

    # Build message and transaction
    message = Message.new_with_blockhash(
        instructions,
        sender,
        blockhash,
    )

    # Create and sign transaction (partially signed - facilitator adds their sig)
    tx = Transaction.new_unsigned(message)
    tx.sign([keypair], blockhash)

    return tx


def sign_solana_payment(
    keypair: Keypair,
    to_address: str,
    value: str,
) -> dict[str, Any]:
    """Sign a Solana USDC payment for x402.

    Unlike EVM which uses EIP-3009 authorization signatures,
    Solana x402 requires a fully serialized and signed transaction.

    Args:
        keypair: Solana keypair
        to_address: Payment recipient address
        value: Amount in smallest units (string)

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
    )

    # Serialize to bytes and encode as base64
    tx_bytes = bytes(tx)
    tx_base64 = base64.b64encode(tx_bytes).decode()

    return {
        "transaction": tx_base64,
    }
