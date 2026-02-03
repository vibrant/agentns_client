# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AgentNS Python client library for wallet-based ICANN domain registration. Supports both EVM (Base mainnet) and Solana wallets with x402 payment protocol for USDC transactions.

## Commands

```bash
# Install in development mode
pip install -e .

# Install with Solana support
pip install -e ".[solana]"

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check .
ruff format --check .
```

## Publishing

When making changes, update:
1. PyPI package: `agentns-client`
2. ClawHub: https://www.clawhub.ai/vibrant/agentns

## Architecture

### Network Auto-Detection
The client auto-detects wallet type (EVM vs Solana) from address format:
- EVM: `0x`-prefixed, 42 characters
- Solana: Base58, 32-44 characters

Network detection happens in `networks.py` and determines which auth/payment modules to use.

### Authentication Flow
- **EVM**: SIWE (Sign-In With Ethereum) in `auth.py`
- **Solana**: SIWS (Sign-In With Solana) in `solana_auth.py`

Both return JWT tokens stored in `AuthSession`/`SolanaAuthSession` dataclasses.

### x402 Payment Protocol
Domain registration uses the x402 payment protocol:
1. Initial POST to `/domains/register` returns 402 with `X-PAYMENT-REQUIRED` header
2. Client signs payment (EIP-3009 for EVM, SPL TransferChecked for Solana)
3. Resubmit with `X-PAYMENT` header containing base64-encoded signed authorization

Payment logic:
- `payment.py`: EVM EIP-3009 signing
- `solana_payment.py`: Solana SPL Token TransferChecked instruction building

### Module Structure
- `client.py`: Main `AgentNSClient` class - facade over all operations
- `domains.py`: Domain check, search, list, register (handles x402 flow)
- `dns.py`: DNS record CRUD and nameserver management
- `registrant.py`: ICANN registrant profile management
- `models.py`: Pydantic models for all API types
- `exceptions.py`: Custom exception hierarchy

### Solana Support
Solana is an optional dependency (`pip install agentns-client[solana]`). The library gracefully handles missing solders/base58 packages with conditional imports in `__init__.py` and `client.py`.
