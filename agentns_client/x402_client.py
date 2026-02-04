"""x402 payment protocol integration using the official x402 library."""

import base64
from typing import TYPE_CHECKING, Any

from x402 import parse_payment_required, x402ClientSync
from x402.mechanisms.evm.signer import TypedDataDomain, TypedDataField

if TYPE_CHECKING:
    from eth_account import Account
    from solders.keypair import Keypair
    from solders.transaction import VersionedTransaction


class EvmSignerAdapter:
    """Adapter to make eth_account.Account compatible with x402 ClientEvmSigner."""

    def __init__(self, account: "Account"):
        self._account = account

    @property
    def address(self) -> str:
        """Return checksummed Ethereum address."""
        return self._account.address

    def sign_typed_data(
        self,
        domain: TypedDataDomain,
        types: dict[str, list[TypedDataField]],
        primary_type: str,
        message: dict[str, Any],
    ) -> bytes:
        """Sign EIP-712 typed data.

        Adapts x402's interface to eth_account's sign_typed_data method.
        """
        # Convert domain to eth_account format
        domain_data = {
            "name": domain.get("name"),
            "version": domain.get("version"),
            "chainId": domain.get("chainId"),
            "verifyingContract": domain.get("verifyingContract"),
        }
        # Remove None values
        domain_data = {k: v for k, v in domain_data.items() if v is not None}

        # Convert types to eth_account format
        types_data = {}
        for type_name, fields in types.items():
            types_data[type_name] = [{"name": f["name"], "type": f["type"]} for f in fields]

        signed = self._account.sign_typed_data(
            domain_data,
            types_data,
            message,
        )
        return signed.signature


class SvmSignerAdapter:
    """Adapter to make solders.Keypair compatible with x402 ClientSvmSigner."""

    def __init__(self, keypair: "Keypair"):
        self._keypair = keypair

    @property
    def address(self) -> str:
        """Return base58 encoded public key."""
        return str(self._keypair.pubkey())

    @property
    def keypair(self) -> "Keypair":
        """Return the underlying keypair."""
        return self._keypair

    def sign_transaction(self, tx: "VersionedTransaction") -> "VersionedTransaction":
        """Sign a versioned transaction."""
        from solders.transaction import VersionedTransaction as VT

        # Get the message bytes with version prefix for V0 messages
        msg_bytes = bytes([0x80]) + bytes(tx.message)
        signature = self._keypair.sign_message(msg_bytes)

        # Create new transaction with our signature
        signatures = list(tx.signatures)
        # Find our position in signers (usually index 0 or 1)
        for i, pubkey in enumerate(tx.message.account_keys):
            if str(pubkey) == self.address:
                signatures[i] = signature
                break

        return VT.populate(tx.message, signatures)


class FixedExactSvmSchemeV1:
    """Fixed SVM client for Exact payment scheme (V1).

    This fixes a bug in x402 v2.0.0 where ExactSvmSchemeV1.create_payment_payload()
    calls VersionedTransaction(message, []) with an empty signers list, which fails
    because solders validates that all required signers must be provided at construction.

    The fix uses VersionedTransaction.populate() with pre-computed signatures instead.
    """

    scheme = "exact"

    def __init__(self, signer: SvmSignerAdapter, rpc_url: str | None = None):
        self._signer = signer
        self._custom_rpc_url = rpc_url
        self._clients: dict = {}

    def _get_client(self, network: str):
        """Get or create RPC client for network."""
        from solana.rpc.api import Client as SolanaClient

        from x402.mechanisms.svm.constants import NETWORK_CONFIGS
        from x402.mechanisms.svm.utils import normalize_network

        caip2_network = normalize_network(network)

        if caip2_network in self._clients:
            return self._clients[caip2_network]

        if self._custom_rpc_url:
            rpc_url = self._custom_rpc_url
        else:
            config = NETWORK_CONFIGS.get(caip2_network)
            if not config:
                raise ValueError(f"Unsupported network: {network}")
            rpc_url = config["rpc_url"]

        client = SolanaClient(rpc_url)
        self._clients[caip2_network] = client
        return client

    def create_payment_payload(self, requirements) -> dict:
        """Create signed SPL TransferChecked inner payload (V1 format).

        This is a fixed version of x402's ExactSvmSchemeV1.create_payment_payload()
        that correctly uses VersionedTransaction.populate() instead of the buggy
        VersionedTransaction(message, []) pattern.
        """
        import base64

        from solders.instruction import AccountMeta, Instruction
        from solders.message import MessageV0
        from solders.pubkey import Pubkey
        from solders.signature import Signature
        from solders.transaction import VersionedTransaction

        from x402.mechanisms.svm.constants import (
            COMPUTE_BUDGET_PROGRAM_ADDRESS,
            DEFAULT_COMPUTE_UNIT_LIMIT,
            DEFAULT_COMPUTE_UNIT_PRICE_MICROLAMPORTS,
            TOKEN_2022_PROGRAM_ADDRESS,
            TOKEN_PROGRAM_ADDRESS,
        )
        from x402.mechanisms.svm.utils import derive_ata

        network = requirements.network
        client = self._get_client(network)

        # Facilitator must provide feePayer to cover transaction fees
        extra = requirements.extra or {}
        fee_payer_str = extra.get("feePayer")
        if not fee_payer_str:
            raise ValueError("feePayer is required in requirements.extra for SVM transactions")
        fee_payer = Pubkey.from_string(fee_payer_str)

        mint = Pubkey.from_string(requirements.asset)
        payer_pubkey = Pubkey.from_string(self._signer.address)

        # Fetch token mint info to get decimals and program
        mint_info = client.get_account_info(mint)
        if not mint_info.value:
            raise ValueError(f"Token mint not found: {requirements.asset}")

        # Determine token program from mint owner
        mint_owner = str(mint_info.value.owner)
        if mint_owner == TOKEN_PROGRAM_ADDRESS:
            token_program = Pubkey.from_string(TOKEN_PROGRAM_ADDRESS)
        elif mint_owner == TOKEN_2022_PROGRAM_ADDRESS:
            token_program = Pubkey.from_string(TOKEN_2022_PROGRAM_ADDRESS)
        else:
            raise ValueError(f"Unknown token program: {mint_owner}")

        # Parse mint data to get decimals (at byte 44)
        mint_data = mint_info.value.data
        decimals = mint_data[44]

        # Derive ATAs
        source_ata_str = derive_ata(self._signer.address, requirements.asset, str(token_program))
        dest_ata_str = derive_ata(requirements.pay_to, requirements.asset, str(token_program))
        source_ata = Pubkey.from_string(source_ata_str)
        dest_ata = Pubkey.from_string(dest_ata_str)

        # Build instructions
        compute_budget_program = Pubkey.from_string(COMPUTE_BUDGET_PROGRAM_ADDRESS)

        # 1. SetComputeUnitLimit instruction
        set_cu_limit_data = bytes([2]) + DEFAULT_COMPUTE_UNIT_LIMIT.to_bytes(4, "little")
        set_cu_limit_ix = Instruction(
            program_id=compute_budget_program,
            accounts=[],
            data=set_cu_limit_data,
        )

        # 2. SetComputeUnitPrice instruction
        set_cu_price_data = bytes([3]) + DEFAULT_COMPUTE_UNIT_PRICE_MICROLAMPORTS.to_bytes(
            8, "little"
        )
        set_cu_price_ix = Instruction(
            program_id=compute_budget_program,
            accounts=[],
            data=set_cu_price_data,
        )

        # 3. TransferChecked instruction - V1 uses max_amount_required
        amount = int(requirements.max_amount_required)
        transfer_data = bytes([12]) + amount.to_bytes(8, "little") + bytes([decimals])
        transfer_ix = Instruction(
            program_id=token_program,
            accounts=[
                AccountMeta(source_ata, is_signer=False, is_writable=True),
                AccountMeta(mint, is_signer=False, is_writable=False),
                AccountMeta(dest_ata, is_signer=False, is_writable=True),
                AccountMeta(payer_pubkey, is_signer=True, is_writable=False),
            ],
            data=transfer_data,
        )

        # Get latest blockhash
        blockhash_resp = client.get_latest_blockhash()
        blockhash = blockhash_resp.value.blockhash

        # Build message
        message = MessageV0.try_compile(
            payer=fee_payer,
            instructions=[set_cu_limit_ix, set_cu_price_ix, transfer_ix],
            address_lookup_table_accounts=[],
            recent_blockhash=blockhash,
        )

        # FIX: Use populate() with pre-computed signatures instead of buggy
        # VersionedTransaction(message, []) which fails validation
        msg_bytes_with_version = bytes([0x80]) + bytes(message)
        client_signature = self._signer.keypair.sign_message(msg_bytes_with_version)

        # Client is at index 1, fee_payer placeholder at index 0
        signatures = [Signature.default(), client_signature]
        tx = VersionedTransaction.populate(message, signatures)

        # Encode to base64
        tx_base64 = base64.b64encode(bytes(tx)).decode("utf-8")

        return {"transaction": tx_base64}


def create_x402_client(
    wallet: Any,
    rpc_url: str | None = None,
) -> x402ClientSync:
    """Create an x402 client configured for the given wallet.

    Args:
        wallet: Either an eth_account.Account or solders.Keypair
        rpc_url: Optional Solana RPC URL (only for Solana wallets)

    Returns:
        Configured x402ClientSync
    """
    client = x402ClientSync()

    # Detect wallet type and register appropriate scheme
    if hasattr(wallet, "address"):
        # EVM Account - use registration helper for both V1 and V2
        from x402.mechanisms.evm.exact import register_exact_evm_client

        signer = EvmSignerAdapter(wallet)
        register_exact_evm_client(client, signer)
    elif hasattr(wallet, "pubkey"):
        # Solana Keypair - register V2 scheme and our fixed V1 scheme
        from x402.mechanisms.svm.exact.client import ExactSvmScheme

        signer = SvmSignerAdapter(wallet)

        # Register V2 scheme for wildcard
        v2_scheme = ExactSvmScheme(signer, rpc_url)
        client.register("solana:*", v2_scheme)

        # Register our FIXED V1 scheme instead of buggy library one
        # (x402 v2.0.0 has a bug in ExactSvmSchemeV1 that crashes on VersionedTransaction)
        v1_scheme = FixedExactSvmSchemeV1(signer, rpc_url)
        for network in ["solana", "solana-devnet"]:
            client.register_v1(network, v1_scheme)
    else:
        raise TypeError(f"Unknown wallet type: {type(wallet)}")

    return client


def _caip2_to_v1_network(caip2_id: str) -> str:
    """Convert CAIP-2 network ID to x402 V1 short network name.

    x402 V1 uses short names like 'solana', 'base' instead of
    full CAIP-2 IDs like 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'.
    """
    mapping = {
        "eip155:8453": "base",
        "eip155:84532": "base-sepolia",
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": "solana",
        "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": "solana-devnet",
    }
    return mapping.get(caip2_id, caip2_id)


def _normalize_payment_required(data: bytes | dict) -> dict:
    """Normalize server's payment requirement to x402 library format.

    The server may return a flat format like:
    {
        "x402Version": 2,
        "scheme": "exact",
        "network": "...",
        "maxAmountRequired": "...",
        ...
    }

    But the x402 library expects:
    {
        "x402Version": 1,
        "accepts": [{ "scheme": "exact", "network": "...", ... }]
    }

    This function converts between formats and normalizes network IDs.
    """
    import json

    if isinstance(data, bytes):
        data = json.loads(data)

    # If already has 'accepts' array, it's in the correct format
    if "accepts" in data:
        return data

    # Convert CAIP-2 network ID to V1 short name
    network = data.get("network", "")
    v1_network = _caip2_to_v1_network(network)

    # Extract the payment requirement fields from flat format
    requirement = {
        "scheme": data.get("scheme", "exact"),
        "network": v1_network,
        "maxAmountRequired": data.get("maxAmountRequired"),
        "resource": data.get("resource"),
        "description": data.get("description"),
        "mimeType": data.get("mimeType", "application/json"),
        "payTo": data.get("payTo"),
        "maxTimeoutSeconds": data.get("maxTimeoutSeconds", 300),
        "asset": data.get("asset"),
        "extra": data.get("extra"),
    }

    # Remove None values
    requirement = {k: v for k, v in requirement.items() if v is not None}

    # Return in V1 format (which x402 library can parse)
    return {
        "x402Version": 1,
        "accepts": [requirement],
    }


def build_payment_header(
    wallet: Any,
    payment_required_data: bytes | dict,
) -> str:
    """Build X-PAYMENT header using x402 library.

    Args:
        wallet: Wallet for signing (Account or Keypair)
        payment_required_data: Raw payment required data (bytes or dict)

    Returns:
        Base64-encoded X-PAYMENT header value
    """
    import json

    # Normalize to x402 library format
    normalized = _normalize_payment_required(payment_required_data)

    # Parse using x402 library
    payment_required = parse_payment_required(json.dumps(normalized).encode())

    # Create client and generate payment
    client = create_x402_client(wallet)
    payment_payload = client.create_payment_payload(payment_required)

    # Serialize to JSON and base64 encode (by_alias=True for camelCase field names)
    return base64.b64encode(payment_payload.model_dump_json(by_alias=True).encode()).decode()
