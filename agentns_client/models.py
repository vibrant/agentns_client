"""Pydantic models for AgentNS client."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


# Auth models
class NonceResponse(BaseModel):
    nonce: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 86400


class SIWEVerifyRequest(BaseModel):
    message: str
    signature: str


# Registrant models
class RegistrantCreate(BaseModel):
    name: str
    organization: str | None = None
    street_address: str
    city: str
    state_province: str
    postal_code: str
    country_code: str = Field(min_length=2, max_length=2)
    email: str
    phone: str
    whois_privacy: bool = True


class RegistrantUpdate(BaseModel):
    name: str | None = None
    organization: str | None = None
    street_address: str | None = None
    city: str | None = None
    state_province: str | None = None
    postal_code: str | None = None
    country_code: str | None = None
    email: str | None = None
    phone: str | None = None
    whois_privacy: bool | None = None


class RegistrantProfile(BaseModel):
    id: int
    wallet_address: str
    name: str
    organization: str | None = None
    street_address: str
    city: str
    state_province: str
    postal_code: str
    country_code: str
    email: str
    phone: str
    whois_privacy: bool
    created_at: datetime
    updated_at: datetime | None = None


# Domain models
class DomainCheck(BaseModel):
    domain: str
    available: bool
    price_usdc: str | None = None


class DomainSearchResult(BaseModel):
    domain: str
    available: bool
    price_usdc: str | None = None


class DomainSearchResponse(BaseModel):
    results: list[DomainSearchResult]


class RegisterRequest(BaseModel):
    domain: str
    years: int = Field(ge=1, le=10, default=1)


class DomainInfo(BaseModel):
    domain: str
    owner_address: str
    status: Literal["pending_payment", "paid", "registered", "failed"]
    registered_at: datetime | None = None
    expires_at: datetime | None = None
    payment_tx_hash: str | None = None
    failure_reason: str | None = None


class DomainsListResponse(BaseModel):
    domains: list[DomainInfo]


# DNS models
DNSRecordType = Literal["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA"]


class DNSRecord(BaseModel):
    record_id: str
    type: DNSRecordType
    host: str
    value: str
    ttl: int = 3600
    distance: int | None = None


class DNSRecordCreate(BaseModel):
    type: DNSRecordType
    host: str
    value: str
    ttl: int = Field(default=3600, ge=300, le=86400)
    distance: int | None = Field(default=None, ge=0, le=65535)


class DNSRecordUpdate(BaseModel):
    host: str | None = None
    value: str | None = None
    ttl: int | None = Field(default=None, ge=300, le=86400)
    distance: int | None = Field(default=None, ge=0, le=65535)


class DNSListResponse(BaseModel):
    domain: str
    records: list[DNSRecord]


class NameserversResponse(BaseModel):
    domain: str
    nameservers: list[str]


class NameserversUpdate(BaseModel):
    nameservers: list[str] = Field(min_length=2, max_length=13)


# Payment models
class PaymentRequired(BaseModel):
    x402Version: int = 1
    scheme: str = "exact"
    network: str = "base"
    maxAmountRequired: str
    resource: str
    description: str
    mimeType: str = "application/json"
    payTo: str
    maxTimeoutSeconds: int = 300
    asset: str
    extra: dict | None = None


class Authorization(BaseModel):
    from_address: str = Field(alias="from")
    to: str
    value: str
    validAfter: str
    validBefore: str
    nonce: str

    class Config:
        populate_by_name = True


class PaymentPayload(BaseModel):
    signature: str
    authorization: Authorization


class XPayment(BaseModel):
    x402Version: int = 1
    scheme: str = "exact"
    network: str = "base"
    payload: PaymentPayload
