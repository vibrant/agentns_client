"""DNS management for AgentNS."""

import httpx

from .auth import AuthSession
from .exceptions import NotFoundError, ValidationError
from .models import DNSRecord, DNSRecordCreate, DNSRecordUpdate


def list_records(
    client: httpx.Client,
    session: AuthSession,
    domain: str,
) -> list[DNSRecord]:
    """List DNS records for a domain.

    Args:
        client: httpx client
        session: Authenticated session
        domain: Domain name

    Returns:
        List of DNS records

    Raises:
        NotFoundError: Domain not found or not owned
    """
    response = client.get(
        f"{session.base_url}/domains/{domain}/dns",
        headers=session.headers,
    )

    if response.status_code == 404:
        raise NotFoundError(f"Domain {domain} not found", status_code=404)

    if response.status_code == 403:
        raise NotFoundError(f"Domain {domain} not owned by this wallet", status_code=403)

    response.raise_for_status()
    data = response.json()
    return [DNSRecord(**r) for r in data["records"]]


def add_record(
    client: httpx.Client,
    session: AuthSession,
    domain: str,
    record: DNSRecordCreate | dict,
) -> DNSRecord:
    """Add a DNS record.

    Args:
        client: httpx client
        session: Authenticated session
        domain: Domain name
        record: DNS record to create

    Returns:
        Created DNS record

    Raises:
        NotFoundError: Domain not found
        ValidationError: Invalid record data
    """
    if isinstance(record, DNSRecordCreate):
        payload = record.model_dump()
    else:
        payload = record

    response = client.post(
        f"{session.base_url}/domains/{domain}/dns",
        headers=session.headers,
        json=payload,
    )

    if response.status_code == 404:
        raise NotFoundError(f"Domain {domain} not found", status_code=404)

    if response.status_code == 400:
        raise ValidationError(
            "Invalid DNS record",
            status_code=400,
            response=response.json() if response.content else None,
        )

    response.raise_for_status()
    return DNSRecord(**response.json())


def update_record(
    client: httpx.Client,
    session: AuthSession,
    domain: str,
    record_id: str,
    updates: DNSRecordUpdate | dict,
) -> DNSRecord:
    """Update a DNS record.

    Args:
        client: httpx client
        session: Authenticated session
        domain: Domain name
        record_id: Record ID to update
        updates: Fields to update

    Returns:
        Updated DNS record

    Raises:
        NotFoundError: Domain or record not found
        ValidationError: Invalid update data
    """
    if isinstance(updates, DNSRecordUpdate):
        payload = updates.model_dump(exclude_unset=True)
    else:
        payload = updates

    response = client.put(
        f"{session.base_url}/domains/{domain}/dns/{record_id}",
        headers=session.headers,
        json=payload,
    )

    if response.status_code == 404:
        raise NotFoundError(
            f"Domain {domain} or record {record_id} not found",
            status_code=404,
        )

    if response.status_code == 400:
        raise ValidationError(
            "Invalid DNS record update",
            status_code=400,
            response=response.json() if response.content else None,
        )

    response.raise_for_status()
    return DNSRecord(**response.json())


def delete_record(
    client: httpx.Client,
    session: AuthSession,
    domain: str,
    record_id: str,
) -> None:
    """Delete a DNS record.

    Args:
        client: httpx client
        session: Authenticated session
        domain: Domain name
        record_id: Record ID to delete

    Raises:
        NotFoundError: Domain or record not found
    """
    response = client.delete(
        f"{session.base_url}/domains/{domain}/dns/{record_id}",
        headers=session.headers,
    )

    if response.status_code == 404:
        raise NotFoundError(
            f"Domain {domain} or record {record_id} not found",
            status_code=404,
        )

    response.raise_for_status()


def get_nameservers(
    client: httpx.Client,
    session: AuthSession,
    domain: str,
) -> list[str]:
    """Get nameservers for a domain.

    Args:
        client: httpx client
        session: Authenticated session
        domain: Domain name

    Returns:
        List of nameserver hostnames

    Raises:
        NotFoundError: Domain not found
    """
    response = client.get(
        f"{session.base_url}/domains/{domain}/nameservers",
        headers=session.headers,
    )

    if response.status_code == 404:
        raise NotFoundError(f"Domain {domain} not found", status_code=404)

    response.raise_for_status()
    return response.json()["nameservers"]


def set_nameservers(
    client: httpx.Client,
    session: AuthSession,
    domain: str,
    nameservers: list[str],
) -> list[str]:
    """Change nameservers for a domain.

    Args:
        client: httpx client
        session: Authenticated session
        domain: Domain name
        nameservers: List of 2-13 nameserver hostnames

    Returns:
        Updated list of nameservers

    Raises:
        NotFoundError: Domain not found
        ValidationError: Invalid nameserver list
    """
    response = client.put(
        f"{session.base_url}/domains/{domain}/nameservers",
        headers=session.headers,
        json={"nameservers": nameservers},
    )

    if response.status_code == 404:
        raise NotFoundError(f"Domain {domain} not found", status_code=404)

    if response.status_code == 400:
        raise ValidationError(
            "Invalid nameservers (need 2-13)",
            status_code=400,
            response=response.json() if response.content else None,
        )

    response.raise_for_status()
    return response.json()["nameservers"]
