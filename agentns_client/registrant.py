"""Registrant profile management for AgentNS."""

import httpx

from .auth import AuthSession
from .exceptions import ConflictError, NotFoundError, ValidationError
from .models import RegistrantCreate, RegistrantProfile, RegistrantUpdate


def get_profile(client: httpx.Client, session: AuthSession) -> RegistrantProfile | None:
    """Get registrant profile.

    Args:
        client: httpx client
        session: Authenticated session

    Returns:
        RegistrantProfile or None if not found
    """
    response = client.get(
        f"{session.base_url}/registrant",
        headers=session.headers,
    )

    if response.status_code == 404:
        return None

    response.raise_for_status()
    return RegistrantProfile(**response.json())


def create_profile(
    client: httpx.Client,
    session: AuthSession,
    data: RegistrantCreate | dict,
) -> RegistrantProfile:
    """Create registrant profile.

    Args:
        client: httpx client
        session: Authenticated session
        data: Registrant data

    Returns:
        Created RegistrantProfile

    Raises:
        ConflictError: Profile already exists
        ValidationError: Invalid data
    """
    if isinstance(data, RegistrantCreate):
        payload = data.model_dump()
    else:
        payload = data

    response = client.post(
        f"{session.base_url}/registrant",
        headers=session.headers,
        json=payload,
    )

    if response.status_code == 409:
        raise ConflictError(
            "Registrant profile already exists",
            status_code=409,
            response=response.json() if response.content else None,
        )

    if response.status_code == 400:
        raise ValidationError(
            "Invalid registrant data",
            status_code=400,
            response=response.json() if response.content else None,
        )

    response.raise_for_status()
    return RegistrantProfile(**response.json())


def update_profile(
    client: httpx.Client,
    session: AuthSession,
    data: RegistrantUpdate | dict,
) -> RegistrantProfile:
    """Update registrant profile.

    Args:
        client: httpx client
        session: Authenticated session
        data: Fields to update

    Returns:
        Updated RegistrantProfile

    Raises:
        NotFoundError: Profile doesn't exist
        ValidationError: Invalid data
    """
    if isinstance(data, RegistrantUpdate):
        payload = data.model_dump(exclude_unset=True)
    else:
        payload = data

    response = client.put(
        f"{session.base_url}/registrant",
        headers=session.headers,
        json=payload,
    )

    if response.status_code == 404:
        raise NotFoundError(
            "Registrant profile not found",
            status_code=404,
        )

    if response.status_code == 400:
        raise ValidationError(
            "Invalid registrant data",
            status_code=400,
            response=response.json() if response.content else None,
        )

    response.raise_for_status()
    return RegistrantProfile(**response.json())


def ensure_profile(
    client: httpx.Client,
    session: AuthSession,
    data: RegistrantCreate | dict,
) -> RegistrantProfile:
    """Get existing profile or create new one.

    Args:
        client: httpx client
        session: Authenticated session
        data: Registrant data (used if creating)

    Returns:
        RegistrantProfile (existing or newly created)
    """
    profile = get_profile(client, session)
    if profile:
        return profile
    return create_profile(client, session, data)
