"""OAuth2 client database operations."""

import oauth2
from database._core import TenantArg, execute, fetchall, fetchone
from database.users import create_user


def create_normal_client(
    tenant_id: TenantArg,
    tenant_id_value: str,
    name: str,
    redirect_uris: list[str],
    created_by: str,
    description: str | None = None,
) -> dict | None:
    """
    Create a normal OAuth2 client for authorization code flow.

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store
        name: Client name
        redirect_uris: List of exact redirect URIs
        created_by: User ID who created the client

    Returns:
        Dict with client details including id, client_id, and plain text client_secret
        (client_secret is only returned once!)
    """
    # Generate client credentials
    client_id = oauth2.generate_client_id()
    client_secret = oauth2.generate_client_secret()
    client_secret_hash = oauth2.hash_token(client_secret)

    # Insert client
    client = fetchone(
        tenant_id,
        """
        insert into oauth2_clients (
            tenant_id, client_id, client_secret_hash, client_type,
            name, description, redirect_uris, created_by
        )
        values (
            :tenant_id, :client_id, :client_secret_hash, 'normal',
            :name, :description, :redirect_uris, :created_by
        )
        returning id, tenant_id, client_id, client_type, name, description,
                  redirect_uris, service_user_id, is_active, created_at
        """,
        {
            "tenant_id": tenant_id_value,
            "client_id": client_id,
            "client_secret_hash": client_secret_hash,
            "name": name,
            "description": description,
            "redirect_uris": redirect_uris,
            "created_by": created_by,
        },
    )

    if client:
        client["client_secret"] = client_secret  # Add plain text secret (shown once)

    return client


def create_b2b_client(
    tenant_id: TenantArg,
    tenant_id_value: str,
    name: str,
    role: str,
    created_by: str,
    description: str | None = None,
) -> dict | None:
    """
    Create a B2B OAuth2 client for client credentials flow.

    This automatically creates a service user with the specified role.
    The service user's first_name is set to the client name, and last_name to "Service Account".

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store
        name: Client name (also used as service user first_name)
        role: Role for service user ('member', 'admin', 'super_admin')
        created_by: User ID who created the client

    Returns:
        Dict with client details including id, client_id, service_user_id, and plain
        text client_secret (client_secret is only returned once!)
    """
    # First, create the service user
    # Service users have no password and use client name as first_name
    service_user = create_user(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id_value,
        first_name=name,
        last_name="Service Account",
        email=f"service_{oauth2.generate_opaque_token('user')}@system.local",
        role=role,
    )

    if not service_user:
        raise ValueError("Failed to create service user")

    # Generate client credentials
    client_id = oauth2.generate_client_id("weft-id_b2b")
    client_secret = oauth2.generate_client_secret()
    client_secret_hash = oauth2.hash_token(client_secret)

    # Insert B2B client
    client = fetchone(
        tenant_id,
        """
        insert into oauth2_clients (
            tenant_id, client_id, client_secret_hash, client_type,
            name, description, service_user_id, created_by
        )
        values (
            :tenant_id, :client_id, :client_secret_hash, 'b2b',
            :name, :description, :service_user_id, :created_by
        )
        returning id, tenant_id, client_id, client_type, name, description,
                  redirect_uris, service_user_id, is_active, created_at
        """,
        {
            "tenant_id": tenant_id_value,
            "client_id": client_id,
            "client_secret_hash": client_secret_hash,
            "name": name,
            "description": description,
            "service_user_id": service_user["user_id"],
            "created_by": created_by,
        },
    )

    if client:
        client["client_secret"] = client_secret  # Add plain text secret (shown once)

    return client


def get_client_by_client_id(tenant_id: TenantArg, client_id: str) -> dict | None:
    """
    Get OAuth2 client by client_id (the TEXT identifier, e.g., "weft-id_client_abc123").

    Returns:
        Client record with id, tenant_id, client_id, client_secret_hash, client_type,
        name, redirect_uris, service_user_id, created_at
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, client_id, client_secret_hash, client_type,
               name, description, redirect_uris, service_user_id, is_active, created_at
        from oauth2_clients
        where client_id = :client_id
        """,
        {"client_id": client_id},
    )


def get_client_by_id(tenant_id: TenantArg, id: str) -> dict | None:
    """
    Get OAuth2 client by internal UUID (the primary key).

    This is used when looking up client details from token validation,
    which returns the client's internal ID (FK to oauth2_clients.id).

    Returns:
        Client record with id, tenant_id, client_id, client_type, name,
        redirect_uris, service_user_id, created_at
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, client_id, client_type, name, description,
               redirect_uris, service_user_id, is_active, created_at
        from oauth2_clients
        where id = :id
        """,
        {"id": id},
    )


def get_all_clients(tenant_id: TenantArg, client_type: str | None = None) -> list[dict]:
    """
    Get all OAuth2 clients for a tenant.

    Args:
        tenant_id: Tenant ID for scoping
        client_type: Optional filter by client type ('normal' or 'b2b')

    Returns:
        List of client records (includes service_role from joined users table)
    """
    if client_type:
        return fetchall(
            tenant_id,
            """
            select c.id, c.tenant_id, c.client_id, c.client_type, c.name,
                   c.description, c.redirect_uris, c.service_user_id,
                   c.is_active, c.created_at, u.role as service_role
            from oauth2_clients c
            left join users u on c.service_user_id = u.id
            where c.client_type = :client_type
            order by c.created_at desc
            """,
            {"client_type": client_type},
        )
    return fetchall(
        tenant_id,
        """
        select c.id, c.tenant_id, c.client_id, c.client_type, c.name,
               c.description, c.redirect_uris, c.service_user_id,
               c.is_active, c.created_at, u.role as service_role
        from oauth2_clients c
        left join users u on c.service_user_id = u.id
        order by c.created_at desc
        """,
        {},
    )


def delete_client(tenant_id: TenantArg, client_id: str) -> int:
    """
    Delete an OAuth2 client.

    This cascades to delete all tokens and authorization codes.
    For B2B clients, the service user is NOT deleted (ON DELETE RESTRICT prevents this).

    Returns:
        Number of rows deleted
    """
    return execute(
        tenant_id,
        "delete from oauth2_clients where client_id = :client_id",
        {"client_id": client_id},
    )


def regenerate_client_secret(tenant_id: TenantArg, client_id: str) -> str:
    """
    Regenerate client secret for an OAuth2 client.

    Args:
        tenant_id: Tenant ID for scoping
        client_id: Client ID to regenerate secret for

    Returns:
        New plain text client_secret (shown only once!)
    """
    # Generate new secret
    client_secret = oauth2.generate_client_secret()
    client_secret_hash = oauth2.hash_token(client_secret)

    # Update client
    execute(
        tenant_id,
        """
        update oauth2_clients
        set client_secret_hash = :client_secret_hash
        where client_id = :client_id
        """,
        {"client_secret_hash": client_secret_hash, "client_id": client_id},
    )

    return client_secret


def get_b2b_client_by_service_user(tenant_id: TenantArg, user_id: str) -> dict | None:
    """
    Get B2B OAuth2 client by service user ID.

    Used to check if a user is a service user before deletion.

    Returns:
        Client record or None
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, client_id, client_type, name
        from oauth2_clients
        where service_user_id = :user_id and client_type = 'b2b'
        """,
        {"user_id": user_id},
    )


def update_client(
    tenant_id: TenantArg,
    client_id: str,
    name: str | None = None,
    description: str | None = None,
    redirect_uris: list[str] | None = None,
) -> dict | None:
    """
    Update an OAuth2 client's name, description, and/or redirect URIs.

    Args:
        tenant_id: Tenant ID for scoping
        client_id: Client ID (the TEXT identifier, e.g., "weft-id_client_abc123")
        name: New client name (optional)
        description: New description (optional)
        redirect_uris: New redirect URIs for normal clients (optional)

    Returns:
        Updated client record, or None if not found
    """
    # Build dynamic update query based on provided fields
    updates = []
    params: dict = {"client_id": client_id}

    if name is not None:
        updates.append("name = :name")
        params["name"] = name

    if description is not None:
        updates.append("description = :description")
        params["description"] = description

    if redirect_uris is not None:
        updates.append("redirect_uris = :redirect_uris")
        params["redirect_uris"] = redirect_uris

    if not updates:
        # No fields to update, just return current record
        return get_client_by_client_id(tenant_id, client_id)

    query = f"""
        update oauth2_clients
        set {", ".join(updates)}
        where client_id = :client_id
        returning id, tenant_id, client_id, client_type, name, description,
                  redirect_uris, service_user_id, is_active, created_at
    """

    return fetchone(tenant_id, query, params)


def update_b2b_client_role(tenant_id: TenantArg, client_id: str, role: str) -> dict | None:
    """
    Update the service user role for a B2B OAuth2 client.

    Args:
        tenant_id: Tenant ID for scoping
        client_id: Client ID (the TEXT identifier)
        role: New role ('member', 'admin', 'super_admin')

    Returns:
        Updated client record with service_role, or None if not found
    """
    # First get the client to find the service_user_id
    client = get_client_by_client_id(tenant_id, client_id)
    if not client or client["client_type"] != "b2b" or not client.get("service_user_id"):
        return None

    # Update the service user's role
    execute(
        tenant_id,
        "update users set role = :role where id = :user_id",
        {"role": role, "user_id": client["service_user_id"]},
    )

    # Return updated client with new role
    return fetchone(
        tenant_id,
        """
        select c.id, c.tenant_id, c.client_id, c.client_type, c.name,
               c.description, c.redirect_uris, c.service_user_id,
               c.is_active, c.created_at, u.role as service_role
        from oauth2_clients c
        left join users u on c.service_user_id = u.id
        where c.client_id = :client_id
        """,
        {"client_id": client_id},
    )


def deactivate_client(tenant_id: TenantArg, client_id: str) -> dict | None:
    """
    Deactivate an OAuth2 client (soft delete).

    Args:
        tenant_id: Tenant ID for scoping
        client_id: Client ID (the TEXT identifier)

    Returns:
        Updated client record, or None if not found
    """
    return fetchone(
        tenant_id,
        """
        update oauth2_clients
        set is_active = false
        where client_id = :client_id
        returning id, tenant_id, client_id, client_type, name, description,
                  redirect_uris, service_user_id, is_active, created_at
        """,
        {"client_id": client_id},
    )


def reactivate_client(tenant_id: TenantArg, client_id: str) -> dict | None:
    """
    Reactivate a deactivated OAuth2 client.

    Args:
        tenant_id: Tenant ID for scoping
        client_id: Client ID (the TEXT identifier)

    Returns:
        Updated client record, or None if not found
    """
    return fetchone(
        tenant_id,
        """
        update oauth2_clients
        set is_active = true
        where client_id = :client_id
        returning id, tenant_id, client_id, client_type, name, description,
                  redirect_uris, service_user_id, is_active, created_at
        """,
        {"client_id": client_id},
    )
