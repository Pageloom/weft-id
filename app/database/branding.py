"""Tenant branding database operations."""

from ._core import TenantArg, execute, fetchone


def get_branding(tenant_id: TenantArg) -> dict | None:
    """
    Get branding metadata for a tenant (no binary logo data).

    Returns:
        Dict with logo_mode, use_logo_as_favicon, has_logo_light, has_logo_dark,
        logo_light_mime, logo_dark_mime, updated_at. None if no branding row exists.
    """
    return fetchone(
        tenant_id,
        """
        SELECT
            logo_mode,
            use_logo_as_favicon,
            (logo_light IS NOT NULL) AS has_logo_light,
            (logo_dark IS NOT NULL) AS has_logo_dark,
            logo_light_mime,
            logo_dark_mime,
            updated_at
        FROM tenant_branding
        WHERE tenant_id = :tenant_id
        """,
        {"tenant_id": str(tenant_id)},
    )


def get_logo(tenant_id: TenantArg, slot: str) -> dict | None:
    """
    Get logo binary data and MIME type for serving.

    Args:
        tenant_id: Tenant ID for scoping
        slot: 'light' or 'dark'

    Returns:
        Dict with logo_data (bytes), mime_type (str), updated_at.
        None if no branding row or no logo in the requested slot.
    """
    column = "logo_light" if slot == "light" else "logo_dark"
    mime_column = f"{column}_mime"

    return fetchone(
        tenant_id,
        f"""
        SELECT
            {column} AS logo_data,
            {mime_column} AS mime_type,
            updated_at
        FROM tenant_branding
        WHERE tenant_id = :tenant_id
          AND {column} IS NOT NULL
        """,
        {"tenant_id": str(tenant_id)},
    )


def upsert_logo(
    tenant_id: TenantArg,
    tenant_id_value: str,
    slot: str,
    logo_data: bytes,
    mime_type: str,
) -> int:
    """
    Upload or replace a logo for a tenant. Creates the branding row if needed.

    Args:
        tenant_id: Tenant ID for RLS scoping
        tenant_id_value: Tenant ID value to store
        slot: 'light' or 'dark'
        logo_data: Raw image bytes
        mime_type: MIME type string

    Returns:
        Number of rows affected
    """
    column = "logo_light" if slot == "light" else "logo_dark"
    mime_column = f"{column}_mime"

    return execute(
        tenant_id,
        f"""
        INSERT INTO tenant_branding (tenant_id, {column}, {mime_column}, updated_at)
        VALUES (:tenant_id, :logo_data, :mime_type, now())
        ON CONFLICT (tenant_id) DO UPDATE
            SET {column} = :logo_data,
                {mime_column} = :mime_type,
                updated_at = now()
        """,
        {
            "tenant_id": tenant_id_value,
            "logo_data": logo_data,
            "mime_type": mime_type,
        },
    )


def delete_logo(tenant_id: TenantArg, slot: str) -> int:
    """
    Remove a logo by NULLing the column. Does not delete the branding row.

    Args:
        tenant_id: Tenant ID for scoping
        slot: 'light' or 'dark'

    Returns:
        Number of rows affected
    """
    column = "logo_light" if slot == "light" else "logo_dark"
    mime_column = f"{column}_mime"

    return execute(
        tenant_id,
        f"""
        UPDATE tenant_branding
        SET {column} = NULL,
            {mime_column} = NULL,
            updated_at = now()
        WHERE tenant_id = :tenant_id
        """,
        {"tenant_id": str(tenant_id)},
    )


def update_branding_settings(
    tenant_id: TenantArg,
    tenant_id_value: str,
    logo_mode: str,
    use_logo_as_favicon: bool,
) -> int:
    """
    Update branding display settings. Creates the branding row if needed.

    Args:
        tenant_id: Tenant ID for RLS scoping
        tenant_id_value: Tenant ID value to store
        logo_mode: 'mandala' or 'custom'
        use_logo_as_favicon: Whether to use logo as favicon

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        INSERT INTO tenant_branding (tenant_id, logo_mode, use_logo_as_favicon, updated_at)
        VALUES (:tenant_id, :logo_mode, :use_logo_as_favicon, now())
        ON CONFLICT (tenant_id) DO UPDATE
            SET logo_mode = :logo_mode,
                use_logo_as_favicon = :use_logo_as_favicon,
                updated_at = now()
        """,
        {
            "tenant_id": tenant_id_value,
            "logo_mode": logo_mode,
            "use_logo_as_favicon": use_logo_as_favicon,
        },
    )
