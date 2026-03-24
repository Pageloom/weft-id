"""Tenant branding database operations."""

from ._core import TenantArg, execute, fetchone


def get_branding(tenant_id: TenantArg) -> dict | None:
    """
    Get branding metadata for a tenant (no binary logo data).

    Returns:
        Dict with logo_mode, use_logo_as_favicon, has_logo_light, has_logo_dark,
        logo_light_mime, logo_dark_mime, group_avatar_style, updated_at.
        None if no branding row exists.
    """
    return fetchone(
        tenant_id,
        """
        SELECT
            tb.logo_mode,
            tb.use_logo_as_favicon,
            tb.show_title_in_nav,
            (tb.logo_light IS NOT NULL) AS has_logo_light,
            (tb.logo_dark IS NOT NULL) AS has_logo_dark,
            tb.logo_light_mime,
            tb.logo_dark_mime,
            tb.group_avatar_style,
            tb.updated_at,
            t.name AS tenant_name
        FROM tenant_branding tb
        JOIN tenants t ON t.id = tb.tenant_id
        WHERE tb.tenant_id = :tenant_id
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
    show_title_in_nav: bool = True,
    group_avatar_style: str = "acronym",
) -> int:
    """
    Update branding display settings. Creates the branding row if needed.

    Args:
        tenant_id: Tenant ID for RLS scoping
        tenant_id_value: Tenant ID value to store
        logo_mode: 'mandala' or 'custom'
        use_logo_as_favicon: Whether to use logo as favicon
        show_title_in_nav: Whether to show title in nav bar
        group_avatar_style: 'acronym'

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        INSERT INTO tenant_branding (
            tenant_id, logo_mode, use_logo_as_favicon,
            show_title_in_nav, group_avatar_style, updated_at
        )
        VALUES (
            :tenant_id, :logo_mode, :use_logo_as_favicon,
            :show_title_in_nav, :group_avatar_style, now()
        )
        ON CONFLICT (tenant_id) DO UPDATE
            SET logo_mode = :logo_mode,
                use_logo_as_favicon = :use_logo_as_favicon,
                show_title_in_nav = :show_title_in_nav,
                group_avatar_style = :group_avatar_style,
                updated_at = now()
        """,
        {
            "tenant_id": tenant_id_value,
            "logo_mode": logo_mode,
            "use_logo_as_favicon": use_logo_as_favicon,
            "show_title_in_nav": show_title_in_nav,
            "group_avatar_style": group_avatar_style,
        },
    )


def get_email_branding(tenant_id: TenantArg) -> dict | None:
    """Get tenant name and pre-rasterized email logo PNG.

    Returns:
        Dict with tenant_name, logo_email_png (bytes or None).
        None if no branding row exists.
    """
    return fetchone(
        tenant_id,
        """
        SELECT
            t.name AS tenant_name,
            tb.logo_email_png
        FROM tenant_branding tb
        JOIN tenants t ON t.id = tb.tenant_id
        WHERE tb.tenant_id = :tenant_id
        """,
        {"tenant_id": str(tenant_id)},
    )


def upsert_email_logo_png(
    tenant_id: TenantArg,
    tenant_id_value: str,
    png_data: bytes,
) -> int:
    """Store a pre-rasterized PNG for email embedding.

    Creates the branding row if needed.

    Returns:
        Number of rows affected.
    """
    return execute(
        tenant_id,
        """
        INSERT INTO tenant_branding (tenant_id, logo_email_png, updated_at)
        VALUES (:tenant_id, :png_data, now())
        ON CONFLICT (tenant_id) DO UPDATE
            SET logo_email_png = :png_data,
                updated_at = now()
        """,
        {"tenant_id": tenant_id_value, "png_data": png_data},
    )


def get_group_logo(tenant_id: TenantArg, group_id: str) -> dict | None:
    """Get group logo binary data and metadata.

    Returns:
        Dict with logo_data (bytes), logo_mime (str), updated_at.
        None if no logo exists for this group.
    """
    return fetchone(
        tenant_id,
        """
        SELECT logo_data, logo_mime, updated_at
        FROM group_logos
        WHERE group_id = :group_id
        """,
        {"group_id": group_id},
    )


def upsert_group_logo(
    tenant_id: TenantArg,
    group_id: str,
    logo_data: bytes,
    mime_type: str,
) -> None:
    """Upload or replace a custom logo for a group."""
    execute(
        tenant_id,
        """
        INSERT INTO group_logos (group_id, tenant_id, logo_data, logo_mime, updated_at)
        VALUES (:group_id, :tenant_id, :logo_data, :logo_mime, now())
        ON CONFLICT (group_id) DO UPDATE
            SET logo_data = :logo_data,
                logo_mime = :logo_mime,
                updated_at = now()
        """,
        {
            "group_id": group_id,
            "tenant_id": str(tenant_id),
            "logo_data": logo_data,
            "logo_mime": mime_type,
        },
    )


def delete_group_logo(tenant_id: TenantArg, group_id: str) -> int:
    """Remove a custom logo for a group.

    Returns:
        Number of rows deleted (0 if no logo existed).
    """
    return execute(
        tenant_id,
        "DELETE FROM group_logos WHERE group_id = :group_id",
        {"group_id": group_id},
    )


# =============================================================================
# SP Logo Operations
# =============================================================================


def get_sp_logo(tenant_id: TenantArg, sp_id: str) -> dict | None:
    """Get SP logo binary data and metadata.

    Returns:
        Dict with logo_data (bytes), logo_mime (str), updated_at.
        None if no logo exists for this SP.
    """
    return fetchone(
        tenant_id,
        """
        SELECT logo_data, logo_mime, updated_at
        FROM sp_logos
        WHERE sp_id = :sp_id
        """,
        {"sp_id": sp_id},
    )


def upsert_sp_logo(
    tenant_id: TenantArg,
    sp_id: str,
    logo_data: bytes,
    mime_type: str,
) -> None:
    """Upload or replace a custom logo for a service provider."""
    execute(
        tenant_id,
        """
        INSERT INTO sp_logos (sp_id, tenant_id, logo_data, logo_mime, updated_at)
        VALUES (:sp_id, :tenant_id, :logo_data, :logo_mime, now())
        ON CONFLICT (sp_id) DO UPDATE
            SET logo_data = :logo_data,
                logo_mime = :logo_mime,
                updated_at = now()
        """,
        {
            "sp_id": sp_id,
            "tenant_id": str(tenant_id),
            "logo_data": logo_data,
            "logo_mime": mime_type,
        },
    )


def delete_sp_logo(tenant_id: TenantArg, sp_id: str) -> int:
    """Remove a custom logo for a service provider.

    Returns:
        Number of rows deleted (0 if no logo existed).
    """
    return execute(
        tenant_id,
        "DELETE FROM sp_logos WHERE sp_id = :sp_id",
        {"sp_id": sp_id},
    )
