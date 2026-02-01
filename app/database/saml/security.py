"""SAML security check database operations."""

from database._core import TenantArg, fetchone


def count_users_with_idp(tenant_id: TenantArg, idp_id: str) -> int:
    """
    Count users explicitly assigned to an IdP.

    Used to check if an IdP can be safely deleted.

    Returns:
        Number of users with saml_idp_id = idp_id
    """
    result = fetchone(
        tenant_id,
        """
        select count(*) as count
        from users
        where saml_idp_id = :idp_id
        """,
        {"idp_id": idp_id},
    )
    return result["count"] if result else 0


def count_domain_bindings_for_idp(tenant_id: TenantArg, idp_id: str) -> int:
    """
    Count domains bound to an IdP.

    Used to check if an IdP can be safely deleted.

    Returns:
        Number of domains bound to this IdP
    """
    result = fetchone(
        tenant_id,
        """
        select count(*) as count
        from saml_idp_domain_bindings
        where idp_id = :idp_id
        """,
        {"idp_id": idp_id},
    )
    return result["count"] if result else 0


def count_users_without_idp_in_domain(tenant_id: TenantArg, domain: str) -> int:
    """
    Count users with emails in the domain who don't have an IdP assigned.

    These are password users in the domain who would be affected by
    a domain binding.

    Args:
        tenant_id: Tenant ID for scoping
        domain: Email domain to check (without @)

    Returns:
        Number of users without IdP assignment
    """
    # Build the pattern in Python to avoid SQL placeholder issues with %
    pattern = f"%@{domain.lower()}"
    result = fetchone(
        tenant_id,
        """
        select count(distinct u.id) as count
        from users u
        join user_emails ue on u.id = ue.user_id
        where ue.email like :pattern
          and ue.verified_at is not null
          and u.saml_idp_id is null
        """,
        {"pattern": pattern},
    )
    return result["count"] if result else 0


def count_users_with_idp_in_domain(
    tenant_id: TenantArg,
    domain: str,
    idp_id: str,
) -> int:
    """
    Count users with emails in the domain who are assigned to a specific IdP.

    Used when rebinding a domain to show how many users will be moved.

    Args:
        tenant_id: Tenant ID for scoping
        domain: Email domain to check (without @)
        idp_id: IdP UUID to count users for

    Returns:
        Number of users assigned to the IdP with emails in this domain
    """
    # Build the pattern in Python to avoid SQL placeholder issues with %
    pattern = f"%@{domain.lower()}"
    result = fetchone(
        tenant_id,
        """
        select count(distinct u.id) as count
        from users u
        join user_emails ue on u.id = ue.user_id
        where ue.email like :pattern
          and ue.verified_at is not null
          and u.saml_idp_id = :idp_id
        """,
        {"pattern": pattern, "idp_id": idp_id},
    )
    return result["count"] if result else 0
