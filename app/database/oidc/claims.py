"""Read queries backing OIDC scope-gated claim assembly.

Pulls the identity attributes released as OIDC claims (profile + email this
iteration) for a single user, tenant-scoped via RLS. Kept separate from the
signing-key queries so the OIDC database package mirrors the service package
layout (keys vs claims vs tokens).
"""

from database._core import TenantArg, fetchone


def get_user_claim_data(tenant_id: TenantArg, user_id: str) -> dict | None:
    """Return the identity attributes used to build OIDC claims for a user.

    Joins the user's primary verified email so the `email`/`email_verified`
    claims can be released. Returns None if the user does not exist in scope.

    Returns:
        Dict with id, first_name, last_name, locale, primary_email,
        email_verified, updated_at, or None.
    """
    return fetchone(
        tenant_id,
        """
        select u.id,
               u.first_name,
               u.last_name,
               u.locale,
               u.updated_at,
               ue.email as primary_email,
               (ue.verified_at is not null) as email_verified
        from users u
        left join user_emails ue on ue.user_id = u.id and ue.is_primary = true
        where u.id = :user_id
        """,
        {"user_id": user_id},
    )
