"""Batch database queries for user audit export.

All queries are set-based (no N+1) and designed for the
multi-sheet XLSX export job handler.
"""

from database._core import TenantArg, fetchall


def get_all_users_for_audit(tenant_id: TenantArg) -> list[dict]:
    """Get all users with full metadata for the Users sheet.

    Includes active, inactive, and anonymized users.
    Excludes service accounts (OAuth2 clients).
    """
    return fetchall(
        tenant_id,
        """
        select u.id, u.first_name, u.last_name, u.role,
               u.created_at, u.last_login, u.is_inactivated, u.is_anonymized,
               u.password_hash is not null as has_password,
               u.mfa_enabled, u.password_changed_at,
               u.saml_idp_id,
               ue.email as primary_email,
               idp.name as saml_idp_name,
               ua.last_activity_at
        from users u
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        left join saml_identity_providers idp on u.saml_idp_id = idp.id
        left join user_activity ua on u.id = ua.user_id
        where not exists (
            select 1 from oauth2_clients oc where oc.service_user_id = u.id
        )
        order by u.last_name asc, u.first_name asc
        """,
        {},
    )


def get_all_secondary_emails(tenant_id: TenantArg) -> list[dict]:
    """Get all non-primary emails for building the secondary_emails column."""
    return fetchall(
        tenant_id,
        """
        select ue.user_id, ue.email
        from user_emails ue
        join users u on ue.user_id = u.id
        where ue.is_primary = false
          and not exists (
              select 1 from oauth2_clients oc where oc.service_user_id = u.id
          )
        order by ue.user_id, ue.email
        """,
        {},
    )


def get_creation_methods(tenant_id: TenantArg) -> list[dict]:
    """Get the creation event type for each user from the event log.

    Returns the first user_created or user_created_jit event per user.
    Users with no creation event (e.g. CLI-provisioned) will be absent.
    """
    return fetchall(
        tenant_id,
        """
        select distinct on (e.artifact_id)
               e.artifact_id as user_id, e.event_type
        from event_logs e
        where e.event_type in ('user_created', 'user_created_jit')
          and e.artifact_type = 'user'
        order by e.artifact_id, e.created_at asc
        """,
        {},
    )


def get_last_login_ips(tenant_id: TenantArg) -> list[dict]:
    """Get the most recent login IP for each user from event log metadata."""
    return fetchall(
        tenant_id,
        """
        select distinct on (e.actor_user_id)
               e.actor_user_id as user_id,
               m.metadata
        from event_logs e
        left join event_log_metadata m on e.metadata_hash = m.metadata_hash
        where e.event_type in ('user_signed_in', 'user_signed_in_saml')
        order by e.actor_user_id, e.created_at desc
        """,
        {},
    )


def get_app_counts(tenant_id: TenantArg) -> list[dict]:
    """Get the number of accessible SPs per user via group membership.

    Does not include available_to_all SPs (added in Python).
    """
    return fetchall(
        tenant_id,
        """
        select gm.user_id, count(distinct sga.sp_id) as app_count
        from group_memberships gm
        join group_lineage gl on gl.descendant_id = gm.group_id
        join sp_group_assignments sga on sga.group_id = gl.ancestor_id
        join service_providers sp on sp.id = sga.sp_id
        where sp.enabled = true
          and sp.trust_established = true
        group by gm.user_id
        """,
        {},
    )


def get_available_to_all_sp_count(tenant_id: TenantArg) -> int:
    """Count SPs that are available to all users."""
    from database._core import fetchone

    row = fetchone(
        tenant_id,
        """
        select count(*) as cnt
        from service_providers
        where available_to_all = true
          and enabled = true
          and trust_established = true
        """,
        {},
    )
    return row["cnt"] if row else 0


def get_all_group_memberships(tenant_id: TenantArg) -> list[dict]:
    """Get all user-group memberships for the Group Memberships sheet."""
    return fetchall(
        tenant_id,
        """
        select gm.user_id, ue.email, g.name as group_name,
               g.group_type, gm.created_at as membership_since
        from group_memberships gm
        join groups g on gm.group_id = g.id
        join users u on gm.user_id = u.id
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        where not exists (
            select 1 from oauth2_clients oc where oc.service_user_id = u.id
        )
        order by ue.email, g.name
        """,
        {},
    )


def get_all_user_sp_access(tenant_id: TenantArg) -> list[dict]:
    """Get all user-SP access pairs with group attribution for the App Access sheet.

    Returns one row per user-SP-group combination for group-based access,
    plus one row per user-SP for available_to_all SPs.
    """
    return fetchall(
        tenant_id,
        """
        select gm.user_id, ue.email, sp.id as sp_id, sp.name as app_name,
               false as available_to_all,
               g.name as granting_group_name
        from service_providers sp
        join sp_group_assignments sga on sga.sp_id = sp.id
        join group_lineage gl on gl.ancestor_id = sga.group_id
        join group_memberships gm on gm.group_id = gl.descendant_id
        join users u on gm.user_id = u.id
        join groups g on g.id = sga.group_id
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        where sp.enabled = true and sp.trust_established = true
          and not exists (
              select 1 from oauth2_clients oc where oc.service_user_id = u.id
          )

        union all

        select u.id as user_id, ue.email, sp.id as sp_id, sp.name as app_name,
               true as available_to_all,
               null as granting_group_name
        from service_providers sp
        cross join users u
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        where sp.available_to_all = true and sp.enabled = true
          and sp.trust_established = true
          and not exists (
              select 1 from oauth2_clients oc where oc.service_user_id = u.id
          )

        order by email, app_name, granting_group_name
        """,
        {},
    )


def get_last_sso_assertions(tenant_id: TenantArg) -> list[dict]:
    """Get the most recent SSO assertion timestamp per user+SP pair."""
    return fetchall(
        tenant_id,
        """
        select distinct on (e.actor_user_id, e.artifact_id)
               e.actor_user_id as user_id,
               e.artifact_id as sp_id,
               e.created_at as last_auth_at
        from event_logs e
        where e.event_type = 'sso_assertion_issued'
          and e.artifact_type = 'service_provider'
        order by e.actor_user_id, e.artifact_id, e.created_at desc
        """,
        {},
    )
