"""Seed every kind of identifying per-user row that anonymization erases.

Shared by the database, service and route tests of anonymization, so all
three check the same set of tables.
"""

from __future__ import annotations

from uuid import uuid4

import database

# The tables ``database.users.erase_user_identity_data`` empties for a user.
ERASED_TABLES = (
    "oidc_idp_user_links",
    "user_oidc_idp_attributes",
    "user_idp_attributes",
    "user_attributes",
    "oidc_idp_sessions",
    "webauthn_credentials",
    "sp_nameid_mappings",
)


def seed_identity_data(tenant_id: str, user_id: str, created_by: str) -> None:
    """Give ``user_id`` one or more rows in each of ``ERASED_TABLES``.

    Also sets the password-derived breach-check values on the user record.
    """
    tenant_id = str(tenant_id)
    user_id = str(user_id)
    created_by = str(created_by)

    connection = database.oidc_upstream.create_connection(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        name=f"Erase IdP {uuid4().hex[:6]}",
        provider_type="generic",
        issuer="https://idp.example.com",
        created_by=created_by,
    )
    idp_id = str(connection["id"])
    database.oidc_upstream.create_link(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        idp_id=idp_id,
        sub=f"upstream-{uuid4().hex[:8]}",
        user_id=user_id,
    )
    database.oidc_upstream.replace_idp_attributes(
        tenant_id, tenant_id, user_id, idp_id, {"department": "Cardiology"}
    )
    database.oidc_upstream.record_idp_session(
        tenant_id,
        tenant_id,
        sid=f"sid-{uuid4().hex[:8]}",
        idp_id=idp_id,
        user_id=user_id,
        upstream_sub="upstream-sub",
        upstream_sid=None,
        id_token="header.payload-with-email.signature",
    )

    saml_idp = database.fetchone(
        tenant_id,
        """
        insert into saml_identity_providers (
            tenant_id, name, provider_type, entity_id, sso_url,
            certificate_pem, sp_entity_id, created_by
        ) values (
            :tenant_id, :name, 'generic', :entity_id,
            'https://idp.example.com/sso', 'cert-placeholder',
            'https://sp.example.com', :created_by
        ) returning id
        """,
        {
            "tenant_id": tenant_id,
            "name": f"Erase SAML IdP {uuid4().hex[:6]}",
            "entity_id": f"https://idp-{uuid4().hex[:8]}.example.com",
            "created_by": created_by,
        },
    )
    database.user_idp_attributes.replace_idp_attributes(
        tenant_id, tenant_id, user_id, str(saml_idp["id"]), {"title": "Surgeon"}
    )

    database.user_attributes.upsert_attribute(tenant_id, tenant_id, user_id, "phone", "+1 555 0100")

    database.webauthn_credentials.create_credential(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        user_id=user_id,
        credential_id=uuid4().bytes,
        public_key=b"public-key",
        name="Anna's iPhone",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )

    sp = database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        name=f"Erase SP {uuid4().hex[:6]}",
        created_by=created_by,
    )
    database.sp_nameid_mappings.get_or_create_nameid_mapping(
        tenant_id, tenant_id, user_id, str(sp["id"])
    )

    database.execute(
        tenant_id,
        "update users set hibp_prefix = 'ABCDE', hibp_check_hmac = 'hmac' where id = :id",
        {"id": user_id},
    )


def count_rows(tenant_id: str, user_id: str) -> dict[str, int]:
    """Rows per erased table for the user."""
    counts = {}
    for table in ERASED_TABLES:
        row = database.fetchone(
            str(tenant_id),
            f"select count(*) as n from {table} where user_id = :user_id",
            {"user_id": str(user_id)},
        )
        counts[table] = int(row["n"])
    return counts


def hibp_values(tenant_id: str, user_id: str) -> tuple:
    row = database.fetchone(
        str(tenant_id),
        "select hibp_prefix, hibp_check_hmac from users where id = :id",
        {"id": str(user_id)},
    )
    return (row["hibp_prefix"], row["hibp_check_hmac"])
