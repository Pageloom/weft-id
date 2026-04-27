"""Tests for database.user_attributes."""

from __future__ import annotations

from uuid import uuid4

import database
import pytest


def _create_idp(tenant_id, user_id):
    """Insert a SAML IdP for tests that need source_idp_id."""
    return database.fetchone(
        tenant_id,
        """
        INSERT INTO saml_identity_providers (
            tenant_id, name, provider_type, entity_id, sso_url,
            certificate_pem, sp_entity_id, created_by
        ) VALUES (
            :tenant_id, :name, 'generic', :entity_id,
            'https://idp.example.com/sso', 'cert-placeholder',
            'https://sp.example.com', :created_by
        ) RETURNING id
        """,
        {
            "tenant_id": tenant_id,
            "name": f"Test IdP {uuid4().hex[:6]}",
            "entity_id": f"https://idp-{uuid4().hex[:8]}.example.com",
            "created_by": user_id,
        },
    )


# ---------------------------------------------------------------------------
# Upsert
# ---------------------------------------------------------------------------


def test_upsert_admin_inserts_new_row(test_user):
    row = database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Engineer",
        source="admin",
        source_idp_id=None,
    )
    assert row["attribute_key"] == "job_title"
    assert row["value"] == "Engineer"
    assert row["source"] == "admin"
    assert row["source_idp_id"] is None


def test_upsert_overwrites_existing_row(test_user):
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Junior Engineer",
        source="admin",
        source_idp_id=None,
    )
    updated = database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Senior Engineer",
        source="self",
        source_idp_id=None,
    )
    assert updated["value"] == "Senior Engineer"
    assert updated["source"] == "self"

    # And only one row exists
    rows = database.user_attributes.list_attributes(test_user["tenant_id"], test_user["id"])
    assert len([r for r in rows if r["attribute_key"] == "job_title"]) == 1


def test_upsert_with_idp_source_requires_idp_id(test_user):
    # source='idp' with no source_idp_id violates the CHECK constraint
    with pytest.raises(Exception):
        database.user_attributes.upsert_attribute(
            tenant_id=test_user["tenant_id"],
            tenant_id_value=str(test_user["tenant_id"]),
            user_id=test_user["id"],
            attribute_key="job_title",
            value="Engineer",
            source="idp",
            source_idp_id=None,
        )


def test_upsert_admin_with_idp_id_violates_check(test_user):
    idp = _create_idp(test_user["tenant_id"], test_user["id"])
    # source='admin' with a source_idp_id violates the CHECK
    with pytest.raises(Exception):
        database.user_attributes.upsert_attribute(
            tenant_id=test_user["tenant_id"],
            tenant_id_value=str(test_user["tenant_id"]),
            user_id=test_user["id"],
            attribute_key="job_title",
            value="Engineer",
            source="admin",
            source_idp_id=str(idp["id"]),
        )


def test_upsert_idp_source_with_idp_id_succeeds(test_user):
    idp = _create_idp(test_user["tenant_id"], test_user["id"])
    row = database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="department",
        value="Platform",
        source="idp",
        source_idp_id=str(idp["id"]),
    )
    assert row["source"] == "idp"
    assert str(row["source_idp_id"]) == str(idp["id"])


def test_upsert_rejects_unknown_source(test_user):
    with pytest.raises(Exception):
        database.user_attributes.upsert_attribute(
            tenant_id=test_user["tenant_id"],
            tenant_id_value=str(test_user["tenant_id"]),
            user_id=test_user["id"],
            attribute_key="job_title",
            value="Engineer",
            source="bogus",
            source_idp_id=None,
        )


# ---------------------------------------------------------------------------
# Read / list / delete
# ---------------------------------------------------------------------------


def test_get_returns_none_when_missing(test_user):
    assert (
        database.user_attributes.get_attribute(test_user["tenant_id"], test_user["id"], "job_title")
        is None
    )


def test_list_orders_by_attribute_key(test_user):
    for key, value in [
        ("job_title", "Eng"),
        ("city", "NYC"),
        ("country", "US"),
    ]:
        database.user_attributes.upsert_attribute(
            tenant_id=test_user["tenant_id"],
            tenant_id_value=str(test_user["tenant_id"]),
            user_id=test_user["id"],
            attribute_key=key,
            value=value,
            source="admin",
            source_idp_id=None,
        )
    rows = database.user_attributes.list_attributes(test_user["tenant_id"], test_user["id"])
    keys = [r["attribute_key"] for r in rows]
    assert keys == sorted(keys)


def test_delete_returns_one_on_hit(test_user):
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Eng",
        source="admin",
        source_idp_id=None,
    )
    rows_affected = database.user_attributes.delete_attribute(
        test_user["tenant_id"], test_user["id"], "job_title"
    )
    assert rows_affected == 1
    assert (
        database.user_attributes.get_attribute(test_user["tenant_id"], test_user["id"], "job_title")
        is None
    )


def test_delete_returns_zero_on_miss(test_user):
    rows_affected = database.user_attributes.delete_attribute(
        test_user["tenant_id"], test_user["id"], "job_title"
    )
    assert rows_affected == 0


# ---------------------------------------------------------------------------
# Tenant isolation and cascade
# ---------------------------------------------------------------------------


def test_tenant_isolation(test_user):
    """Attributes in tenant A must not be visible from tenant B."""
    other_subdomain = f"isolated-{uuid4().hex[:8]}"
    database.execute(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n)",
        {"s": other_subdomain, "n": "Isolated"},
    )
    other = database.fetchone(
        database.UNSCOPED,
        "SELECT id FROM tenants WHERE subdomain = :s",
        {"s": other_subdomain},
    )
    assert other is not None
    try:
        database.user_attributes.upsert_attribute(
            tenant_id=test_user["tenant_id"],
            tenant_id_value=str(test_user["tenant_id"]),
            user_id=test_user["id"],
            attribute_key="job_title",
            value="Engineer",
            source="admin",
            source_idp_id=None,
        )
        rows = database.user_attributes.list_attributes(other["id"], test_user["id"])
        assert rows == []
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": other["id"]},
        )


def test_cascade_delete_on_user(test_user):
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Engineer",
        source="admin",
        source_idp_id=None,
    )
    database.execute(
        test_user["tenant_id"],
        "DELETE FROM users WHERE id = :id",
        {"id": test_user["id"]},
    )
    rows = database.user_attributes.list_attributes(test_user["tenant_id"], test_user["id"])
    assert rows == []


def test_unique_user_attribute_key(test_user):
    """Two rows with the same (user_id, attribute_key) are rejected."""
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Eng",
        source="admin",
        source_idp_id=None,
    )
    # Direct INSERT (bypassing upsert) must violate the unique constraint
    with pytest.raises(Exception):
        database.execute(
            test_user["tenant_id"],
            """
            INSERT INTO user_attributes (
                tenant_id, user_id, attribute_key, value, source
            ) VALUES (
                :tenant_id, :user_id, 'job_title', 'Other', 'admin'
            )
            """,
            {
                "tenant_id": str(test_user["tenant_id"]),
                "user_id": test_user["id"],
            },
        )


def test_force_profile_completion_default(test_user):
    """The new users.force_profile_completion column defaults to false."""
    row = database.fetchone(
        test_user["tenant_id"],
        "SELECT force_profile_completion FROM users WHERE id = :id",
        {"id": test_user["id"]},
    )
    assert row is not None
    assert row["force_profile_completion"] is False


def test_idp_delete_cascades_to_user_attributes(test_user):
    """Deleting a SAML IdP removes IdP-sourced attribute rows.

    The CHECK constraint requires source='idp' rows to have a non-null
    source_idp_id, so the FK must use ON DELETE CASCADE (not SET NULL).
    """
    idp = _create_idp(test_user["tenant_id"], test_user["id"])
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="department",
        value="Platform",
        source="idp",
        source_idp_id=str(idp["id"]),
    )
    database.execute(
        test_user["tenant_id"],
        "DELETE FROM saml_identity_providers WHERE id = :id",
        {"id": idp["id"]},
    )
    rows = database.user_attributes.list_attributes(test_user["tenant_id"], test_user["id"])
    assert rows == []


# Note on tenant-delete cascade for user_attributes:
# The chain is tenants -> users -> user_attributes via composite FKs with
# ON DELETE CASCADE. The user-level cascade is verified by
# test_cascade_delete_on_user above. The tenant-level cascade through users
# is well-established by the existing tenants/users/users-fkey schema. Adding
# a direct tenant-delete-then-count check here is not feasible under appuser
# because RLS USING current_setting('app.tenant_id')::uuid blocks UNSCOPED
# reads. The transitive guarantee is sufficient.


def test_cross_tenant_upsert_rejected_by_rls(test_user):
    """An upsert that targets another tenant's tenant_id must be rejected."""
    other_subdomain = f"foreign-{uuid4().hex[:8]}"
    database.execute(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n)",
        {"s": other_subdomain, "n": "Foreign"},
    )
    other = database.fetchone(
        database.UNSCOPED,
        "SELECT id FROM tenants WHERE subdomain = :s",
        {"s": other_subdomain},
    )
    assert other is not None
    try:
        # Session is scoped to test_user's tenant. Attempting to insert with
        # tenant_id = other['id'] must trigger RLS WITH CHECK.
        with pytest.raises(Exception):
            database.execute(
                test_user["tenant_id"],
                """
                INSERT INTO user_attributes (
                    tenant_id, user_id, attribute_key, value, source
                ) VALUES (
                    :tenant_id, :user_id, 'job_title', 'Engineer', 'admin'
                )
                """,
                {
                    "tenant_id": str(other["id"]),
                    "user_id": test_user["id"],
                },
            )
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": other["id"]},
        )
