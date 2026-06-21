"""Tests for database.user_idp_attributes."""

from __future__ import annotations

from uuid import uuid4

import database


def _create_idp(tenant_id, user_id):
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
# replace_idp_attributes
# ---------------------------------------------------------------------------


def test_replace_inserts_new_rows(test_user):
    idp = _create_idp(test_user["tenant_id"], test_user["id"])
    database.user_idp_attributes.replace_idp_attributes(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        idp_id=str(idp["id"]),
        attributes={"job_title": "Engineer", "department": "Platform"},
    )
    rows = database.user_idp_attributes.list_attributes_for_idp(
        test_user["tenant_id"], test_user["id"], str(idp["id"])
    )
    by_key = {r["attribute_key"]: r["value"] for r in rows}
    assert by_key == {"job_title": "Engineer", "department": "Platform"}


def test_replace_updates_existing_keys(test_user):
    idp = _create_idp(test_user["tenant_id"], test_user["id"])
    database.user_idp_attributes.replace_idp_attributes(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        idp_id=str(idp["id"]),
        attributes={"job_title": "Engineer"},
    )
    database.user_idp_attributes.replace_idp_attributes(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        idp_id=str(idp["id"]),
        attributes={"job_title": "Senior Engineer"},
    )
    rows = database.user_idp_attributes.list_attributes_for_idp(
        test_user["tenant_id"], test_user["id"], str(idp["id"])
    )
    assert len(rows) == 1
    assert rows[0]["value"] == "Senior Engineer"


def test_replace_deletes_keys_absent_from_new_set(test_user):
    """An attribute the IdP previously sent but no longer carries is dropped."""
    idp = _create_idp(test_user["tenant_id"], test_user["id"])
    database.user_idp_attributes.replace_idp_attributes(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        idp_id=str(idp["id"]),
        attributes={"job_title": "Engineer", "department": "Platform"},
    )
    database.user_idp_attributes.replace_idp_attributes(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        idp_id=str(idp["id"]),
        attributes={"job_title": "Engineer"},
    )
    rows = database.user_idp_attributes.list_attributes_for_idp(
        test_user["tenant_id"], test_user["id"], str(idp["id"])
    )
    keys = {r["attribute_key"] for r in rows}
    assert keys == {"job_title"}


def test_replace_with_empty_dict_clears_snapshot(test_user):
    idp = _create_idp(test_user["tenant_id"], test_user["id"])
    database.user_idp_attributes.replace_idp_attributes(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        idp_id=str(idp["id"]),
        attributes={"job_title": "Engineer"},
    )
    database.user_idp_attributes.replace_idp_attributes(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        idp_id=str(idp["id"]),
        attributes={},
    )
    rows = database.user_idp_attributes.list_attributes_for_idp(
        test_user["tenant_id"], test_user["id"], str(idp["id"])
    )
    assert rows == []


def test_replace_isolated_per_idp(test_user):
    """Replacing IdP A's snapshot must leave IdP B's rows untouched."""
    idp_a = _create_idp(test_user["tenant_id"], test_user["id"])
    idp_b = _create_idp(test_user["tenant_id"], test_user["id"])

    database.user_idp_attributes.replace_idp_attributes(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        idp_id=str(idp_a["id"]),
        attributes={"job_title": "Eng A"},
    )
    database.user_idp_attributes.replace_idp_attributes(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        idp_id=str(idp_b["id"]),
        attributes={"job_title": "Eng B"},
    )
    # Replace A's snapshot with empty -- B's rows should remain.
    database.user_idp_attributes.replace_idp_attributes(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        idp_id=str(idp_a["id"]),
        attributes={},
    )
    a_rows = database.user_idp_attributes.list_attributes_for_idp(
        test_user["tenant_id"], test_user["id"], str(idp_a["id"])
    )
    b_rows = database.user_idp_attributes.list_attributes_for_idp(
        test_user["tenant_id"], test_user["id"], str(idp_b["id"])
    )
    assert a_rows == []
    assert len(b_rows) == 1
    assert b_rows[0]["value"] == "Eng B"


# ---------------------------------------------------------------------------
# CASCADE
# ---------------------------------------------------------------------------


def test_cascade_on_idp_delete(test_user):
    idp = _create_idp(test_user["tenant_id"], test_user["id"])
    database.user_idp_attributes.replace_idp_attributes(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        idp_id=str(idp["id"]),
        attributes={"job_title": "Engineer"},
    )
    database.execute(
        test_user["tenant_id"],
        "DELETE FROM saml_identity_providers WHERE id = :id",
        {"id": idp["id"]},
    )
    rows = database.user_idp_attributes.list_attributes(test_user["tenant_id"], test_user["id"])
    assert rows == []


def test_cascade_on_user_delete(test_user):
    """Deleting a user removes their IdP-mirror rows.

    Uses a separate user so the IdP's ``created_by`` doesn't pin the
    user to a SET NULL (which would fail because tenant_id is NOT NULL).
    """
    idp = _create_idp(test_user["tenant_id"], test_user["id"])
    from tests.conftest import TEST_PASSWORD_HASH

    second_user = database.fetchone(
        test_user["tenant_id"],
        """
        INSERT INTO users (
            tenant_id, password_hash, first_name, last_name, role
        ) VALUES (
            :tenant_id, :pw, 'Other', 'User', 'member'
        ) RETURNING id
        """,
        {"tenant_id": str(test_user["tenant_id"]), "pw": TEST_PASSWORD_HASH},
    )
    database.user_idp_attributes.replace_idp_attributes(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=str(second_user["id"]),
        idp_id=str(idp["id"]),
        attributes={"job_title": "Engineer"},
    )
    database.execute(
        test_user["tenant_id"],
        "DELETE FROM users WHERE id = :id",
        {"id": second_user["id"]},
    )
    rows = database.user_idp_attributes.list_attributes_for_idp(
        test_user["tenant_id"], str(second_user["id"]), str(idp["id"])
    )
    assert rows == []


def test_delete_for_user_removes_all_idps(test_user):
    idp_a = _create_idp(test_user["tenant_id"], test_user["id"])
    idp_b = _create_idp(test_user["tenant_id"], test_user["id"])
    for idp in (idp_a, idp_b):
        database.user_idp_attributes.replace_idp_attributes(
            tenant_id=test_user["tenant_id"],
            tenant_id_value=str(test_user["tenant_id"]),
            user_id=test_user["id"],
            idp_id=str(idp["id"]),
            attributes={"job_title": "Engineer"},
        )
    rows_affected = database.user_idp_attributes.delete_for_user(
        test_user["tenant_id"], test_user["id"]
    )
    assert rows_affected == 2
    assert (
        database.user_idp_attributes.list_attributes(test_user["tenant_id"], test_user["id"]) == []
    )


def test_delete_for_user_idp_removes_only_that_idp(test_user):
    """delete_for_user_idp clears one IdP's snapshot, leaving others intact."""
    idp_a = _create_idp(test_user["tenant_id"], test_user["id"])
    idp_b = _create_idp(test_user["tenant_id"], test_user["id"])
    for idp in (idp_a, idp_b):
        database.user_idp_attributes.replace_idp_attributes(
            tenant_id=test_user["tenant_id"],
            tenant_id_value=str(test_user["tenant_id"]),
            user_id=test_user["id"],
            idp_id=str(idp["id"]),
            attributes={"job_title": "Engineer"},
        )
    rows_affected = database.user_idp_attributes.delete_for_user_idp(
        test_user["tenant_id"], test_user["id"], str(idp_a["id"])
    )
    assert rows_affected == 1
    a_rows = database.user_idp_attributes.list_attributes_for_idp(
        test_user["tenant_id"], test_user["id"], str(idp_a["id"])
    )
    b_rows = database.user_idp_attributes.list_attributes_for_idp(
        test_user["tenant_id"], test_user["id"], str(idp_b["id"])
    )
    assert a_rows == []
    assert len(b_rows) == 1


def test_cross_tenant_insert_rejected_by_rls(test_user):
    """A direct INSERT targeting another tenant's tenant_id must be rejected."""
    import pytest

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
    idp = _create_idp(test_user["tenant_id"], test_user["id"])
    try:
        with pytest.raises(Exception):
            database.execute(
                test_user["tenant_id"],
                """
                INSERT INTO user_idp_attributes (
                    tenant_id, user_id, idp_id, attribute_key, value
                ) VALUES (
                    :tenant_id, :user_id, :idp_id, 'job_title', 'Engineer'
                )
                """,
                {
                    "tenant_id": str(other["id"]),
                    "user_id": str(test_user["id"]),
                    "idp_id": str(idp["id"]),
                },
            )
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": other["id"]},
        )
