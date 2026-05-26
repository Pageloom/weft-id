"""Database integration tests for inbound SCIM write helpers.

Covers:
- `user_idp_attributes.set_external_id` / `get_external_id` /
  `get_user_id_by_external_id` (the upstream-id storage layer).
- The `users.updated_at` column + trigger added in
  `0043_users_updated_at.sql` -- including the trigger firing on
  generic UPDATE statements.
- The externalId filter on `users.scim_reads` now preferring upstream
  externalId over the WeftID-minted id.
"""

from __future__ import annotations

import time
from uuid import uuid4

import database

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_idp(tenant_id, user_id, *, name="Test IdP"):
    return database.saml.create_identity_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        provider_type="generic",
        sp_entity_id=f"urn:test:{uuid4().hex}",
        created_by=str(user_id),
    )


def _create_user(tenant_id, *, email, idp_id):
    user = database.fetchone(
        tenant_id,
        """
        insert into users (tenant_id, first_name, last_name, role, saml_idp_id)
        values (:tenant_id, 'X', 'Y', 'member', :idp_id)
        returning id
        """,
        {"tenant_id": str(tenant_id), "idp_id": idp_id},
    )
    database.execute(
        tenant_id,
        """
        insert into user_emails (tenant_id, user_id, email, is_primary, verified_at)
        values (:tenant_id, :user_id, :email, true, now())
        """,
        {"tenant_id": str(tenant_id), "user_id": user["id"], "email": email},
    )
    return user


# ---------------------------------------------------------------------------
# users.updated_at column + trigger
# ---------------------------------------------------------------------------


def test_users_updated_at_present_after_create(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    u = _create_user(test_tenant["id"], email="u@x.test", idp_id=str(idp["id"]))
    row = database.fetchone(
        test_tenant["id"],
        "select created_at, updated_at from users where id = :id",
        {"id": u["id"]},
    )
    assert row is not None
    assert row["updated_at"] is not None
    assert row["created_at"] is not None


def test_users_updated_at_bumped_by_trigger_on_profile_update(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    u = _create_user(test_tenant["id"], email="u@x.test", idp_id=str(idp["id"]))

    before = database.fetchone(
        test_tenant["id"],
        "select updated_at from users where id = :id",
        {"id": u["id"]},
    )["updated_at"]

    # Tiny pause to ensure now() advances past the trigger's previous tick.
    time.sleep(0.05)
    database.users.update_user_profile(test_tenant["id"], str(u["id"]), "New", "Name")

    after = database.fetchone(
        test_tenant["id"],
        "select updated_at from users where id = :id",
        {"id": u["id"]},
    )["updated_at"]

    assert after > before


# ---------------------------------------------------------------------------
# user_idp_attributes external-id helpers
# ---------------------------------------------------------------------------


def test_set_and_get_external_id_round_trip(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    u = _create_user(test_tenant["id"], email="u@x.test", idp_id=str(idp["id"]))

    database.user_idp_attributes.set_external_id(
        test_tenant["id"], str(test_tenant["id"]), str(u["id"]), str(idp["id"]), "okta-abc"
    )

    fetched = database.user_idp_attributes.get_external_id(
        test_tenant["id"], str(u["id"]), str(idp["id"])
    )
    assert fetched == "okta-abc"


def test_set_external_id_upserts_on_repeat_set(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    u = _create_user(test_tenant["id"], email="u@x.test", idp_id=str(idp["id"]))

    database.user_idp_attributes.set_external_id(
        test_tenant["id"], str(test_tenant["id"]), str(u["id"]), str(idp["id"]), "first"
    )
    database.user_idp_attributes.set_external_id(
        test_tenant["id"], str(test_tenant["id"]), str(u["id"]), str(idp["id"]), "second"
    )
    assert (
        database.user_idp_attributes.get_external_id(
            test_tenant["id"], str(u["id"]), str(idp["id"])
        )
        == "second"
    )


def test_get_user_id_by_external_id_reverse_lookup(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    u = _create_user(test_tenant["id"], email="u@x.test", idp_id=str(idp["id"]))

    database.user_idp_attributes.set_external_id(
        test_tenant["id"], str(test_tenant["id"]), str(u["id"]), str(idp["id"]), "okta-reverse"
    )
    assert database.user_idp_attributes.get_user_id_by_external_id(
        test_tenant["id"], str(idp["id"]), "okta-reverse"
    ) == str(u["id"])


def test_get_user_id_by_external_id_returns_none_for_unknown(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    assert (
        database.user_idp_attributes.get_user_id_by_external_id(
            test_tenant["id"], str(idp["id"]), "no-such-id"
        )
        is None
    )


def test_external_id_isolated_per_idp(test_tenant, test_user):
    """The same upstream id under two different IdPs maps to two different users."""
    idp_a = _create_idp(test_tenant["id"], test_user["id"], name="A")
    idp_b = _create_idp(test_tenant["id"], test_user["id"], name="B")
    u_a = _create_user(test_tenant["id"], email="a@x.test", idp_id=str(idp_a["id"]))
    u_b = _create_user(test_tenant["id"], email="b@x.test", idp_id=str(idp_b["id"]))

    database.user_idp_attributes.set_external_id(
        test_tenant["id"], str(test_tenant["id"]), str(u_a["id"]), str(idp_a["id"]), "shared-id"
    )
    database.user_idp_attributes.set_external_id(
        test_tenant["id"], str(test_tenant["id"]), str(u_b["id"]), str(idp_b["id"]), "shared-id"
    )
    assert database.user_idp_attributes.get_user_id_by_external_id(
        test_tenant["id"], str(idp_a["id"]), "shared-id"
    ) == str(u_a["id"])
    assert database.user_idp_attributes.get_user_id_by_external_id(
        test_tenant["id"], str(idp_b["id"]), "shared-id"
    ) == str(u_b["id"])


# ---------------------------------------------------------------------------
# scim_reads externalId filter -- prefers upstream id, falls back to user id
# ---------------------------------------------------------------------------


def test_list_users_for_idp_external_id_prefers_upstream(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    target = _create_user(test_tenant["id"], email="ext@x.test", idp_id=str(idp["id"]))
    _create_user(test_tenant["id"], email="other@x.test", idp_id=str(idp["id"]))

    database.user_idp_attributes.set_external_id(
        test_tenant["id"], str(test_tenant["id"]), str(target["id"]), str(idp["id"]), "okta-100"
    )

    # Upstream externalId matches.
    rows = database.users.list_users_for_idp(
        test_tenant["id"], str(idp["id"]), external_id="okta-100"
    )
    assert [str(r["id"]) for r in rows] == [str(target["id"])]

    # WeftID id still works as fallback for users without an upstream id.
    rows_by_id = database.users.list_users_for_idp(
        test_tenant["id"], str(idp["id"]), external_id=str(target["id"])
    )
    assert [str(r["id"]) for r in rows_by_id] == [str(target["id"])]


def test_get_user_for_idp_includes_external_id_column(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    u = _create_user(test_tenant["id"], email="u@x.test", idp_id=str(idp["id"]))
    database.user_idp_attributes.set_external_id(
        test_tenant["id"], str(test_tenant["id"]), str(u["id"]), str(idp["id"]), "okta-ext"
    )
    row = database.users.get_user_for_idp(test_tenant["id"], str(idp["id"]), str(u["id"]))
    assert row is not None
    assert row["external_id"] == "okta-ext"
