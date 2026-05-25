"""Tests for `database.scim_inbound_tokens` module."""

from uuid import uuid4

import database


def _create_idp(tenant_id, user_id, *, name="Test IdP"):
    return database.saml.create_identity_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        provider_type="generic",
        sp_entity_id=f"urn:test:{uuid4().hex}",
        created_by=str(user_id),
    )


def _create_token(tenant_id, user_id, idp, *, token_hash=None, name=None):
    if token_hash is None:
        # Hashes must be 64 hex chars per the CHECK constraint.
        token_hash = uuid4().hex + uuid4().hex
    return database.scim_inbound_tokens.create_token(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        idp_id=str(idp["id"]),
        token_hash=token_hash,
        name=name,
        created_by_user_id=str(user_id),
    )


# -- create_token -------------------------------------------------------------


def test_create_token_returns_row(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])

    row = _create_token(test_tenant["id"], test_user["id"], idp, name="Okta production")

    assert row["id"] is not None
    assert str(row["idp_id"]) == str(idp["id"])
    assert str(row["created_by_user_id"]) == str(test_user["id"])
    assert row["name"] == "Okta production"
    assert row["created_at"] is not None
    assert row["revoked_at"] is None
    assert row["last_used_at"] is None


def test_create_token_allows_null_name(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    row = _create_token(test_tenant["id"], test_user["id"], idp, name=None)
    assert row["name"] is None


# -- list_tokens / list_active_tokens -----------------------------------------


def test_list_tokens_includes_active_and_revoked(test_tenant, test_user):
    """Admin UI needs both for the revocation history view."""
    idp = _create_idp(test_tenant["id"], test_user["id"])
    active = _create_token(test_tenant["id"], test_user["id"], idp)
    revoked = _create_token(test_tenant["id"], test_user["id"], idp)
    database.scim_inbound_tokens.revoke(test_tenant["id"], str(revoked["id"]))

    rows = database.scim_inbound_tokens.list_tokens(test_tenant["id"], str(idp["id"]))
    ids = {str(r["id"]) for r in rows}
    assert ids == {str(active["id"]), str(revoked["id"])}


def test_list_active_tokens_excludes_revoked(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    active = _create_token(test_tenant["id"], test_user["id"], idp)
    revoked = _create_token(test_tenant["id"], test_user["id"], idp)
    database.scim_inbound_tokens.revoke(test_tenant["id"], str(revoked["id"]))

    rows = database.scim_inbound_tokens.list_active_tokens(test_tenant["id"], str(idp["id"]))
    assert [str(r["id"]) for r in rows] == [str(active["id"])]


def test_list_tokens_orders_newest_first(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    first = _create_token(test_tenant["id"], test_user["id"], idp)
    second = _create_token(test_tenant["id"], test_user["id"], idp)

    rows = database.scim_inbound_tokens.list_tokens(test_tenant["id"], str(idp["id"]))
    ordered = [str(r["id"]) for r in rows]
    # The second token was created later -> appears first in the listing.
    assert ordered.index(str(second["id"])) < ordered.index(str(first["id"]))


def test_list_tokens_scopes_to_idp(test_tenant, test_user):
    """Tokens belong to one IdP connection; the listing must not leak across."""
    idp_a = _create_idp(test_tenant["id"], test_user["id"], name="IdP A")
    idp_b = _create_idp(test_tenant["id"], test_user["id"], name="IdP B")
    tok_a = _create_token(test_tenant["id"], test_user["id"], idp_a)
    _create_token(test_tenant["id"], test_user["id"], idp_b)

    rows_a = database.scim_inbound_tokens.list_tokens(test_tenant["id"], str(idp_a["id"]))
    assert [str(r["id"]) for r in rows_a] == [str(tok_a["id"])]


# -- get_by_hash / get_token --------------------------------------------------


def test_get_by_hash_returns_row(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    token_hash = "a" * 64
    row = _create_token(test_tenant["id"], test_user["id"], idp, token_hash=token_hash)

    fetched = database.scim_inbound_tokens.get_by_hash(test_tenant["id"], token_hash)
    assert fetched is not None
    assert str(fetched["id"]) == str(row["id"])


def test_get_by_hash_returns_none_for_unknown(test_tenant, test_user):
    # Distinct from any other test fixture's hash.
    assert database.scim_inbound_tokens.get_by_hash(test_tenant["id"], "f" * 64) is None


def test_get_by_hash_returns_revoked_row(test_tenant, test_user):
    """Auth path must be able to distinguish 'revoked' from 'no such token'."""
    idp = _create_idp(test_tenant["id"], test_user["id"])
    token_hash = "b" * 64
    row = _create_token(test_tenant["id"], test_user["id"], idp, token_hash=token_hash)
    database.scim_inbound_tokens.revoke(test_tenant["id"], str(row["id"]))

    fetched = database.scim_inbound_tokens.get_by_hash(test_tenant["id"], token_hash)
    assert fetched is not None
    assert fetched["revoked_at"] is not None


def test_get_token_by_id(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    row = _create_token(test_tenant["id"], test_user["id"], idp)
    fetched = database.scim_inbound_tokens.get_token(test_tenant["id"], str(row["id"]))
    assert fetched is not None
    assert str(fetched["id"]) == str(row["id"])


def test_get_token_unknown_returns_none(test_tenant):
    assert database.scim_inbound_tokens.get_token(test_tenant["id"], str(uuid4())) is None


# -- revoke -------------------------------------------------------------------


def test_revoke_sets_timestamp_and_is_idempotent(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    row = _create_token(test_tenant["id"], test_user["id"], idp)

    rows = database.scim_inbound_tokens.revoke(test_tenant["id"], str(row["id"]))
    assert rows == 1

    # Second revoke is a no-op (already revoked)
    rows = database.scim_inbound_tokens.revoke(test_tenant["id"], str(row["id"]))
    assert rows == 0


# -- touch_last_used ----------------------------------------------------------


def test_touch_last_used(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    row = _create_token(test_tenant["id"], test_user["id"], idp)
    assert row["last_used_at"] is None

    rows = database.scim_inbound_tokens.touch_last_used(test_tenant["id"], str(row["id"]))
    assert rows == 1

    fetched = database.scim_inbound_tokens.get_token(test_tenant["id"], str(row["id"]))
    assert fetched is not None
    assert fetched["last_used_at"] is not None


# -- RLS scoping --------------------------------------------------------------


def test_rls_isolates_tokens_by_tenant(test_tenant, test_user):
    """A second tenant's session cannot see this tenant's tokens."""
    idp = _create_idp(test_tenant["id"], test_user["id"])
    _create_token(test_tenant["id"], test_user["id"], idp)

    other_id = database.fetchone(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id",
        {"s": f"other-{uuid4().hex[:8]}", "n": "Other"},
    )
    try:
        rows = database.scim_inbound_tokens.list_tokens(other_id["id"], str(idp["id"]))
        assert rows == []
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": other_id["id"]},
        )


# -- Unique constraint --------------------------------------------------------


def test_token_hash_is_globally_unique(test_tenant, test_user):
    """The unique index on token_hash protects against cross-tenant collisions.

    Hash collisions across tenants would be a cross-tenant authentication
    bypass -- the auth path looks up by hash with UNSCOPED RLS, and a
    duplicate would map a request to the wrong tenant. Defence in depth:
    the unique index makes the collision impossible at the DB layer.
    """
    import psycopg.errors
    import pytest

    idp = _create_idp(test_tenant["id"], test_user["id"])
    shared_hash = "c" * 64
    _create_token(test_tenant["id"], test_user["id"], idp, token_hash=shared_hash)

    with pytest.raises((psycopg.errors.UniqueViolation, Exception)):
        _create_token(test_tenant["id"], test_user["id"], idp, token_hash=shared_hash)
