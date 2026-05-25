"""Tests for `services.scim.inbound_credentials` (inbound SCIM token CRUD)."""

from __future__ import annotations

import hashlib
from uuid import uuid4

import database
import pytest
from services.exceptions import ForbiddenError, NotFoundError
from services.scim import inbound_credentials as inbound_creds
from services.types import RequestingUser


def _create_idp(tenant_id, user_id, *, name="Inbound SCIM IdP"):
    return database.saml.create_identity_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        provider_type="generic",
        sp_entity_id=f"urn:test:{uuid4().hex}",
        created_by=str(user_id),
    )


def _requesting_user(tenant_id, user_id, role="super_admin") -> RequestingUser:
    return RequestingUser(id=str(user_id), tenant_id=str(tenant_id), role=role)


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


def test_create_token_requires_super_admin(test_tenant, test_admin_user):
    """An admin (non-super) cannot mint inbound tokens.

    The inbound SCIM tokens grant directory write access from upstream;
    only super_admin should be able to issue them. The role gate is
    tested explicitly so a future refactor of `require_super_admin`
    cannot silently relax it.
    """
    idp = _create_idp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"], role="admin")
    with pytest.raises(ForbiddenError):
        inbound_creds.create_token(ru, str(idp["id"]))


def test_list_tokens_requires_super_admin(test_tenant, test_admin_user):
    idp = _create_idp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"], role="user")
    with pytest.raises(ForbiddenError):
        inbound_creds.list_tokens(ru, str(idp["id"]))


def test_revoke_token_requires_super_admin(test_tenant, test_admin_user):
    idp = _create_idp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"], role="admin")
    with pytest.raises(ForbiddenError):
        inbound_creds.revoke_token(ru, str(idp["id"]), str(uuid4()))


# ---------------------------------------------------------------------------
# create_token: plaintext + hash + audit
# ---------------------------------------------------------------------------


def test_create_token_returns_plaintext_with_prefix(test_tenant, test_admin_user):
    """Plaintext is returned in the response; the prefix is set."""
    idp = _create_idp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    response = inbound_creds.create_token(ru, str(idp["id"]), name="Okta production")

    assert response.plaintext.startswith("wid_inbound_")
    # Entropy body: 32 raw bytes -> 43 base64url chars (no padding)
    assert len(response.plaintext) >= len("wid_inbound_") + 40
    assert response.idp_id == str(idp["id"])
    assert response.name == "Okta production"


def test_create_token_persists_hash_not_plaintext(test_tenant, test_admin_user):
    """The DB stores SHA-256(plaintext); plaintext never leaves the response."""
    idp = _create_idp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    response = inbound_creds.create_token(ru, str(idp["id"]))
    expected_hash = hashlib.sha256(response.plaintext.encode("utf-8")).hexdigest()

    row = database.fetchone(
        test_tenant["id"],
        "select token_hash from scim_inbound_tokens where id = :id",
        {"id": response.id},
    )
    assert row is not None
    assert row["token_hash"] == expected_hash
    # The plaintext value must not appear anywhere in the stored row.
    assert response.plaintext not in str(row["token_hash"])


def test_create_token_emits_audit_event(test_tenant, test_admin_user):
    idp = _create_idp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    response = inbound_creds.create_token(ru, str(idp["id"]), name="audit-test")

    events = database.fetchall(
        database.UNSCOPED,
        """
        SELECT el.event_type, el.artifact_id, el.artifact_type, elm.metadata
        FROM event_logs el
        JOIN event_log_metadata elm ON elm.metadata_hash = el.metadata_hash
        WHERE el.event_type = 'scim_inbound_token_created'
          AND el.artifact_id = :idp_id
        """,
        {"idp_id": str(idp["id"])},
    )
    assert len(events) == 1
    assert events[0]["artifact_type"] == "saml_identity_provider"
    metadata = events[0]["metadata"]
    assert metadata["token_id"] == response.id
    assert metadata["name"] == "audit-test"


def test_create_token_unknown_idp_raises(test_tenant, test_admin_user):
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(NotFoundError):
        inbound_creds.create_token(ru, str(uuid4()))


def test_create_token_strips_and_normalises_blank_name(test_tenant, test_admin_user):
    """A whitespace-only name becomes NULL; a padded name is stripped."""
    idp = _create_idp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    blank = inbound_creds.create_token(ru, str(idp["id"]), name="   ")
    assert blank.name is None

    padded = inbound_creds.create_token(ru, str(idp["id"]), name="  Okta  ")
    assert padded.name == "Okta"


def test_create_token_unique_plaintext_per_call(test_tenant, test_admin_user):
    """Two consecutive mints yield distinct plaintexts.

    Sanity check on the entropy source -- a regression that returned a
    constant would defeat the security model entirely.
    """
    idp = _create_idp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    a = inbound_creds.create_token(ru, str(idp["id"]))
    b = inbound_creds.create_token(ru, str(idp["id"]))
    assert a.plaintext != b.plaintext


# ---------------------------------------------------------------------------
# list_tokens
# ---------------------------------------------------------------------------


def test_list_tokens_returns_metadata_only(test_tenant, test_admin_user):
    """No plaintext, no hash leaks through the listing shape."""
    idp = _create_idp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    created = inbound_creds.create_token(ru, str(idp["id"]), name="t1")

    listing = inbound_creds.list_tokens(ru, str(idp["id"]))
    assert listing.total == 1
    item = listing.items[0]
    assert item.id == created.id
    assert item.name == "t1"
    # ScimInboundToken intentionally has no `plaintext` / `token_hash` field.
    assert not hasattr(item, "plaintext")
    assert not hasattr(item, "token_hash")


def test_list_tokens_includes_revoked(test_tenant, test_admin_user):
    idp = _create_idp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    active = inbound_creds.create_token(ru, str(idp["id"]))
    revoked = inbound_creds.create_token(ru, str(idp["id"]))
    inbound_creds.revoke_token(ru, str(idp["id"]), revoked.id)

    listing = inbound_creds.list_tokens(ru, str(idp["id"]))
    ids = {item.id for item in listing.items}
    assert ids == {active.id, revoked.id}
    revoked_item = next(i for i in listing.items if i.id == revoked.id)
    assert revoked_item.revoked_at is not None


def test_list_tokens_unknown_idp_raises(test_tenant, test_admin_user):
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(NotFoundError):
        inbound_creds.list_tokens(ru, str(uuid4()))


# ---------------------------------------------------------------------------
# revoke_token
# ---------------------------------------------------------------------------


def test_revoke_token_marks_revoked_and_logs(test_tenant, test_admin_user):
    idp = _create_idp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    created = inbound_creds.create_token(ru, str(idp["id"]))
    inbound_creds.revoke_token(ru, str(idp["id"]), created.id)

    row = database.scim_inbound_tokens.get_token(test_tenant["id"], created.id)
    assert row is not None
    assert row["revoked_at"] is not None

    events = database.fetchall(
        database.UNSCOPED,
        """
        SELECT el.event_type, elm.metadata
        FROM event_logs el
        JOIN event_log_metadata elm ON elm.metadata_hash = el.metadata_hash
        WHERE el.event_type = 'scim_inbound_token_revoked'
          AND el.artifact_id = :idp_id
        """,
        {"idp_id": str(idp["id"])},
    )
    assert len(events) == 1
    assert events[0]["metadata"]["token_id"] == created.id


def test_revoke_token_unknown_idp_raises(test_tenant, test_admin_user):
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(NotFoundError):
        inbound_creds.revoke_token(ru, str(uuid4()), str(uuid4()))


def test_revoke_token_unknown_token_raises(test_tenant, test_admin_user):
    idp = _create_idp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(NotFoundError):
        inbound_creds.revoke_token(ru, str(idp["id"]), str(uuid4()))


def test_revoke_token_already_revoked_raises(test_tenant, test_admin_user):
    """Double-revoke surfaces as NotFoundError so the API returns 404, not 204.

    A 204 on a no-op would hide a UI race (two admins both clicking
    Revoke) where the second click should fail loudly with "already
    revoked" rather than appear to succeed.
    """
    idp = _create_idp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    created = inbound_creds.create_token(ru, str(idp["id"]))
    inbound_creds.revoke_token(ru, str(idp["id"]), created.id)
    with pytest.raises(NotFoundError):
        inbound_creds.revoke_token(ru, str(idp["id"]), created.id)


def test_revoke_rejects_token_from_different_idp(test_tenant, test_admin_user):
    """Cross-IdP id must not revoke a token belonging to another IdP.

    Defence in depth on top of RLS: same tenant, two IdPs, an admin
    typo of the idp_id path component should not silently revoke a
    token under a different IdP than the one the URL names.
    """
    idp_a = _create_idp(test_tenant["id"], test_admin_user["id"], name="IdP A")
    idp_b = _create_idp(test_tenant["id"], test_admin_user["id"], name="IdP B")
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    tok_a = inbound_creds.create_token(ru, str(idp_a["id"]))
    with pytest.raises(NotFoundError):
        inbound_creds.revoke_token(ru, str(idp_b["id"]), tok_a.id)

    # Token remains active.
    row = database.scim_inbound_tokens.get_token(test_tenant["id"], tok_a.id)
    assert row is not None
    assert row["revoked_at"] is None
