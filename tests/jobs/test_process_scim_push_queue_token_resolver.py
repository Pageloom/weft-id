"""Tests for the production `_resolve_outbound_token` helper.

The push worker's `token_resolver` injection point is intentionally tiny:
look up the SP's most recent non-revoked credential row, decrypt the
plaintext via the Fernet key derived from `SECRET_KEY`, return it (or
None on any failure). These tests verify each branch.
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import database
from jobs.process_scim_push_queue import _resolve_outbound_token
from utils.scim_crypto import encrypt_token


def _create_sp(tenant_id, user_id, name="Token Resolver SP"):
    return database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        created_by=str(user_id),
    )


def test_returns_plaintext_when_active_credential_exists(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    plaintext = "active-token-value"
    database.scim_credentials.create_credential(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp["id"]),
        created_by_user_id=str(test_user["id"]),
        encrypted_plaintext=encrypt_token(plaintext),
    )

    out = _resolve_outbound_token(str(test_tenant["id"]), str(sp["id"]))
    assert out == plaintext


def test_returns_none_when_no_credential_exists(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    out = _resolve_outbound_token(str(test_tenant["id"]), str(sp["id"]))
    assert out is None


def test_returns_none_for_row_without_plaintext(test_tenant, test_user):
    """A row whose `encrypted_plaintext` is NULL must not surface to the worker."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    database.scim_credentials.create_credential(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp["id"]),
        created_by_user_id=str(test_user["id"]),
        encrypted_plaintext=None,
    )

    out = _resolve_outbound_token(str(test_tenant["id"]), str(sp["id"]))
    assert out is None


def test_returns_none_when_ciphertext_invalid(test_tenant, test_user):
    """Corrupted ciphertext logs and yields None instead of crashing the worker."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    database.scim_credentials.create_credential(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp["id"]),
        created_by_user_id=str(test_user["id"]),
        encrypted_plaintext=b"not-a-fernet-token",
    )

    out = _resolve_outbound_token(str(test_tenant["id"]), str(sp["id"]))
    assert out is None


def test_picks_newest_credential_during_rotation_overlap(test_tenant, test_user):
    """A freshly-rotated credential overrides the scheduled-for-revocation one."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    old_plain = "old"
    new_plain = "new"
    old = database.scim_credentials.create_credential(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp["id"]),
        created_by_user_id=str(test_user["id"]),
        encrypted_plaintext=encrypt_token(old_plain),
    )
    # Schedule revocation in the future -- both rows remain "active" but the
    # resolver must pick the newest.
    database.scim_credentials.schedule_revocation(
        test_tenant["id"], str(old["id"]), overlap_interval="1 hour"
    )
    database.scim_credentials.create_credential(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp["id"]),
        created_by_user_id=str(test_user["id"]),
        encrypted_plaintext=encrypt_token(new_plain),
    )

    out = _resolve_outbound_token(str(test_tenant["id"]), str(sp["id"]))
    assert out == new_plain


def test_returns_none_on_database_failure(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    with patch(
        "database.scim_credentials.get_active_credential_for_outbound",
        side_effect=RuntimeError("db down"),
    ):
        out = _resolve_outbound_token(str(test_tenant["id"]), str(sp["id"]))
        assert out is None


def test_picks_unknown_sp_returns_none(test_tenant):
    out = _resolve_outbound_token(str(test_tenant["id"]), str(uuid4()))
    assert out is None
