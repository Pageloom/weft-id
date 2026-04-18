"""Tests for database.webauthn_credentials module."""

from uuid import uuid4

import database
import pytest


def _cred_bytes(seed: int = 0) -> bytes:
    """Produce deterministic credential_id bytes for tests."""
    return (b"\x00" * 16 + seed.to_bytes(16, "big"))[-32:]


def test_create_credential_returns_row(test_user):
    row = database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=_cred_bytes(1),
        public_key=b"pk-bytes",
        name="My laptop",
        sign_count=0,
        aaguid="aaguid-1",
        transports=["internal"],
        backup_eligible=True,
        backup_state=True,
    )

    assert row["id"] is not None
    assert row["name"] == "My laptop"
    assert bytes(row["credential_id"]) == _cred_bytes(1)
    assert row["backup_eligible"] is True
    assert row["backup_state"] is True
    assert list(row["transports"]) == ["internal"]
    assert row["created_at"] is not None


def test_list_credentials_orders_newest_first(test_user):
    first = database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=_cred_bytes(2),
        public_key=b"pk",
        name="First",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )
    second = database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=_cred_bytes(3),
        public_key=b"pk",
        name="Second",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )

    rows = database.webauthn_credentials.list_credentials(test_user["tenant_id"], test_user["id"])
    ids = [str(r["id"]) for r in rows]
    assert str(second["id"]) in ids
    assert str(first["id"]) in ids
    # Newest first
    assert ids.index(str(second["id"])) < ids.index(str(first["id"]))


def test_count_credentials(test_user):
    assert (
        database.webauthn_credentials.count_credentials(test_user["tenant_id"], test_user["id"])
        == 0
    )
    database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=_cred_bytes(4),
        public_key=b"pk",
        name="Key",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )
    assert (
        database.webauthn_credentials.count_credentials(test_user["tenant_id"], test_user["id"])
        == 1
    )


def test_rename_scoped_to_user(test_user, test_admin_user):
    """Rename on another user's credential (same tenant) must be a no-op (0 rows)."""
    row = database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=_cred_bytes(5),
        public_key=b"pk",
        name="User key",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )

    # Admin tries to rename user's passkey via db layer
    rows = database.webauthn_credentials.rename_credential(
        test_user["tenant_id"],
        str(row["id"]),
        test_admin_user["id"],
        "Hacked",
    )
    assert rows == 0

    # Still the original name
    fresh = database.webauthn_credentials.get_credential(test_user["tenant_id"], str(row["id"]))
    assert fresh is not None
    assert fresh["name"] == "User key"


def test_delete_scoped_to_user(test_user, test_admin_user):
    row = database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=_cred_bytes(6),
        public_key=b"pk",
        name="User key",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )

    rows = database.webauthn_credentials.delete_credential(
        test_user["tenant_id"],
        str(row["id"]),
        test_admin_user["id"],
    )
    assert rows == 0

    # Still exists
    assert (
        database.webauthn_credentials.get_credential(test_user["tenant_id"], str(row["id"]))
        is not None
    )


def test_delete_own_credential(test_user):
    row = database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=_cred_bytes(7),
        public_key=b"pk",
        name="Mine",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )

    rows = database.webauthn_credentials.delete_credential(
        test_user["tenant_id"], str(row["id"]), test_user["id"]
    )
    assert rows == 1

    assert (
        database.webauthn_credentials.get_credential(test_user["tenant_id"], str(row["id"])) is None
    )


def test_tenant_isolation(test_user):
    """Credentials in tenant A must not be visible from tenant B."""
    # Create a second tenant + user
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
        # Create a credential in test_user's tenant
        database.webauthn_credentials.create_credential(
            tenant_id=test_user["tenant_id"],
            tenant_id_value=str(test_user["tenant_id"]),
            user_id=test_user["id"],
            credential_id=_cred_bytes(8),
            public_key=b"pk",
            name="Tenant-A key",
            sign_count=0,
            aaguid=None,
            transports=None,
            backup_eligible=False,
            backup_state=False,
        )

        # List from the other tenant should yield nothing for test_user
        rows = database.webauthn_credentials.list_credentials(other["id"], test_user["id"])
        assert rows == []
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": other["id"]},
        )


def test_unique_credential_id_constraint(test_user):
    database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=_cred_bytes(9),
        public_key=b"pk",
        name="A",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )
    # Second insert with the same credential_id must raise
    with pytest.raises(Exception):
        database.webauthn_credentials.create_credential(
            tenant_id=test_user["tenant_id"],
            tenant_id_value=str(test_user["tenant_id"]),
            user_id=test_user["id"],
            credential_id=_cred_bytes(9),
            public_key=b"pk",
            name="B",
            sign_count=0,
            aaguid=None,
            transports=None,
            backup_eligible=False,
            backup_state=False,
        )


def test_unique_credential_id_is_global(test_user, test_admin_user):
    """Globally-unique: same credential_id for a different user in the same
    tenant still violates the unique index."""
    database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=_cred_bytes(11),
        public_key=b"pk",
        name="Owned by user",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )
    with pytest.raises(Exception):
        database.webauthn_credentials.create_credential(
            tenant_id=test_user["tenant_id"],
            tenant_id_value=str(test_user["tenant_id"]),
            user_id=test_admin_user["id"],
            credential_id=_cred_bytes(11),
            public_key=b"pk",
            name="Different user, same cred_id",
            sign_count=0,
            aaguid=None,
            transports=None,
            backup_eligible=False,
            backup_state=False,
        )


def test_update_auth_state_happy_path(test_user):
    """update_auth_state writes sign_count, backup_state, and last_used_at."""
    row = database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=_cred_bytes(20),
        public_key=b"pk",
        name="Key",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )

    # Before: no last_used_at, sign_count=0
    assert row["last_used_at"] is None
    assert row["sign_count"] == 0
    assert row["backup_state"] is False

    rows = database.webauthn_credentials.update_auth_state(
        tenant_id=test_user["tenant_id"],
        credential_uuid=str(row["id"]),
        user_id=test_user["id"],
        sign_count=42,
        backup_state=True,
    )
    assert rows == 1

    fresh = database.webauthn_credentials.get_credential(test_user["tenant_id"], str(row["id"]))
    assert fresh is not None
    assert fresh["sign_count"] == 42
    assert fresh["backup_state"] is True
    assert fresh["last_used_at"] is not None


def test_update_auth_state_wrong_user(test_user, test_admin_user):
    """update_auth_state must not modify a credential owned by another user."""
    row = database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=_cred_bytes(21),
        public_key=b"pk",
        name="Owner",
        sign_count=5,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )

    rows = database.webauthn_credentials.update_auth_state(
        tenant_id=test_user["tenant_id"],
        credential_uuid=str(row["id"]),
        user_id=test_admin_user["id"],
        sign_count=999,
        backup_state=True,
    )
    assert rows == 0

    fresh = database.webauthn_credentials.get_credential(test_user["tenant_id"], str(row["id"]))
    assert fresh is not None
    assert fresh["sign_count"] == 5
    assert fresh["backup_state"] is False
    assert fresh["last_used_at"] is None


def test_update_auth_state_wrong_tenant(test_user):
    """update_auth_state must not cross tenant boundaries."""
    row = database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=_cred_bytes(22),
        public_key=b"pk",
        name="Scoped",
        sign_count=3,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )

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
        rows = database.webauthn_credentials.update_auth_state(
            tenant_id=other["id"],
            credential_uuid=str(row["id"]),
            user_id=test_user["id"],
            sign_count=999,
            backup_state=True,
        )
        assert rows == 0

        fresh = database.webauthn_credentials.get_credential(test_user["tenant_id"], str(row["id"]))
        assert fresh is not None
        assert fresh["sign_count"] == 3
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": other["id"]},
        )


def test_cascade_delete_on_user(test_user):
    database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=_cred_bytes(10),
        public_key=b"pk",
        name="Cascade",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )
    assert (
        database.webauthn_credentials.count_credentials(test_user["tenant_id"], test_user["id"])
        == 1
    )

    database.execute(
        test_user["tenant_id"],
        "DELETE FROM users WHERE id = :id",
        {"id": test_user["id"]},
    )

    assert (
        database.webauthn_credentials.count_credentials(test_user["tenant_id"], test_user["id"])
        == 0
    )
