"""Tests for `services.scim.admin` (config, credentials, sync log, queue actions)."""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from uuid import uuid4

import database
import pytest
from schemas.scim_admin import ScimConfigUpdate
from services.exceptions import NotFoundError, ValidationError
from services.scim import admin as scim_admin
from services.types import RequestingUser
from utils.scim_crypto import decrypt_token


def _fake_getaddrinfo_to(addr: str):
    """Return a `getaddrinfo`-shaped sequence that resolves to `addr`.

    Used by SSRF tests so DNS is deterministic (no network in tests).
    """
    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    sockaddr: tuple = (addr, 0, 0, 0) if family == socket.AF_INET6 else (addr, 0)
    return [(family, socket.SOCK_STREAM, 6, "", sockaddr)]


@pytest.fixture
def patch_dns_public(monkeypatch):
    """Patch `socket.getaddrinfo` to resolve any hostname to a public IP.

    Lets the existing tests that set `scim_target_url=https://example.com/...`
    pass without hitting real DNS while SSRF validation is in force.
    """
    monkeypatch.setattr(
        "services.scim.admin.socket.getaddrinfo",
        lambda host, *_a, **_kw: _fake_getaddrinfo_to("93.184.216.34"),
    )


def _create_sp(tenant_id, user_id, name="SCIM Admin SP"):
    return database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        created_by=str(user_id),
    )


def _requesting_user(tenant_id, user_id, role="super_admin") -> RequestingUser:
    return RequestingUser(id=str(user_id), tenant_id=str(tenant_id), role=role)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_get_scim_config_returns_defaults(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    config = scim_admin.get_scim_config(ru, str(sp["id"]))
    assert config.sp_id == str(sp["id"])
    assert config.scim_enabled is False
    assert config.scim_kind == "generic"
    assert config.scim_membership_mode == "effective"
    assert config.scim_log_retention == "3"


def test_get_scim_config_unknown_sp_raises(test_tenant, test_admin_user):
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(NotFoundError):
        scim_admin.get_scim_config(ru, str(uuid4()))


def test_update_scim_config_writes_changes_and_logs(test_tenant, test_admin_user, patch_dns_public):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    updated = scim_admin.update_scim_config(
        ru,
        str(sp["id"]),
        ScimConfigUpdate(
            scim_enabled=True,
            scim_target_url="https://example.com/scim",
            scim_kind="slack",
            scim_membership_mode="direct",
            scim_log_retention="12",
        ),
    )
    assert updated.scim_enabled is True
    assert updated.scim_target_url == "https://example.com/scim"
    assert updated.scim_kind == "slack"
    assert updated.scim_membership_mode == "direct"
    assert updated.scim_log_retention == "12"

    # Audit event captured.
    events = database.fetchall(
        database.UNSCOPED,
        """
        SELECT el.event_type, elm.metadata
        FROM event_logs el
        JOIN event_log_metadata elm ON elm.metadata_hash = el.metadata_hash
        WHERE el.event_type = 'scim_config_updated' AND el.artifact_id = :sp_id
        """,
        {"sp_id": str(sp["id"])},
    )
    assert len(events) == 1
    metadata = events[0]["metadata"]
    assert set(metadata["changed_fields"]) == {
        "scim_enabled",
        "scim_target_url",
        "scim_kind",
        "scim_membership_mode",
        "scim_log_retention",
    }


def test_update_scim_config_no_fields_raises(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(ValidationError):
        scim_admin.update_scim_config(ru, str(sp["id"]), ScimConfigUpdate())


def test_update_scim_config_enable_without_url_raises(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(ValidationError):
        scim_admin.update_scim_config(ru, str(sp["id"]), ScimConfigUpdate(scim_enabled=True))


def test_update_scim_config_clears_target_url_with_empty_string(
    test_tenant, test_admin_user, patch_dns_public
):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    scim_admin.update_scim_config(
        ru, str(sp["id"]), ScimConfigUpdate(scim_target_url="https://example.com/scim")
    )
    cleared = scim_admin.update_scim_config(ru, str(sp["id"]), ScimConfigUpdate(scim_target_url=""))
    assert cleared.scim_target_url is None


# ---------------------------------------------------------------------------
# SSRF allowlist on scim_target_url
# ---------------------------------------------------------------------------


def _try_update_url(test_tenant, test_admin_user, url):
    """Helper: try to set the SCIM target URL on a fresh SP."""
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    return scim_admin.update_scim_config(ru, str(sp["id"]), ScimConfigUpdate(scim_target_url=url))


def test_scim_target_url_rejects_http_outside_dev(
    test_tenant, test_admin_user, monkeypatch, patch_dns_public
):
    """`http://` is rejected when `IS_DEV` is false."""
    monkeypatch.setattr("services.scim.admin.settings.IS_DEV", False)
    with pytest.raises(ValidationError) as excinfo:
        _try_update_url(test_tenant, test_admin_user, "http://scim.example.com/v2")
    assert excinfo.value.code == "scim_target_url_invalid"


def test_scim_target_url_allows_http_in_dev(
    test_tenant, test_admin_user, monkeypatch, patch_dns_public
):
    """`http://` is allowed when `IS_DEV` is true (tests already set IS_DEV=true)."""
    monkeypatch.setattr("services.scim.admin.settings.IS_DEV", True)
    out = _try_update_url(test_tenant, test_admin_user, "http://scim.example.com/v2")
    assert out.scim_target_url == "http://scim.example.com/v2"


def test_scim_target_url_rejects_rfc1918_10(test_tenant, test_admin_user, monkeypatch):
    monkeypatch.setattr(
        "services.scim.admin.socket.getaddrinfo",
        lambda *_a, **_kw: _fake_getaddrinfo_to("10.0.5.5"),
    )
    with pytest.raises(ValidationError) as excinfo:
        _try_update_url(test_tenant, test_admin_user, "https://internal.example.com/scim")
    assert excinfo.value.code == "scim_target_url_invalid"


def test_scim_target_url_rejects_rfc1918_172_16(test_tenant, test_admin_user, monkeypatch):
    monkeypatch.setattr(
        "services.scim.admin.socket.getaddrinfo",
        lambda *_a, **_kw: _fake_getaddrinfo_to("172.20.1.1"),
    )
    with pytest.raises(ValidationError):
        _try_update_url(test_tenant, test_admin_user, "https://internal.example.com/scim")


def test_scim_target_url_rejects_rfc1918_192_168(test_tenant, test_admin_user, monkeypatch):
    monkeypatch.setattr(
        "services.scim.admin.socket.getaddrinfo",
        lambda *_a, **_kw: _fake_getaddrinfo_to("192.168.1.5"),
    )
    with pytest.raises(ValidationError):
        _try_update_url(test_tenant, test_admin_user, "https://internal.example.com/scim")


def test_scim_target_url_rejects_loopback_v4(test_tenant, test_admin_user, monkeypatch):
    monkeypatch.setattr(
        "services.scim.admin.socket.getaddrinfo",
        lambda *_a, **_kw: _fake_getaddrinfo_to("127.0.0.1"),
    )
    with pytest.raises(ValidationError):
        _try_update_url(test_tenant, test_admin_user, "https://loopback.example.com/scim")


def test_scim_target_url_rejects_loopback_v6(test_tenant, test_admin_user, monkeypatch):
    monkeypatch.setattr(
        "services.scim.admin.socket.getaddrinfo",
        lambda *_a, **_kw: _fake_getaddrinfo_to("::1"),
    )
    with pytest.raises(ValidationError):
        _try_update_url(test_tenant, test_admin_user, "https://loopback6.example.com/scim")


def test_scim_target_url_rejects_link_local(test_tenant, test_admin_user, monkeypatch):
    monkeypatch.setattr(
        "services.scim.admin.socket.getaddrinfo",
        lambda *_a, **_kw: _fake_getaddrinfo_to("169.254.169.254"),
    )
    with pytest.raises(ValidationError):
        _try_update_url(test_tenant, test_admin_user, "https://metadata.example.com/scim")


def test_scim_target_url_rejects_ipv6_ula(test_tenant, test_admin_user, monkeypatch):
    """ULA (`fc00::/7`) is rejected via ipaddress.is_private."""
    monkeypatch.setattr(
        "services.scim.admin.socket.getaddrinfo",
        lambda *_a, **_kw: _fake_getaddrinfo_to("fd12:3456::1"),
    )
    with pytest.raises(ValidationError):
        _try_update_url(test_tenant, test_admin_user, "https://ula.example.com/scim")


def test_scim_target_url_rejects_literal_localhost(test_tenant, test_admin_user):
    """Literal `localhost` is rejected by string match before DNS."""
    with pytest.raises(ValidationError) as excinfo:
        _try_update_url(test_tenant, test_admin_user, "https://localhost/scim")
    assert excinfo.value.code == "scim_target_url_invalid"


def test_scim_target_url_accepts_public_https(test_tenant, test_admin_user, patch_dns_public):
    """A normal https URL to a public IP is accepted."""
    out = _try_update_url(test_tenant, test_admin_user, "https://scim.example.com/v2")
    assert out.scim_target_url == "https://scim.example.com/v2"


def test_scim_target_url_skips_validation_when_unchanged(
    test_tenant, test_admin_user, monkeypatch, patch_dns_public
):
    """Re-saving the same URL must not re-resolve DNS.

    Critical: the admin can re-save a config (e.g. to flip `scim_enabled`)
    without re-paying the DNS cost or hitting transient resolution
    failures.
    """
    out = _try_update_url(test_tenant, test_admin_user, "https://scim.example.com/v2")
    sp_id = out.sp_id

    # Now swap the resolver to one that would FAIL if called. Saving the
    # same URL again must not call it.
    def _boom(*_a, **_kw):
        raise AssertionError("getaddrinfo should not be called for unchanged URL")

    monkeypatch.setattr("services.scim.admin.socket.getaddrinfo", _boom)

    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    out2 = scim_admin.update_scim_config(
        ru, sp_id, ScimConfigUpdate(scim_target_url="https://scim.example.com/v2")
    )
    assert out2.scim_target_url == "https://scim.example.com/v2"


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


def test_create_credential_returns_plaintext_and_stores_ciphertext(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    response = scim_admin.create_credential(ru, str(sp["id"]))
    assert response.plaintext
    assert len(response.plaintext) >= 24

    # The encrypted plaintext column round-trips through the Fernet key.
    row = database.scim_credentials.get_active_credential_for_outbound(
        test_tenant["id"], str(sp["id"])
    )
    assert row is not None
    decrypted = decrypt_token(bytes(row["encrypted_plaintext"]))
    assert decrypted == response.plaintext

    # Audit event.
    events = database.fetchall(
        database.UNSCOPED,
        """
        SELECT el.event_type, elm.metadata
        FROM event_logs el
        JOIN event_log_metadata elm ON elm.metadata_hash = el.metadata_hash
        WHERE el.event_type = 'scim_token_created' AND el.artifact_id = :sp_id
        """,
        {"sp_id": str(sp["id"])},
    )
    assert len(events) == 1
    assert events[0]["metadata"]["credential_id"] == response.id


def test_list_credentials_includes_pending_revocation(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    first = scim_admin.create_credential(ru, str(sp["id"]))
    rotated = scim_admin.rotate_credential(ru, str(sp["id"]), first.id, overlap_hours=24)

    listing = scim_admin.list_credentials(ru, str(sp["id"]))
    ids = {item.id for item in listing.items}
    assert first.id in ids  # still inside overlap window
    assert rotated.id in ids


def test_rotate_credential_creates_new_and_schedules_old(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    first = scim_admin.create_credential(ru, str(sp["id"]))

    rotated = scim_admin.rotate_credential(ru, str(sp["id"]), first.id, overlap_hours=24)
    assert rotated.rotated_from_id == first.id
    assert rotated.rotated_from_revoke_at is not None
    assert rotated.plaintext != first.plaintext

    # The new token is what the worker would receive.
    row = database.scim_credentials.get_active_credential_for_outbound(
        test_tenant["id"], str(sp["id"])
    )
    assert row is not None
    assert str(row["id"]) == rotated.id

    events = database.fetchall(
        database.UNSCOPED,
        """
        SELECT elm.metadata FROM event_logs el
        JOIN event_log_metadata elm ON elm.metadata_hash = el.metadata_hash
        WHERE el.event_type = 'scim_token_rotated' AND el.artifact_id = :sp_id
        """,
        {"sp_id": str(sp["id"])},
    )
    assert len(events) == 1
    assert events[0]["metadata"]["old_credential_id"] == first.id
    assert events[0]["metadata"]["new_credential_id"] == rotated.id


def test_rotate_credential_zero_overlap_revokes_immediately(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    first = scim_admin.create_credential(ru, str(sp["id"]))

    scim_admin.rotate_credential(ru, str(sp["id"]), first.id, overlap_hours=0)

    listing = scim_admin.list_credentials(ru, str(sp["id"]))
    # Old credential is hard-revoked, not in usable list.
    assert first.id not in {item.id for item in listing.items}


def test_rotate_credential_unknown_id_raises(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(NotFoundError):
        scim_admin.rotate_credential(ru, str(sp["id"]), str(uuid4()))


def test_rotate_credential_overlap_out_of_range(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    first = scim_admin.create_credential(ru, str(sp["id"]))
    with pytest.raises(ValidationError):
        scim_admin.rotate_credential(ru, str(sp["id"]), first.id, overlap_hours=1000)


def test_revoke_credential_marks_revoked_and_logs(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    first = scim_admin.create_credential(ru, str(sp["id"]))

    scim_admin.revoke_credential(ru, str(sp["id"]), first.id)

    listing = scim_admin.list_credentials(ru, str(sp["id"]))
    assert first.id not in {item.id for item in listing.items}

    events = database.fetchall(
        database.UNSCOPED,
        """
        SELECT elm.metadata FROM event_logs el
        JOIN event_log_metadata elm ON elm.metadata_hash = el.metadata_hash
        WHERE el.event_type = 'scim_token_revoked' AND el.artifact_id = :sp_id
        """,
        {"sp_id": str(sp["id"])},
    )
    assert len(events) == 1
    assert events[0]["metadata"]["credential_id"] == first.id


def test_revoke_credential_unknown_raises(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(NotFoundError):
        scim_admin.revoke_credential(ru, str(sp["id"]), str(uuid4()))


# ---------------------------------------------------------------------------
# Sync activity
# ---------------------------------------------------------------------------


def _write_sync_log_row(tenant_id, sp_id, status, started_at=None, completed=False):
    row = database.scim_sync_log.create_entry(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        sp_id=str(sp_id),
        resource_type="user",
        resource_id=str(uuid4()),
        status=status,
        attempt=1,
        started_at=started_at or datetime.now(UTC),
    )
    if completed:
        database.scim_sync_log.update_status(tenant_id, str(row["id"]), status, completed=True)
    return row


def test_list_sync_log_paginates_and_orders(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    # Mix completed and in-flight; completed first so in-flight has newer created_at
    _write_sync_log_row(test_tenant["id"], sp["id"], "done", completed=True)
    in_flight = _write_sync_log_row(test_tenant["id"], sp["id"], "running")

    page = scim_admin.list_sync_log(ru, str(sp["id"]), page=1, page_size=10)
    assert page.total == 2
    assert page.page_size == 10
    # In-flight surfaces first thanks to `completed_at DESC NULLS FIRST`.
    assert page.items[0].id == str(in_flight["id"])


def test_list_sync_log_filters_by_status(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    _write_sync_log_row(test_tenant["id"], sp["id"], "done", completed=True)
    failed = _write_sync_log_row(test_tenant["id"], sp["id"], "failed", completed=True)

    page = scim_admin.list_sync_log(ru, str(sp["id"]), status="failed")
    assert page.total == 1
    assert page.items[0].id == str(failed["id"])


def test_get_queue_status_counts(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )
    dead = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )
    database.scim_push_queue.mark_dead_letter(test_tenant["id"], str(dead["id"]), error="x")

    snap = scim_admin.get_queue_status(ru, str(sp["id"]))
    assert snap.pending == 1
    assert snap.dead_lettered == 1


def test_retry_dead_lettered_revives_rows_and_logs(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    dead_a = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )
    dead_b = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )
    database.scim_push_queue.mark_dead_letter(test_tenant["id"], str(dead_a["id"]), error="a")
    database.scim_push_queue.mark_dead_letter(test_tenant["id"], str(dead_b["id"]), error="b")

    result = scim_admin.retry_dead_lettered(ru, str(sp["id"]))
    assert result.revived == 2

    counts = database.scim_push_queue.count_pending_for_sp(test_tenant["id"], str(sp["id"]))
    assert counts == {"pending": 2, "dead_lettered": 0}

    events = database.fetchall(
        database.UNSCOPED,
        """
        SELECT elm.metadata FROM event_logs el
        JOIN event_log_metadata elm ON elm.metadata_hash = el.metadata_hash
        WHERE el.event_type = 'scim_config_updated' AND el.artifact_id = :sp_id
        """,
        {"sp_id": str(sp["id"])},
    )
    # Must include a retry_dead_lettered action breadcrumb.
    actions = [e["metadata"].get("action") for e in events]
    assert "retry_dead_lettered" in actions


def test_retry_dead_lettered_no_rows_returns_zero(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    result = scim_admin.retry_dead_lettered(ru, str(sp["id"]))
    assert result.revived == 0

    # No-op retry must NOT emit a scim_config_updated audit event.
    events = database.fetchall(
        database.UNSCOPED,
        """
        SELECT el.id FROM event_logs el
        WHERE el.event_type = 'scim_config_updated' AND el.artifact_id = :sp_id
        """,
        {"sp_id": str(sp["id"])},
    )
    assert events == []


# ---------------------------------------------------------------------------
# Authorization boundary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fn,args_factory",
    [
        ("get_scim_config", lambda sp_id: (sp_id,)),
        (
            "update_scim_config",
            lambda sp_id: (sp_id, ScimConfigUpdate(scim_kind="slack")),
        ),
        ("list_credentials", lambda sp_id: (sp_id,)),
        ("create_credential", lambda sp_id: (sp_id,)),
        ("rotate_credential", lambda sp_id: (sp_id, str(uuid4()))),
        ("revoke_credential", lambda sp_id: (sp_id, str(uuid4()))),
        ("list_sync_log", lambda sp_id: (sp_id,)),
        ("get_queue_status", lambda sp_id: (sp_id,)),
        ("retry_dead_lettered", lambda sp_id: (sp_id,)),
    ],
)
@pytest.mark.parametrize("role", ["user", "admin"])
def test_admin_service_requires_super_admin_role(
    fn, args_factory, role, test_tenant, test_admin_user
):
    """SCIM admin service entry points are super_admin-only.

    Both `user` and `admin` roles must be rejected; only `super_admin`
    may invoke them. Iteration 7b promoted these from admin -> super_admin
    after the final-review security pass flagged token operations as too
    sensitive for the admin tier.
    """
    from services.exceptions import ForbiddenError

    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    caller = _requesting_user(test_tenant["id"], test_admin_user["id"], role=role)

    func = getattr(scim_admin, fn)
    with pytest.raises(ForbiddenError):
        func(caller, *args_factory(str(sp["id"])))
