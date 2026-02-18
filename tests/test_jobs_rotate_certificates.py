"""Comprehensive tests for the certificate rotation/cleanup job.

This test file covers all functions in jobs/rotate_certificates.py:
- rotate_and_cleanup_certificates() - Main job function
- _rotate_certificate() / _rotate_idp_sp_certificate() - Per-certificate rotation
- _cleanup_certificate() / _cleanup_idp_sp_certificate() - Per-certificate cleanup

Tests verify:
- Certificate detection (rotation vs cleanup) for both cert types
- Auto-rotation with correct parameters
- Grace period cleanup
- Event logging with correct metadata
- Error handling (per-cert errors don't stop processing)
- Tenant certificate lifetime configuration
- Mixed SP signing and per-IdP SP cert processing
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

# =============================================================================
# Helper Functions
# =============================================================================


def _make_cert(
    action: str = "rotate",
    tenant_id: str | None = None,
    sp_id: str | None = None,
    cert_id: str | None = None,
    expires_at: datetime | None = None,
    grace_period_ends_at: datetime | None = None,
) -> dict[str, Any]:
    """Create a test SP signing certificate dict from the database query."""
    return {
        "id": cert_id or str(uuid4()),
        "sp_id": sp_id or str(uuid4()),
        "tenant_id": tenant_id or str(uuid4()),
        "expires_at": expires_at or datetime.now(UTC) + timedelta(days=30),
        "rotation_grace_period_ends_at": grace_period_ends_at,
        "action": action,
    }


def _make_idp_sp_cert(
    action: str = "rotate",
    tenant_id: str | None = None,
    idp_id: str | None = None,
    cert_id: str | None = None,
    expires_at: datetime | None = None,
    grace_period_ends_at: datetime | None = None,
) -> dict[str, Any]:
    """Create a test per-IdP SP certificate dict from the database query."""
    return {
        "id": cert_id or str(uuid4()),
        "idp_id": idp_id or str(uuid4()),
        "tenant_id": tenant_id or str(uuid4()),
        "expires_at": expires_at or datetime.now(UTC) + timedelta(days=30),
        "rotation_grace_period_ends_at": grace_period_ends_at,
        "action": action,
    }


def _make_current_cert(
    sp_id: str | None = None,
) -> dict[str, Any]:
    """Create a full certificate row from get_signing_certificate."""
    return {
        "id": str(uuid4()),
        "sp_id": sp_id or str(uuid4()),
        "tenant_id": str(uuid4()),
        "certificate_pem": "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
        "private_key_pem_enc": "encrypted-current-key",
        "expires_at": datetime.now(UTC) + timedelta(days=30),
        "created_by": str(uuid4()),
        "created_at": datetime.now(UTC),
        "previous_certificate_pem": None,
        "previous_private_key_pem_enc": None,
        "previous_expires_at": None,
        "rotation_grace_period_ends_at": None,
    }


def _make_current_idp_sp_cert(
    idp_id: str | None = None,
) -> dict[str, Any]:
    """Create a full certificate row from get_idp_sp_certificate."""
    return {
        "id": str(uuid4()),
        "idp_id": idp_id or str(uuid4()),
        "tenant_id": str(uuid4()),
        "certificate_pem": "-----BEGIN CERTIFICATE-----\nfake-idp-sp\n-----END CERTIFICATE-----",
        "private_key_pem_enc": "encrypted-idp-sp-key",
        "expires_at": datetime.now(UTC) + timedelta(days=30),
        "created_by": str(uuid4()),
        "created_at": datetime.now(UTC),
        "previous_certificate_pem": None,
        "previous_private_key_pem_enc": None,
        "previous_expires_at": None,
        "rotation_grace_period_ends_at": None,
    }


def _mock_certs_query(mock_db: MagicMock) -> MagicMock:
    """Get the mock for get_certificates_needing_rotation_or_cleanup."""
    return mock_db.sp_signing_certificates.get_certificates_needing_rotation_or_cleanup


def _mock_idp_sp_certs_query(mock_db: MagicMock) -> MagicMock:
    """Get the mock for get_idp_sp_certificates_needing_rotation_or_cleanup."""
    return mock_db.saml.get_idp_sp_certificates_needing_rotation_or_cleanup


def _setup_no_idp_sp_certs(mock_db: MagicMock) -> None:
    """Set up mock to return no IdP SP certs needing attention."""
    _mock_idp_sp_certs_query(mock_db).return_value = []


def _setup_no_sp_certs(mock_db: MagicMock) -> None:
    """Set up mock to return no SP signing certs needing attention."""
    _mock_certs_query(mock_db).return_value = []


def _patch_crypto():
    """Patch certificate generation utilities."""
    return (
        patch(
            "jobs.rotate_certificates.generate_sp_certificate",
            return_value=("new-cert-pem", "new-key-pem"),
        ),
        patch(
            "jobs.rotate_certificates.encrypt_private_key",
            return_value="encrypted-new-key",
        ),
        patch(
            "jobs.rotate_certificates.get_certificate_expiry",
            return_value=datetime.now(UTC) + timedelta(days=3650),
        ),
    )


# =============================================================================
# SP Signing Certificate Tests (existing behavior)
# =============================================================================


@patch("jobs.rotate_certificates.database")
def test_no_certs_needing_attention(mock_database):
    """Returns zeroes when no certificates need attention."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    _mock_certs_query(mock_database).return_value = []
    _setup_no_idp_sp_certs(mock_database)

    result = rotate_and_cleanup_certificates()

    assert result["rotated"] == 0
    assert result["cleaned_up"] == 0
    assert result["errors"] == []
    assert result["sp_rotated"] == 0
    assert result["sp_cleaned_up"] == 0
    assert result["idp_sp_rotated"] == 0
    assert result["idp_sp_cleaned_up"] == 0


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_auto_rotates_cert_expiring_soon(mock_database, mock_session, mock_log_event):
    """Auto-rotates a certificate that expires within 90 days."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    cert = _make_cert(
        action="rotate",
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    _mock_certs_query(mock_database).return_value = [cert]
    _setup_no_idp_sp_certs(mock_database)

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    current = _make_current_cert(sp_id=cert["sp_id"])
    mock_database.sp_signing_certificates.get_signing_certificate.return_value = current
    mock_database.security.get_certificate_lifetime.return_value = 10
    mock_database.security.get_certificate_rotation_window.return_value = 90

    new_expires = datetime.now(UTC) + timedelta(days=3650)
    rotate_result = {"id": str(uuid4()), "sp_id": cert["sp_id"]}
    db_rotate = mock_database.sp_signing_certificates.rotate_signing_certificate
    db_rotate.return_value = rotate_result

    with (
        _patch_crypto()[0],
        _patch_crypto()[1],
        patch(
            "jobs.rotate_certificates.get_certificate_expiry",
            return_value=new_expires,
        ),
    ):
        result = rotate_and_cleanup_certificates()

    assert result["rotated"] == 1
    assert result["cleaned_up"] == 0
    assert result["errors"] == []

    db_rotate.assert_called_once()
    kw = db_rotate.call_args[1]
    assert kw["new_certificate_pem"] == "new-cert-pem"
    assert kw["new_private_key_pem_enc"] == "encrypted-new-key"
    assert kw["new_expires_at"] == new_expires
    assert kw["previous_certificate_pem"] == current["certificate_pem"]
    assert kw["previous_private_key_pem_enc"] == current["private_key_pem_enc"]


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_cleans_up_expired_grace_period(mock_database, mock_session, mock_log_event):
    """Cleans up previous cert data when grace period has expired."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    cert = _make_cert(
        action="cleanup",
        grace_period_ends_at=datetime.now(UTC) - timedelta(days=1),
    )
    _mock_certs_query(mock_database).return_value = [cert]
    _setup_no_idp_sp_certs(mock_database)

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    cleanup_result = {"id": str(uuid4()), "sp_id": cert["sp_id"]}
    db_clear = mock_database.sp_signing_certificates.clear_previous_signing_certificate
    db_clear.return_value = cleanup_result

    result = rotate_and_cleanup_certificates()

    assert result["rotated"] == 0
    assert result["cleaned_up"] == 1
    assert result["errors"] == []

    db_clear.assert_called_once_with(str(cert["tenant_id"]), str(cert["sp_id"]))


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_handles_mixed_certs(mock_database, mock_session, mock_log_event):
    """Handles a mix of certs needing rotation and cleanup."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    rotate_cert = _make_cert(action="rotate")
    cleanup_cert = _make_cert(
        action="cleanup",
        grace_period_ends_at=datetime.now(UTC) - timedelta(days=1),
    )
    _mock_certs_query(mock_database).return_value = [
        rotate_cert,
        cleanup_cert,
    ]
    _setup_no_idp_sp_certs(mock_database)

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    # Setup rotation mocks
    current = _make_current_cert(sp_id=rotate_cert["sp_id"])
    mock_database.sp_signing_certificates.get_signing_certificate.return_value = current
    mock_database.security.get_certificate_lifetime.return_value = 10
    mock_database.security.get_certificate_rotation_window.return_value = 90
    db_rotate = mock_database.sp_signing_certificates.rotate_signing_certificate
    db_rotate.return_value = {
        "id": str(uuid4()),
        "sp_id": rotate_cert["sp_id"],
    }

    # Setup cleanup mocks
    db_clear = mock_database.sp_signing_certificates.clear_previous_signing_certificate
    db_clear.return_value = {
        "id": str(uuid4()),
        "sp_id": cleanup_cert["sp_id"],
    }

    with _patch_crypto()[0], _patch_crypto()[1], _patch_crypto()[2]:
        result = rotate_and_cleanup_certificates()

    assert result["rotated"] == 1
    assert result["cleaned_up"] == 1
    assert result["errors"] == []


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_per_cert_errors_dont_stop_processing(mock_database, mock_session, mock_log_event):
    """A failure on one cert doesn't prevent processing of others."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    cert1 = _make_cert(action="rotate", tenant_id="tenant-1")
    cert2 = _make_cert(action="rotate", tenant_id="tenant-2")
    _mock_certs_query(mock_database).return_value = [cert1, cert2]
    _setup_no_idp_sp_certs(mock_database)

    # First cert fails via session, second succeeds
    def session_side_effect(tenant_id):
        mock_cm = MagicMock()
        mock_cm.__enter__ = MagicMock()
        if tenant_id == str(cert1["tenant_id"]):
            mock_cm.__enter__.side_effect = Exception("DB error")
        mock_cm.__exit__ = MagicMock(return_value=False)
        return mock_cm

    mock_session.side_effect = session_side_effect

    current = _make_current_cert(sp_id=cert2["sp_id"])
    mock_database.sp_signing_certificates.get_signing_certificate.return_value = current
    mock_database.security.get_certificate_lifetime.return_value = 10
    mock_database.security.get_certificate_rotation_window.return_value = 90
    db_rotate = mock_database.sp_signing_certificates.rotate_signing_certificate
    db_rotate.return_value = {
        "id": str(uuid4()),
        "sp_id": cert2["sp_id"],
    }

    with _patch_crypto()[0], _patch_crypto()[1], _patch_crypto()[2]:
        result = rotate_and_cleanup_certificates()

    assert result["rotated"] == 1
    assert len(result["errors"]) == 1
    assert result["errors"][0]["action"] == "rotate"
    assert result["errors"][0]["tenant_id"] == str(cert1["tenant_id"])
    assert "DB error" in result["errors"][0]["error"]


# =============================================================================
# SP Signing Certificate Event Logging Tests
# =============================================================================


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_rotation_event_logging(mock_database, mock_session, mock_log_event):
    """Verifies event logging for auto-rotation includes tenant's rotation window."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    cert = _make_cert(action="rotate")
    _mock_certs_query(mock_database).return_value = [cert]
    _setup_no_idp_sp_certs(mock_database)

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    current = _make_current_cert(sp_id=cert["sp_id"])
    mock_database.sp_signing_certificates.get_signing_certificate.return_value = current
    mock_database.security.get_certificate_lifetime.return_value = 5
    mock_database.security.get_certificate_rotation_window.return_value = 60

    rotate_result_id = str(uuid4())
    db_rotate = mock_database.sp_signing_certificates.rotate_signing_certificate
    db_rotate.return_value = {
        "id": rotate_result_id,
        "sp_id": cert["sp_id"],
    }

    new_expires = datetime.now(UTC) + timedelta(days=1825)

    with (
        _patch_crypto()[0],
        _patch_crypto()[1],
        patch(
            "jobs.rotate_certificates.get_certificate_expiry",
            return_value=new_expires,
        ),
    ):
        rotate_and_cleanup_certificates()

    mock_log_event.assert_called_once()
    kw = mock_log_event.call_args[1]
    assert kw["tenant_id"] == str(cert["tenant_id"])
    assert kw["actor_user_id"] == "00000000-0000-0000-0000-000000000000"
    assert kw["artifact_type"] == "sp_signing_certificate"
    assert kw["artifact_id"] == rotate_result_id
    assert kw["event_type"] == "sp_signing_certificate_auto_rotated"
    assert kw["metadata"]["sp_id"] == str(cert["sp_id"])
    assert kw["metadata"]["grace_period_days"] == 60
    assert kw["metadata"]["validity_years"] == 5
    assert str(new_expires) in kw["metadata"]["new_expires_at"]


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_cleanup_event_logging(mock_database, mock_session, mock_log_event):
    """Verifies event logging for cleanup with correct metadata."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    grace_ended = datetime.now(UTC) - timedelta(days=1)
    cert = _make_cert(
        action="cleanup",
        grace_period_ends_at=grace_ended,
    )
    _mock_certs_query(mock_database).return_value = [cert]
    _setup_no_idp_sp_certs(mock_database)

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    cleanup_result_id = str(uuid4())
    db_clear = mock_database.sp_signing_certificates.clear_previous_signing_certificate
    db_clear.return_value = {
        "id": cleanup_result_id,
        "sp_id": cert["sp_id"],
    }

    rotate_and_cleanup_certificates()

    mock_log_event.assert_called_once()
    kw = mock_log_event.call_args[1]
    assert kw["tenant_id"] == str(cert["tenant_id"])
    assert kw["actor_user_id"] == "00000000-0000-0000-0000-000000000000"
    assert kw["artifact_type"] == "sp_signing_certificate"
    assert kw["artifact_id"] == cleanup_result_id
    assert kw["event_type"] == "sp_signing_certificate_cleanup_completed"
    assert kw["metadata"]["sp_id"] == str(cert["sp_id"])
    assert str(grace_ended) in kw["metadata"]["grace_period_ended_at"]


# =============================================================================
# Tenant Certificate Lifetime Tests
# =============================================================================


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_uses_tenant_certificate_lifetime(mock_database, mock_session, mock_log_event):
    """Uses the tenant's configured lifetime for new certificates."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    cert = _make_cert(action="rotate")
    _mock_certs_query(mock_database).return_value = [cert]
    _setup_no_idp_sp_certs(mock_database)

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    current = _make_current_cert(sp_id=cert["sp_id"])
    mock_database.sp_signing_certificates.get_signing_certificate.return_value = current
    mock_database.security.get_certificate_lifetime.return_value = 3
    mock_database.security.get_certificate_rotation_window.return_value = 90

    db_rotate = mock_database.sp_signing_certificates.rotate_signing_certificate
    db_rotate.return_value = {
        "id": str(uuid4()),
        "sp_id": cert["sp_id"],
    }

    with (
        patch(
            "jobs.rotate_certificates.generate_sp_certificate",
            return_value=("new-cert-pem", "new-key-pem"),
        ) as mock_gen,
        patch(
            "jobs.rotate_certificates.encrypt_private_key",
            return_value="encrypted-new-key",
        ),
        patch(
            "jobs.rotate_certificates.get_certificate_expiry",
            return_value=datetime.now(UTC) + timedelta(days=1095),
        ),
    ):
        rotate_and_cleanup_certificates()

    mock_gen.assert_called_once_with(
        str(cert["tenant_id"]),
        validity_years=3,
    )


# =============================================================================
# SP Signing Edge Cases
# =============================================================================


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_skips_rotation_when_cert_disappears(mock_database, mock_session, mock_log_event):
    """Gracefully handles cert disappearing between query and rotation."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    cert = _make_cert(action="rotate")
    _mock_certs_query(mock_database).return_value = [cert]
    _setup_no_idp_sp_certs(mock_database)

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    mock_database.security.get_certificate_lifetime.return_value = 10
    mock_database.security.get_certificate_rotation_window.return_value = 90
    mock_database.sp_signing_certificates.get_signing_certificate.return_value = None

    with _patch_crypto()[0], _patch_crypto()[1], _patch_crypto()[2]:
        result = rotate_and_cleanup_certificates()

    assert result["rotated"] == 0
    assert result["errors"] == []
    db_rotate = mock_database.sp_signing_certificates.rotate_signing_certificate
    db_rotate.assert_not_called()
    mock_log_event.assert_not_called()


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_skips_cleanup_when_cert_disappears(mock_database, mock_session, mock_log_event):
    """Gracefully handles cert disappearing between query and cleanup."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    cert = _make_cert(
        action="cleanup",
        grace_period_ends_at=datetime.now(UTC) - timedelta(days=1),
    )
    _mock_certs_query(mock_database).return_value = [cert]
    _setup_no_idp_sp_certs(mock_database)

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    db_clear = mock_database.sp_signing_certificates.clear_previous_signing_certificate
    db_clear.return_value = None

    result = rotate_and_cleanup_certificates()

    assert result["cleaned_up"] == 0
    assert result["errors"] == []
    mock_log_event.assert_not_called()


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_cleanup_error_doesnt_stop_rotation(mock_database, mock_session, mock_log_event):
    """Cleanup errors don't prevent rotation of other certificates."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    cleanup_cert = _make_cert(
        action="cleanup",
        tenant_id="tenant-failing",
        grace_period_ends_at=datetime.now(UTC) - timedelta(days=1),
    )
    rotate_cert = _make_cert(
        action="rotate",
        tenant_id="tenant-ok",
    )
    _mock_certs_query(mock_database).return_value = [
        rotate_cert,
        cleanup_cert,
    ]
    _setup_no_idp_sp_certs(mock_database)

    def session_side_effect(tenant_id):
        mock_cm = MagicMock()
        mock_cm.__enter__ = MagicMock()
        if tenant_id == str(cleanup_cert["tenant_id"]):
            mock_cm.__enter__.side_effect = Exception("DB error")
        mock_cm.__exit__ = MagicMock(return_value=False)
        return mock_cm

    mock_session.side_effect = session_side_effect

    current = _make_current_cert(sp_id=rotate_cert["sp_id"])
    mock_database.sp_signing_certificates.get_signing_certificate.return_value = current
    mock_database.security.get_certificate_lifetime.return_value = 10
    mock_database.security.get_certificate_rotation_window.return_value = 90
    db_rotate = mock_database.sp_signing_certificates.rotate_signing_certificate
    db_rotate.return_value = {
        "id": str(uuid4()),
        "sp_id": rotate_cert["sp_id"],
    }

    with _patch_crypto()[0], _patch_crypto()[1], _patch_crypto()[2]:
        result = rotate_and_cleanup_certificates()

    assert result["rotated"] == 1
    assert result["cleaned_up"] == 0
    assert len(result["errors"]) == 1
    assert result["errors"][0]["action"] == "cleanup"


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_rotation_uses_tenant_configured_window(mock_database, mock_session, mock_log_event):
    """Verifies that auto-rotation uses the tenant's configured rotation window."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    cert = _make_cert(action="rotate")
    _mock_certs_query(mock_database).return_value = [cert]
    _setup_no_idp_sp_certs(mock_database)

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    current = _make_current_cert(sp_id=cert["sp_id"])
    mock_database.sp_signing_certificates.get_signing_certificate.return_value = current
    mock_database.security.get_certificate_lifetime.return_value = 10
    mock_database.security.get_certificate_rotation_window.return_value = 30
    db_rotate = mock_database.sp_signing_certificates.rotate_signing_certificate
    db_rotate.return_value = {
        "id": str(uuid4()),
        "sp_id": cert["sp_id"],
    }

    with _patch_crypto()[0], _patch_crypto()[1], _patch_crypto()[2]:
        rotate_and_cleanup_certificates()

    # Verify it fetched the rotation window from DB
    mock_database.security.get_certificate_rotation_window.assert_called_once_with(
        str(cert["tenant_id"])
    )

    kw = db_rotate.call_args[1]
    grace_end = kw["rotation_grace_period_ends_at"]

    # Should be approximately 30 days from now (tenant's configured window)
    expected = datetime.now(UTC) + timedelta(days=30)
    delta = abs((grace_end - expected).total_seconds())
    assert delta < 5  # Within 5 seconds


# =============================================================================
# Per-IdP SP Certificate Tests
# =============================================================================


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_auto_rotates_idp_sp_cert_expiring_soon(mock_database, mock_session, mock_log_event):
    """Auto-rotates a per-IdP SP certificate that expires within the rotation window."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    cert = _make_idp_sp_cert(
        action="rotate",
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    _setup_no_sp_certs(mock_database)
    _mock_idp_sp_certs_query(mock_database).return_value = [cert]

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    current = _make_current_idp_sp_cert(idp_id=cert["idp_id"])
    mock_database.saml.get_idp_sp_certificate.return_value = current
    mock_database.security.get_certificate_lifetime.return_value = 10
    mock_database.security.get_certificate_rotation_window.return_value = 90

    new_expires = datetime.now(UTC) + timedelta(days=3650)
    rotate_result = {"id": str(uuid4()), "idp_id": cert["idp_id"]}
    db_rotate = mock_database.saml.rotate_idp_sp_certificate
    db_rotate.return_value = rotate_result

    with (
        _patch_crypto()[0],
        _patch_crypto()[1],
        patch(
            "jobs.rotate_certificates.get_certificate_expiry",
            return_value=new_expires,
        ),
    ):
        result = rotate_and_cleanup_certificates()

    assert result["rotated"] == 1
    assert result["idp_sp_rotated"] == 1
    assert result["sp_rotated"] == 0
    assert result["cleaned_up"] == 0
    assert result["errors"] == []

    db_rotate.assert_called_once()
    kw = db_rotate.call_args[1]
    assert kw["new_certificate_pem"] == "new-cert-pem"
    assert kw["new_private_key_pem_enc"] == "encrypted-new-key"
    assert kw["new_expires_at"] == new_expires
    assert kw["previous_certificate_pem"] == current["certificate_pem"]
    assert kw["previous_private_key_pem_enc"] == current["private_key_pem_enc"]


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_cleans_up_idp_sp_expired_grace_period(mock_database, mock_session, mock_log_event):
    """Cleans up previous per-IdP SP cert data when grace period has expired."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    cert = _make_idp_sp_cert(
        action="cleanup",
        grace_period_ends_at=datetime.now(UTC) - timedelta(days=1),
    )
    _setup_no_sp_certs(mock_database)
    _mock_idp_sp_certs_query(mock_database).return_value = [cert]

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    cleanup_result = {"id": str(uuid4()), "idp_id": cert["idp_id"]}
    db_clear = mock_database.saml.clear_previous_idp_sp_certificate
    db_clear.return_value = cleanup_result

    result = rotate_and_cleanup_certificates()

    assert result["rotated"] == 0
    assert result["cleaned_up"] == 1
    assert result["idp_sp_cleaned_up"] == 1
    assert result["sp_cleaned_up"] == 0
    assert result["errors"] == []

    db_clear.assert_called_once_with(str(cert["tenant_id"]), str(cert["idp_id"]))


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_idp_sp_rotation_event_logging(mock_database, mock_session, mock_log_event):
    """Verifies event logging for per-IdP SP auto-rotation."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    cert = _make_idp_sp_cert(action="rotate")
    _setup_no_sp_certs(mock_database)
    _mock_idp_sp_certs_query(mock_database).return_value = [cert]

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    current = _make_current_idp_sp_cert(idp_id=cert["idp_id"])
    mock_database.saml.get_idp_sp_certificate.return_value = current
    mock_database.security.get_certificate_lifetime.return_value = 5
    mock_database.security.get_certificate_rotation_window.return_value = 60

    rotate_result_id = str(uuid4())
    db_rotate = mock_database.saml.rotate_idp_sp_certificate
    db_rotate.return_value = {
        "id": rotate_result_id,
        "idp_id": cert["idp_id"],
    }

    new_expires = datetime.now(UTC) + timedelta(days=1825)

    with (
        _patch_crypto()[0],
        _patch_crypto()[1],
        patch(
            "jobs.rotate_certificates.get_certificate_expiry",
            return_value=new_expires,
        ),
    ):
        rotate_and_cleanup_certificates()

    mock_log_event.assert_called_once()
    kw = mock_log_event.call_args[1]
    assert kw["tenant_id"] == str(cert["tenant_id"])
    assert kw["actor_user_id"] == "00000000-0000-0000-0000-000000000000"
    assert kw["artifact_type"] == "saml_idp_sp_certificate"
    assert kw["artifact_id"] == rotate_result_id
    assert kw["event_type"] == "saml_idp_sp_certificate_auto_rotated"
    assert kw["metadata"]["idp_id"] == str(cert["idp_id"])
    assert kw["metadata"]["grace_period_days"] == 60
    assert kw["metadata"]["validity_years"] == 5
    assert str(new_expires) in kw["metadata"]["new_expires_at"]


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_idp_sp_cleanup_event_logging(mock_database, mock_session, mock_log_event):
    """Verifies event logging for per-IdP SP cleanup with correct metadata."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    grace_ended = datetime.now(UTC) - timedelta(days=1)
    cert = _make_idp_sp_cert(
        action="cleanup",
        grace_period_ends_at=grace_ended,
    )
    _setup_no_sp_certs(mock_database)
    _mock_idp_sp_certs_query(mock_database).return_value = [cert]

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    cleanup_result_id = str(uuid4())
    db_clear = mock_database.saml.clear_previous_idp_sp_certificate
    db_clear.return_value = {
        "id": cleanup_result_id,
        "idp_id": cert["idp_id"],
    }

    rotate_and_cleanup_certificates()

    mock_log_event.assert_called_once()
    kw = mock_log_event.call_args[1]
    assert kw["tenant_id"] == str(cert["tenant_id"])
    assert kw["actor_user_id"] == "00000000-0000-0000-0000-000000000000"
    assert kw["artifact_type"] == "saml_idp_sp_certificate"
    assert kw["artifact_id"] == cleanup_result_id
    assert kw["event_type"] == "saml_idp_sp_certificate_cleanup_completed"
    assert kw["metadata"]["idp_id"] == str(cert["idp_id"])
    assert str(grace_ended) in kw["metadata"]["grace_period_ended_at"]


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_idp_sp_uses_tenant_certificate_lifetime(mock_database, mock_session, mock_log_event):
    """Uses the tenant's configured lifetime for new per-IdP SP certificates."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    cert = _make_idp_sp_cert(action="rotate")
    _setup_no_sp_certs(mock_database)
    _mock_idp_sp_certs_query(mock_database).return_value = [cert]

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    current = _make_current_idp_sp_cert(idp_id=cert["idp_id"])
    mock_database.saml.get_idp_sp_certificate.return_value = current
    mock_database.security.get_certificate_lifetime.return_value = 3
    mock_database.security.get_certificate_rotation_window.return_value = 90

    db_rotate = mock_database.saml.rotate_idp_sp_certificate
    db_rotate.return_value = {
        "id": str(uuid4()),
        "idp_id": cert["idp_id"],
    }

    with (
        patch(
            "jobs.rotate_certificates.generate_sp_certificate",
            return_value=("new-cert-pem", "new-key-pem"),
        ) as mock_gen,
        patch(
            "jobs.rotate_certificates.encrypt_private_key",
            return_value="encrypted-new-key",
        ),
        patch(
            "jobs.rotate_certificates.get_certificate_expiry",
            return_value=datetime.now(UTC) + timedelta(days=1095),
        ),
    ):
        rotate_and_cleanup_certificates()

    mock_gen.assert_called_once_with(
        str(cert["tenant_id"]),
        validity_years=3,
    )


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_idp_sp_skips_rotation_when_cert_disappears(mock_database, mock_session, mock_log_event):
    """Gracefully handles per-IdP SP cert disappearing between query and rotation."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    cert = _make_idp_sp_cert(action="rotate")
    _setup_no_sp_certs(mock_database)
    _mock_idp_sp_certs_query(mock_database).return_value = [cert]

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    mock_database.security.get_certificate_lifetime.return_value = 10
    mock_database.security.get_certificate_rotation_window.return_value = 90
    mock_database.saml.get_idp_sp_certificate.return_value = None

    with _patch_crypto()[0], _patch_crypto()[1], _patch_crypto()[2]:
        result = rotate_and_cleanup_certificates()

    assert result["rotated"] == 0
    assert result["idp_sp_rotated"] == 0
    assert result["errors"] == []
    db_rotate = mock_database.saml.rotate_idp_sp_certificate
    db_rotate.assert_not_called()
    mock_log_event.assert_not_called()


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_idp_sp_skips_cleanup_when_cert_disappears(mock_database, mock_session, mock_log_event):
    """Gracefully handles per-IdP SP cert disappearing between query and cleanup."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    cert = _make_idp_sp_cert(
        action="cleanup",
        grace_period_ends_at=datetime.now(UTC) - timedelta(days=1),
    )
    _setup_no_sp_certs(mock_database)
    _mock_idp_sp_certs_query(mock_database).return_value = [cert]

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    db_clear = mock_database.saml.clear_previous_idp_sp_certificate
    db_clear.return_value = None

    result = rotate_and_cleanup_certificates()

    assert result["cleaned_up"] == 0
    assert result["idp_sp_cleaned_up"] == 0
    assert result["errors"] == []
    mock_log_event.assert_not_called()


# =============================================================================
# Mixed SP signing + Per-IdP SP Certificate Tests
# =============================================================================


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_mixed_sp_and_idp_sp_certs(mock_database, mock_session, mock_log_event):
    """Both SP signing and per-IdP SP certs processed in same run."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    sp_cert = _make_cert(action="rotate")
    idp_sp_cert = _make_idp_sp_cert(action="rotate")

    _mock_certs_query(mock_database).return_value = [sp_cert]
    _mock_idp_sp_certs_query(mock_database).return_value = [idp_sp_cert]

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    # SP signing mocks
    sp_current = _make_current_cert(sp_id=sp_cert["sp_id"])
    mock_database.sp_signing_certificates.get_signing_certificate.return_value = sp_current
    mock_database.security.get_certificate_lifetime.return_value = 10
    mock_database.security.get_certificate_rotation_window.return_value = 90
    db_sp_rotate = mock_database.sp_signing_certificates.rotate_signing_certificate
    db_sp_rotate.return_value = {
        "id": str(uuid4()),
        "sp_id": sp_cert["sp_id"],
    }

    # IdP SP mocks
    idp_sp_current = _make_current_idp_sp_cert(idp_id=idp_sp_cert["idp_id"])
    mock_database.saml.get_idp_sp_certificate.return_value = idp_sp_current
    db_idp_sp_rotate = mock_database.saml.rotate_idp_sp_certificate
    db_idp_sp_rotate.return_value = {
        "id": str(uuid4()),
        "idp_id": idp_sp_cert["idp_id"],
    }

    with _patch_crypto()[0], _patch_crypto()[1], _patch_crypto()[2]:
        result = rotate_and_cleanup_certificates()

    assert result["rotated"] == 2
    assert result["sp_rotated"] == 1
    assert result["idp_sp_rotated"] == 1
    assert result["cleaned_up"] == 0
    assert result["errors"] == []

    db_sp_rotate.assert_called_once()
    db_idp_sp_rotate.assert_called_once()


@patch("jobs.rotate_certificates.log_event")
@patch("jobs.rotate_certificates.session")
@patch("jobs.rotate_certificates.database")
def test_idp_sp_errors_dont_stop_sp_processing(mock_database, mock_session, mock_log_event):
    """IdP SP errors don't prevent SP signing certificate processing."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    sp_cert = _make_cert(action="rotate", tenant_id="tenant-sp")
    idp_sp_cert = _make_idp_sp_cert(action="rotate", tenant_id="tenant-idp-sp")

    _mock_certs_query(mock_database).return_value = [sp_cert]
    _mock_idp_sp_certs_query(mock_database).return_value = [idp_sp_cert]

    # SP signing succeeds, IdP SP fails
    def session_side_effect(tenant_id):
        mock_cm = MagicMock()
        mock_cm.__enter__ = MagicMock()
        if tenant_id == str(idp_sp_cert["tenant_id"]):
            mock_cm.__enter__.side_effect = Exception("IdP SP DB error")
        mock_cm.__exit__ = MagicMock(return_value=False)
        return mock_cm

    mock_session.side_effect = session_side_effect

    # SP signing mocks
    sp_current = _make_current_cert(sp_id=sp_cert["sp_id"])
    mock_database.sp_signing_certificates.get_signing_certificate.return_value = sp_current
    mock_database.security.get_certificate_lifetime.return_value = 10
    mock_database.security.get_certificate_rotation_window.return_value = 90
    db_sp_rotate = mock_database.sp_signing_certificates.rotate_signing_certificate
    db_sp_rotate.return_value = {
        "id": str(uuid4()),
        "sp_id": sp_cert["sp_id"],
    }

    with _patch_crypto()[0], _patch_crypto()[1], _patch_crypto()[2]:
        result = rotate_and_cleanup_certificates()

    assert result["rotated"] == 1
    assert result["sp_rotated"] == 1
    assert result["idp_sp_rotated"] == 0
    assert len(result["errors"]) == 1
    assert result["errors"][0]["cert_type"] == "idp_sp"
    assert "IdP SP DB error" in result["errors"][0]["error"]


@patch("jobs.rotate_certificates.database")
def test_summary_includes_both_cert_types(mock_database):
    """Return summary includes per-type counts."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    _mock_certs_query(mock_database).return_value = []
    _mock_idp_sp_certs_query(mock_database).return_value = []

    result = rotate_and_cleanup_certificates()

    # Verify all expected keys are present
    assert "rotated" in result
    assert "cleaned_up" in result
    assert "errors" in result
    assert "sp_rotated" in result
    assert "sp_cleaned_up" in result
    assert "idp_sp_rotated" in result
    assert "idp_sp_cleaned_up" in result
