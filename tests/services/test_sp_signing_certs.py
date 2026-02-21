"""Tests for SP signing certificate service functions.

Covers the rotation guard in rotate_sp_signing_certificate() that prevents
initiating a new rotation while one is already in progress.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest
from services.exceptions import NotFoundError, ValidationError


def _make_requesting_user(tenant_id: str | None = None) -> dict:
    """Create a test requesting user with super_admin role."""
    return {
        "id": str(uuid4()),
        "tenant_id": tenant_id or str(uuid4()),
        "role": "super_admin",
        "email": "admin@example.com",
    }


def _make_cert_row(
    sp_id: str | None = None,
    grace_period_ends_at: datetime | None = None,
) -> dict:
    """Create a test certificate database row."""
    return {
        "id": str(uuid4()),
        "sp_id": sp_id or str(uuid4()),
        "tenant_id": str(uuid4()),
        "certificate_pem": "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
        "private_key_pem_enc": "encrypted-key-data",
        "expires_at": datetime.now(UTC) + timedelta(days=365),
        "created_by": str(uuid4()),
        "created_at": datetime.now(UTC),
        "previous_certificate_pem": None,
        "previous_private_key_pem_enc": None,
        "previous_expires_at": None,
        "rotation_grace_period_ends_at": grace_period_ends_at,
    }


# =============================================================================
# Rotation Guard Tests
# =============================================================================


@patch("services.service_providers.signing_certs.log_event")
@patch("services.service_providers.signing_certs.database")
def test_rotation_rejected_when_grace_period_active(mock_database, mock_log_event):
    """Rejects rotation when a grace period is still active (in the future)."""
    from services.service_providers.signing_certs import rotate_sp_signing_certificate

    user = _make_requesting_user()
    sp_id = str(uuid4())

    mock_database.service_providers.get_service_provider.return_value = {
        "id": sp_id,
        "name": "Test SP",
    }
    mock_database.sp_signing_certificates.get_signing_certificate.return_value = _make_cert_row(
        sp_id=sp_id,
        grace_period_ends_at=datetime.now(UTC) + timedelta(days=5),
    )

    with pytest.raises(ValidationError) as exc_info:
        rotate_sp_signing_certificate(user, sp_id)

    assert exc_info.value.code == "sp_signing_certificate_rotation_in_progress"
    assert "already in progress" in exc_info.value.message

    # Should not have attempted to generate a new certificate
    mock_database.sp_signing_certificates.rotate_signing_certificate.assert_not_called()
    mock_log_event.assert_not_called()


@patch("services.service_providers.signing_certs.log_event")
@patch("services.service_providers.signing_certs.database")
def test_rotation_allowed_when_no_grace_period(mock_database, mock_log_event):
    """Allows rotation when rotation_grace_period_ends_at is None."""
    from services.service_providers.signing_certs import rotate_sp_signing_certificate

    user = _make_requesting_user()
    sp_id = str(uuid4())

    mock_database.service_providers.get_service_provider.return_value = {
        "id": sp_id,
        "name": "Test SP",
    }
    mock_database.sp_signing_certificates.get_signing_certificate.return_value = _make_cert_row(
        sp_id=sp_id,
        grace_period_ends_at=None,
    )

    # Mock the certificate generation chain
    with (
        patch(
            "utils.saml.generate_sp_certificate",
            return_value=("new-cert-pem", "new-key-pem"),
        ),
        patch(
            "utils.saml.encrypt_private_key",
            return_value="encrypted-new-key",
        ),
        patch(
            "utils.saml.get_certificate_expiry",
            return_value=datetime.now(UTC) + timedelta(days=3650),
        ),
        patch(
            "services.settings.get_certificate_lifetime",
            return_value=10,
        ),
    ):
        mock_database.sp_signing_certificates.rotate_signing_certificate.return_value = {
            "id": str(uuid4()),
            "sp_id": sp_id,
        }

        result = rotate_sp_signing_certificate(user, sp_id)

    assert result.new_certificate_pem == "new-cert-pem"
    mock_database.sp_signing_certificates.rotate_signing_certificate.assert_called_once()


@patch("services.service_providers.signing_certs.log_event")
@patch("services.service_providers.signing_certs.database")
def test_rotation_allowed_when_grace_period_expired(mock_database, mock_log_event):
    """Allows rotation when grace period has already expired (in the past)."""
    from services.service_providers.signing_certs import rotate_sp_signing_certificate

    user = _make_requesting_user()
    sp_id = str(uuid4())

    mock_database.service_providers.get_service_provider.return_value = {
        "id": sp_id,
        "name": "Test SP",
    }
    mock_database.sp_signing_certificates.get_signing_certificate.return_value = _make_cert_row(
        sp_id=sp_id,
        grace_period_ends_at=datetime.now(UTC) - timedelta(days=1),
    )

    with (
        patch(
            "utils.saml.generate_sp_certificate",
            return_value=("new-cert-pem", "new-key-pem"),
        ),
        patch(
            "utils.saml.encrypt_private_key",
            return_value="encrypted-new-key",
        ),
        patch(
            "utils.saml.get_certificate_expiry",
            return_value=datetime.now(UTC) + timedelta(days=3650),
        ),
        patch(
            "services.settings.get_certificate_lifetime",
            return_value=10,
        ),
    ):
        mock_database.sp_signing_certificates.rotate_signing_certificate.return_value = {
            "id": str(uuid4()),
            "sp_id": sp_id,
        }

        result = rotate_sp_signing_certificate(user, sp_id)

    assert result.new_certificate_pem == "new-cert-pem"
    mock_database.sp_signing_certificates.rotate_signing_certificate.assert_called_once()


@patch("services.service_providers.signing_certs.database")
def test_rotation_fails_when_sp_not_found(mock_database):
    """Raises NotFoundError when SP does not exist."""
    from services.service_providers.signing_certs import rotate_sp_signing_certificate

    user = _make_requesting_user()
    sp_id = str(uuid4())

    mock_database.service_providers.get_service_provider.return_value = None

    with pytest.raises(NotFoundError) as exc_info:
        rotate_sp_signing_certificate(user, sp_id)

    assert exc_info.value.code == "sp_not_found"


@patch("services.service_providers.signing_certs.database")
def test_rotation_fails_when_no_certificate(mock_database):
    """Raises NotFoundError when no certificate exists for the SP."""
    from services.service_providers.signing_certs import rotate_sp_signing_certificate

    user = _make_requesting_user()
    sp_id = str(uuid4())

    mock_database.service_providers.get_service_provider.return_value = {
        "id": sp_id,
        "name": "Test SP",
    }
    mock_database.sp_signing_certificates.get_signing_certificate.return_value = None

    with pytest.raises(NotFoundError) as exc_info:
        rotate_sp_signing_certificate(user, sp_id)

    assert exc_info.value.code == "sp_signing_certificate_not_found"
