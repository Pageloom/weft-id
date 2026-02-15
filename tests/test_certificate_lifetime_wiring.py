"""Tests that certificate generation call sites use the configured lifetime setting.

These tests verify that all four call sites that generate certificates
consult the tenant's certificate lifetime setting and pass the correct
validity_years to generate_sp_certificate().
"""

from datetime import UTC, datetime
from unittest.mock import patch

NOW = datetime.now(UTC)


def _mock_generate_cert(*args, **kwargs):
    """Return a fake cert/key pair for testing."""
    return ("FAKE_CERT_PEM", "FAKE_KEY_PEM")


# =============================================================================
# saml/certificates.py - get_or_create_sp_certificate
# =============================================================================


def test_get_or_create_sp_certificate_uses_configured_lifetime(test_tenant, test_super_admin_user):
    """get_or_create_sp_certificate passes validity_years from setting."""
    requesting_user = {
        "id": str(test_super_admin_user["id"]),
        "tenant_id": test_tenant["id"],
        "role": "super_admin",
    }

    with (
        patch("services.saml.certificates.database") as mock_db,
        patch(
            "services.saml.certificates.generate_sp_certificate",
            side_effect=_mock_generate_cert,
        ) as mock_gen,
        patch("services.saml.certificates.encrypt_private_key", return_value=b"enc"),
        patch("services.saml.certificates.get_certificate_expiry", return_value=NOW),
        patch("services.settings.database") as mock_settings_db,
        patch("services.saml.certificates.log_event"),
    ):
        mock_db.saml.get_sp_certificate.return_value = None
        mock_db.saml.create_sp_certificate.return_value = {
            "id": "cert-id",
            "certificate_pem": "FAKE_CERT_PEM",
            "expires_at": NOW,
            "created_at": NOW,
        }
        mock_settings_db.security.get_certificate_lifetime.return_value = 3

        from services.saml.certificates import get_or_create_sp_certificate

        get_or_create_sp_certificate(requesting_user)

        mock_gen.assert_called_once_with(test_tenant["id"], validity_years=3)


# =============================================================================
# saml/certificates.py - rotate_sp_certificate
# =============================================================================


def test_rotate_sp_certificate_uses_configured_lifetime(test_tenant, test_super_admin_user):
    """rotate_sp_certificate passes validity_years from setting."""
    requesting_user = {
        "id": str(test_super_admin_user["id"]),
        "tenant_id": test_tenant["id"],
        "role": "super_admin",
    }

    with (
        patch("services.saml.certificates.database") as mock_db,
        patch(
            "services.saml.certificates.generate_sp_certificate",
            side_effect=_mock_generate_cert,
        ) as mock_gen,
        patch("services.saml.certificates.encrypt_private_key", return_value=b"enc"),
        patch("services.saml.certificates.get_certificate_expiry", return_value=NOW),
        patch("services.settings.database") as mock_settings_db,
        patch("services.saml.certificates.log_event"),
    ):
        mock_db.saml.get_sp_certificate.return_value = {
            "id": "old-cert-id",
            "certificate_pem": "OLD_CERT",
            "private_key_pem_enc": b"old_enc",
            "expires_at": NOW,
        }
        mock_db.saml.rotate_sp_certificate.return_value = {
            "id": "new-cert-id",
        }
        mock_settings_db.security.get_certificate_lifetime.return_value = 5

        from services.saml.certificates import rotate_sp_certificate

        rotate_sp_certificate(requesting_user)

        mock_gen.assert_called_once_with(test_tenant["id"], validity_years=5)


# =============================================================================
# service_providers/crud.py - _get_or_create_sp_signing_certificate
# =============================================================================


def test_get_or_create_sp_signing_certificate_uses_configured_lifetime(
    test_tenant, test_super_admin_user
):
    """_get_or_create_sp_signing_certificate passes validity_years from setting."""
    with (
        patch("services.service_providers.crud.database") as mock_db,
        patch(
            "utils.saml.generate_sp_certificate",
            side_effect=_mock_generate_cert,
        ) as mock_gen,
        patch("utils.saml.encrypt_private_key", return_value=b"enc"),
        patch("utils.saml.get_certificate_expiry", return_value=NOW),
        patch("services.settings.database") as mock_settings_db,
        patch("services.service_providers.crud.log_event"),
    ):
        mock_db.sp_signing_certificates.get_signing_certificate.return_value = None
        mock_db.sp_signing_certificates.create_signing_certificate.return_value = {
            "id": "cert-id",
        }
        mock_settings_db.security.get_certificate_lifetime.return_value = 2

        from services.service_providers.crud import _get_or_create_sp_signing_certificate

        _get_or_create_sp_signing_certificate(
            test_tenant["id"], "sp-id", str(test_super_admin_user["id"])
        )

        mock_gen.assert_called_once_with(test_tenant["id"], validity_years=2)


# =============================================================================
# service_providers/signing_certs.py - rotate_sp_signing_certificate
# =============================================================================


def test_rotate_sp_signing_certificate_uses_configured_lifetime(test_tenant, test_super_admin_user):
    """rotate_sp_signing_certificate passes validity_years from setting."""
    requesting_user = {
        "id": str(test_super_admin_user["id"]),
        "tenant_id": test_tenant["id"],
        "role": "super_admin",
    }

    with (
        patch("services.service_providers.signing_certs.database") as mock_db,
        patch(
            "utils.saml.generate_sp_certificate",
            side_effect=_mock_generate_cert,
        ) as mock_gen,
        patch("utils.saml.encrypt_private_key", return_value=b"enc"),
        patch("utils.saml.get_certificate_expiry", return_value=NOW),
        patch("services.settings.database") as mock_settings_db,
        patch("services.service_providers.signing_certs.log_event"),
    ):
        mock_db.service_providers.get_service_provider.return_value = {
            "id": "sp-id",
            "name": "Test SP",
        }
        mock_db.sp_signing_certificates.get_signing_certificate.return_value = {
            "id": "old-cert-id",
            "certificate_pem": "OLD_CERT",
            "private_key_pem_enc": b"old_enc",
            "expires_at": NOW,
        }
        mock_db.sp_signing_certificates.rotate_signing_certificate.return_value = {
            "id": "new-cert-id",
        }
        mock_settings_db.security.get_certificate_lifetime.return_value = 1

        from services.service_providers.signing_certs import rotate_sp_signing_certificate

        rotate_sp_signing_certificate(requesting_user, "sp-id")

        mock_gen.assert_called_once_with(test_tenant["id"], validity_years=1)
