"""Integration tests for database certificate modules.

Covers:
- database.saml.idp_certificates (untested functions)
- database.sp_signing_certificates (untested functions)
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import database


def _create_idp(tenant, user, name="Test IdP"):
    """Create a SAML IdP record for testing."""
    return database.fetchone(
        tenant["id"],
        """
        INSERT INTO saml_identity_providers (
            tenant_id, name, provider_type, entity_id, sso_url,
            certificate_pem, sp_entity_id, created_by
        ) VALUES (
            :tenant_id, :name, 'generic', :entity_id,
            'https://idp.example.com/sso', 'cert-placeholder',
            'https://sp.example.com', :created_by
        ) RETURNING id, name
        """,
        {
            "tenant_id": tenant["id"],
            "name": name,
            "entity_id": f"https://idp-{uuid4().hex[:8]}.example.com",
            "created_by": user["id"],
        },
    )


def _create_sp(tenant, user, name="Test SP"):
    """Create a service provider for testing."""
    return database.service_providers.create_service_provider(
        tenant_id=tenant["id"],
        tenant_id_value=str(tenant["id"]),
        name=name,
        created_by=str(user["id"]),
    )


def _create_idp_cert(tenant, idp, suffix="A"):
    """Create an IdP certificate with a unique fingerprint."""
    return database.saml.create_idp_certificate(
        tenant_id=tenant["id"],
        idp_id=str(idp["id"]),
        tenant_id_value=str(tenant["id"]),
        certificate_pem=f"-----BEGIN CERTIFICATE-----\nCERT_{suffix}\n-----END CERTIFICATE-----",
        fingerprint=f"AA:BB:CC:{uuid4().hex[:8].upper()}",
        expires_at=datetime.now(UTC) + timedelta(days=365),
    )


# =============================================================================
# database.saml.idp_certificates
# =============================================================================


# -- get_idp_certificate -------------------------------------------------------


def test_get_idp_certificate_returns_by_id(test_tenant, test_user):
    """Test retrieving an IdP certificate by its ID."""
    idp = _create_idp(test_tenant, test_user)
    cert = _create_idp_cert(test_tenant, idp)

    result = database.saml.get_idp_certificate(test_tenant["id"], str(cert["id"]))

    assert result is not None
    assert result["id"] == cert["id"]
    assert result["certificate_pem"] == cert["certificate_pem"]
    assert result["fingerprint"] == cert["fingerprint"]
    assert str(result["idp_id"]) == str(idp["id"])


def test_get_idp_certificate_returns_none_when_not_found(test_tenant):
    """Test that get_idp_certificate returns None for an unknown ID."""
    result = database.saml.get_idp_certificate(test_tenant["id"], str(uuid4()))

    assert result is None


# -- get_idp_certificate_by_fingerprint ----------------------------------------


def test_get_idp_certificate_by_fingerprint_returns_match(test_tenant, test_user):
    """Test retrieving a certificate by fingerprint for duplicate detection."""
    idp = _create_idp(test_tenant, test_user)
    cert = _create_idp_cert(test_tenant, idp)

    result = database.saml.get_idp_certificate_by_fingerprint(
        test_tenant["id"], str(idp["id"]), cert["fingerprint"]
    )

    assert result is not None
    assert result["id"] == cert["id"]
    assert result["fingerprint"] == cert["fingerprint"]


def test_get_idp_certificate_by_fingerprint_returns_none_for_wrong_idp(test_tenant, test_user):
    """Test that fingerprint lookup is scoped to the correct IdP."""
    idp_a = _create_idp(test_tenant, test_user, name="IdP A")
    idp_b = _create_idp(test_tenant, test_user, name="IdP B")
    cert = _create_idp_cert(test_tenant, idp_a)

    # Same fingerprint but different IdP should not match
    result = database.saml.get_idp_certificate_by_fingerprint(
        test_tenant["id"], str(idp_b["id"]), cert["fingerprint"]
    )

    assert result is None


def test_get_idp_certificate_by_fingerprint_returns_none_when_not_found(test_tenant, test_user):
    """Test that a non-existent fingerprint returns None."""
    idp = _create_idp(test_tenant, test_user)

    result = database.saml.get_idp_certificate_by_fingerprint(
        test_tenant["id"], str(idp["id"]), "NO:SUCH:FINGERPRINT"
    )

    assert result is None


# -- delete_idp_certificate ----------------------------------------------------


def test_delete_idp_certificate_returns_true(test_tenant, test_user):
    """Test that deleting an existing certificate returns True."""
    idp = _create_idp(test_tenant, test_user)
    cert = _create_idp_cert(test_tenant, idp)

    result = database.saml.delete_idp_certificate(test_tenant["id"], str(cert["id"]))

    assert result is True
    assert database.saml.get_idp_certificate(test_tenant["id"], str(cert["id"])) is None


def test_delete_idp_certificate_returns_false_when_not_found(test_tenant):
    """Test that deleting a non-existent certificate returns False."""
    result = database.saml.delete_idp_certificate(test_tenant["id"], str(uuid4()))

    assert result is False


# -- update_idp_certificate_fingerprint ----------------------------------------


def test_update_idp_certificate_fingerprint(test_tenant, test_user):
    """Test backfilling fingerprint and expiry on an existing certificate."""
    idp = _create_idp(test_tenant, test_user)
    cert = _create_idp_cert(test_tenant, idp)

    new_fingerprint = "FF:EE:DD:CC:BB:AA:99:88"
    new_expires_at = datetime.now(UTC) + timedelta(days=730)

    updated = database.saml.update_idp_certificate_fingerprint(
        test_tenant["id"], str(cert["id"]), new_fingerprint, new_expires_at
    )

    assert updated is not None
    assert updated["fingerprint"] == new_fingerprint
    assert updated["expires_at"].date() == new_expires_at.date()
    assert updated["id"] == cert["id"]


def test_update_idp_certificate_fingerprint_returns_none_when_not_found(test_tenant):
    """Test that updating a non-existent certificate returns None."""
    result = database.saml.update_idp_certificate_fingerprint(
        test_tenant["id"],
        str(uuid4()),
        "AA:BB:CC",
        datetime.now(UTC) + timedelta(days=365),
    )

    assert result is None


# =============================================================================
# database.sp_signing_certificates
# =============================================================================


# -- create_signing_certificate ------------------------------------------------


def test_create_signing_certificate(test_tenant, test_user):
    """Test creating a signing certificate for a service provider."""
    sp = _create_sp(test_tenant, test_user)
    expires_at = datetime.now(UTC) + timedelta(days=365)

    cert = database.sp_signing_certificates.create_signing_certificate(
        tenant_id=test_tenant["id"],
        sp_id=str(sp["id"]),
        tenant_id_value=str(test_tenant["id"]),
        certificate_pem="-----BEGIN CERTIFICATE-----\nCERT_DATA\n-----END CERTIFICATE-----",
        private_key_pem_enc="ENCRYPTED_KEY_DATA",
        expires_at=expires_at,
        created_by=str(test_user["id"]),
    )

    assert cert is not None
    assert str(cert["sp_id"]) == str(sp["id"])
    expected_pem = "-----BEGIN CERTIFICATE-----\nCERT_DATA\n-----END CERTIFICATE-----"
    assert cert["certificate_pem"] == expected_pem
    assert cert["private_key_pem_enc"] == "ENCRYPTED_KEY_DATA"
    assert cert["expires_at"].date() == expires_at.date()
    assert str(cert["created_by"]) == str(test_user["id"])
    assert cert["id"] is not None
    assert cert["created_at"] is not None


def test_create_signing_certificate_readable_via_get(test_tenant, test_user):
    """Test that a created certificate is retrievable via get_signing_certificate."""
    sp = _create_sp(test_tenant, test_user, name="Get After Create SP")

    database.sp_signing_certificates.create_signing_certificate(
        tenant_id=test_tenant["id"],
        sp_id=str(sp["id"]),
        tenant_id_value=str(test_tenant["id"]),
        certificate_pem="CERT_PEM",
        private_key_pem_enc="KEY_ENC",
        expires_at=datetime.now(UTC) + timedelta(days=365),
        created_by=str(test_user["id"]),
    )

    fetched = database.sp_signing_certificates.get_signing_certificate(
        test_tenant["id"], str(sp["id"])
    )

    assert fetched is not None
    assert fetched["certificate_pem"] == "CERT_PEM"
    assert fetched["previous_certificate_pem"] is None
    assert fetched["rotation_grace_period_ends_at"] is None


# -- rotate_signing_certificate ------------------------------------------------


def test_rotate_signing_certificate_moves_current_to_previous(test_tenant, test_user):
    """Test that rotation moves current cert to previous_* columns."""
    sp = _create_sp(test_tenant, test_user, name="Rotate SP")
    original_expires = datetime.now(UTC) + timedelta(days=365)

    # Create initial certificate
    database.sp_signing_certificates.create_signing_certificate(
        tenant_id=test_tenant["id"],
        sp_id=str(sp["id"]),
        tenant_id_value=str(test_tenant["id"]),
        certificate_pem="OLD_CERT_PEM",
        private_key_pem_enc="OLD_KEY_ENC",
        expires_at=original_expires,
        created_by=str(test_user["id"]),
    )

    new_expires = datetime.now(UTC) + timedelta(days=730)
    grace_ends = datetime.now(UTC) + timedelta(days=7)

    rotated = database.sp_signing_certificates.rotate_signing_certificate(
        tenant_id=test_tenant["id"],
        sp_id=str(sp["id"]),
        new_certificate_pem="NEW_CERT_PEM",
        new_private_key_pem_enc="NEW_KEY_ENC",
        new_expires_at=new_expires,
        previous_certificate_pem="OLD_CERT_PEM",
        previous_private_key_pem_enc="OLD_KEY_ENC",
        previous_expires_at=original_expires,
        rotation_grace_period_ends_at=grace_ends,
    )

    assert rotated is not None
    assert rotated["certificate_pem"] == "NEW_CERT_PEM"
    assert rotated["private_key_pem_enc"] == "NEW_KEY_ENC"
    assert rotated["expires_at"].date() == new_expires.date()
    assert rotated["previous_certificate_pem"] == "OLD_CERT_PEM"
    assert rotated["previous_private_key_pem_enc"] == "OLD_KEY_ENC"
    assert rotated["previous_expires_at"].date() == original_expires.date()
    assert rotated["rotation_grace_period_ends_at"].date() == grace_ends.date()


def test_rotate_signing_certificate_returns_none_when_sp_not_found(test_tenant):
    """Test that rotating a non-existent SP's certificate returns None."""
    result = database.sp_signing_certificates.rotate_signing_certificate(
        tenant_id=test_tenant["id"],
        sp_id=str(uuid4()),
        new_certificate_pem="NEW_CERT",
        new_private_key_pem_enc="NEW_KEY",
        new_expires_at=datetime.now(UTC) + timedelta(days=365),
        previous_certificate_pem="OLD_CERT",
        previous_private_key_pem_enc="OLD_KEY",
        previous_expires_at=datetime.now(UTC),
        rotation_grace_period_ends_at=datetime.now(UTC) + timedelta(days=7),
    )

    assert result is None


# -- clear_previous_signing_certificate ----------------------------------------


def test_clear_previous_signing_certificate_nulls_rotation_fields(test_tenant, test_user):
    """Test that cleanup nulls the previous_* columns after grace period ends."""
    sp = _create_sp(test_tenant, test_user, name="Clear SP")
    original_expires = datetime.now(UTC) + timedelta(days=365)

    database.sp_signing_certificates.create_signing_certificate(
        tenant_id=test_tenant["id"],
        sp_id=str(sp["id"]),
        tenant_id_value=str(test_tenant["id"]),
        certificate_pem="OLD_CERT",
        private_key_pem_enc="OLD_KEY",
        expires_at=original_expires,
        created_by=str(test_user["id"]),
    )

    # Rotate with a grace period already in the past
    past_grace = datetime.now(UTC) - timedelta(seconds=1)
    database.sp_signing_certificates.rotate_signing_certificate(
        tenant_id=test_tenant["id"],
        sp_id=str(sp["id"]),
        new_certificate_pem="NEW_CERT",
        new_private_key_pem_enc="NEW_KEY",
        new_expires_at=datetime.now(UTC) + timedelta(days=730),
        previous_certificate_pem="OLD_CERT",
        previous_private_key_pem_enc="OLD_KEY",
        previous_expires_at=original_expires,
        rotation_grace_period_ends_at=past_grace,
    )

    cleared = database.sp_signing_certificates.clear_previous_signing_certificate(
        test_tenant["id"], str(sp["id"])
    )

    assert cleared is not None
    assert cleared["previous_certificate_pem"] is None
    assert cleared["previous_private_key_pem_enc"] is None
    assert cleared["previous_expires_at"] is None
    assert cleared["rotation_grace_period_ends_at"] is None
    # New cert should still be in place
    assert cleared["certificate_pem"] == "NEW_CERT"


def test_clear_previous_signing_certificate_returns_none_when_grace_not_expired(
    test_tenant, test_user
):
    """Test that cleanup is a no-op when grace period has not yet ended."""
    sp = _create_sp(test_tenant, test_user, name="Active Grace SP")
    original_expires = datetime.now(UTC) + timedelta(days=365)

    database.sp_signing_certificates.create_signing_certificate(
        tenant_id=test_tenant["id"],
        sp_id=str(sp["id"]),
        tenant_id_value=str(test_tenant["id"]),
        certificate_pem="OLD_CERT",
        private_key_pem_enc="OLD_KEY",
        expires_at=original_expires,
        created_by=str(test_user["id"]),
    )

    # Rotate with a future grace period
    future_grace = datetime.now(UTC) + timedelta(days=7)
    database.sp_signing_certificates.rotate_signing_certificate(
        tenant_id=test_tenant["id"],
        sp_id=str(sp["id"]),
        new_certificate_pem="NEW_CERT",
        new_private_key_pem_enc="NEW_KEY",
        new_expires_at=datetime.now(UTC) + timedelta(days=730),
        previous_certificate_pem="OLD_CERT",
        previous_private_key_pem_enc="OLD_KEY",
        previous_expires_at=original_expires,
        rotation_grace_period_ends_at=future_grace,
    )

    # Grace period still active - should return None (WHERE condition fails)
    result = database.sp_signing_certificates.clear_previous_signing_certificate(
        test_tenant["id"], str(sp["id"])
    )

    assert result is None
