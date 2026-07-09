"""Integration tests for the worker-sweep cross-tenant accessors (migration 0055).

These four listing queries power periodic worker jobs (certificate
auto-rotation/cleanup, SAML metadata refresh, idle-user inactivation). Their
tables have strict RLS policies that fail closed on unscoped reads, so the
queries route through SECURITY DEFINER functions. Tests connect as appuser --
the same role the worker uses -- so they exercise the exact production path:
before migration 0055 every one of these queries silently returned zero rows.

Assertions are membership-based (filtered to this test's tenants) because the
suite runs in parallel and other tests may plant their own rows.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import database
import pytest


@pytest.fixture
def second_tenant():
    """A second tenant proving the accessors see across tenants in one query."""
    subdomain = f"sweep-{uuid4().hex[:8]}"
    tenant = database.fetchone(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id, subdomain, name",
        {"s": subdomain, "n": "Sweep Second Tenant"},
    )
    yield tenant
    database.execute(
        database.UNSCOPED,
        "DELETE FROM tenants WHERE id = :id",
        {"id": tenant["id"]},
    )


def _create_sp(tenant, user, name="Sweep SP"):
    return database.service_providers.create_service_provider(
        tenant_id=tenant["id"],
        tenant_id_value=str(tenant["id"]),
        name=name,
        created_by=str(user["id"]),
    )


def _create_sp_cert(tenant, sp, user, expires_in_days: int):
    return database.sp_signing_certificates.create_signing_certificate(
        tenant_id=tenant["id"],
        sp_id=str(sp["id"]),
        tenant_id_value=str(tenant["id"]),
        certificate_pem="-----BEGIN CERTIFICATE-----\nSWEEP\n-----END CERTIFICATE-----",
        private_key_pem_enc="enc-material",
        expires_at=datetime.now(UTC) + timedelta(days=expires_in_days),
        created_by=str(user["id"]),
    )


def _create_idp(tenant, user, name="Sweep IdP", metadata_url=None):
    return database.fetchone(
        tenant["id"],
        """
        INSERT INTO saml_identity_providers (
            tenant_id, name, provider_type, entity_id, sso_url,
            certificate_pem, sp_entity_id, metadata_url, created_by
        ) VALUES (
            :tenant_id, :name, 'generic', :entity_id,
            'https://idp.example.com/sso', 'cert-placeholder',
            'https://sp.example.com', :metadata_url, :created_by
        ) RETURNING id, name
        """,
        {
            "tenant_id": tenant["id"],
            "name": name,
            "entity_id": f"https://idp-{uuid4().hex[:8]}.example.com",
            "metadata_url": metadata_url,
            "created_by": user["id"],
        },
    )


def _create_idp_sp_cert(tenant, idp, user, expires_in_days: int):
    return database.saml.create_idp_sp_certificate(
        tenant_id=tenant["id"],
        idp_id=str(idp["id"]),
        tenant_id_value=str(tenant["id"]),
        certificate_pem="-----BEGIN CERTIFICATE-----\nSWEEP\n-----END CERTIFICATE-----",
        private_key_pem_enc="enc-material",
        expires_at=datetime.now(UTC) + timedelta(days=expires_in_days),
        created_by=str(user["id"]),
    )


def _set_inactivity_threshold(tenant_id, days: int):
    database.execute(
        tenant_id,
        """
        INSERT INTO tenant_security_settings (tenant_id, inactivity_threshold_days)
        VALUES (:tenant_id, :days)
        ON CONFLICT (tenant_id) DO UPDATE SET inactivity_threshold_days = :days
        """,
        {"tenant_id": str(tenant_id), "days": days},
    )


class TestSpSigningCertificateSweep:
    def test_cert_within_default_window_is_listed_for_rotation(self, test_tenant, test_user):
        sp = _create_sp(test_tenant, test_user)
        cert = _create_sp_cert(test_tenant, sp, test_user, expires_in_days=10)

        rows = database.sp_signing_certificates.get_certificates_needing_rotation_or_cleanup()
        mine = [r for r in rows if str(r["id"]) == str(cert["id"])]
        assert len(mine) == 1
        assert mine[0]["action"] == "rotate"
        assert str(mine[0]["tenant_id"]) == str(test_tenant["id"])

    def test_fresh_cert_is_not_listed(self, test_tenant, test_user):
        sp = _create_sp(test_tenant, test_user)
        cert = _create_sp_cert(test_tenant, sp, test_user, expires_in_days=3650)

        rows = database.sp_signing_certificates.get_certificates_needing_rotation_or_cleanup()
        assert [r for r in rows if str(r["id"]) == str(cert["id"])] == []

    def test_expired_grace_is_listed_for_cleanup(self, test_tenant, test_user):
        sp = _create_sp(test_tenant, test_user)
        cert = _create_sp_cert(test_tenant, sp, test_user, expires_in_days=3650)
        database.execute(
            test_tenant["id"],
            """
            UPDATE sp_signing_certificates
            SET rotation_grace_period_ends_at = :past WHERE id = :id
            """,
            {"past": datetime.now(UTC) - timedelta(hours=1), "id": str(cert["id"])},
        )

        rows = database.sp_signing_certificates.get_certificates_needing_rotation_or_cleanup()
        mine = [r for r in rows if str(r["id"]) == str(cert["id"])]
        assert len(mine) == 1
        assert mine[0]["action"] == "cleanup"

    def test_tenant_configured_window_is_respected(self, test_tenant, test_user):
        """A 14-day window (the smallest allowed) excludes a cert expiring in 30 days."""
        database.execute(
            test_tenant["id"],
            """
            INSERT INTO tenant_security_settings (tenant_id, certificate_rotation_window_days)
            VALUES (:tenant_id, 14)
            ON CONFLICT (tenant_id) DO UPDATE SET certificate_rotation_window_days = 14
            """,
            {"tenant_id": str(test_tenant["id"])},
        )
        sp = _create_sp(test_tenant, test_user)
        cert = _create_sp_cert(test_tenant, sp, test_user, expires_in_days=30)

        rows = database.sp_signing_certificates.get_certificates_needing_rotation_or_cleanup()
        assert [r for r in rows if str(r["id"]) == str(cert["id"])] == []

    def test_sweep_sees_certs_across_tenants(self, test_tenant, test_user, second_tenant):
        """The core 0055 regression: the worker's unscoped view must span tenants."""
        sp_a = _create_sp(test_tenant, test_user)
        cert_a = _create_sp_cert(test_tenant, sp_a, test_user, expires_in_days=10)

        other_user = database.fetchone(
            second_tenant["id"],
            """
            INSERT INTO users (tenant_id, first_name, last_name, role)
            VALUES (:tenant_id, 'Sweep', 'User', 'admin') RETURNING id
            """,
            {"tenant_id": second_tenant["id"]},
        )
        sp_b = _create_sp(second_tenant, other_user)
        cert_b = _create_sp_cert(second_tenant, sp_b, other_user, expires_in_days=10)

        rows = database.sp_signing_certificates.get_certificates_needing_rotation_or_cleanup()
        listed_ids = {str(r["id"]) for r in rows}
        assert str(cert_a["id"]) in listed_ids
        assert str(cert_b["id"]) in listed_ids


class TestIdpSpCertificateSweep:
    def test_cert_within_window_is_listed_for_rotation(self, test_tenant, test_user):
        idp = _create_idp(test_tenant, test_user)
        cert = _create_idp_sp_cert(test_tenant, idp, test_user, expires_in_days=10)

        rows = database.saml.get_idp_sp_certificates_needing_rotation_or_cleanup()
        mine = [r for r in rows if str(r["id"]) == str(cert["id"])]
        assert len(mine) == 1
        assert mine[0]["action"] == "rotate"
        assert str(mine[0]["idp_id"]) == str(idp["id"])

    def test_fresh_cert_is_not_listed(self, test_tenant, test_user):
        idp = _create_idp(test_tenant, test_user)
        cert = _create_idp_sp_cert(test_tenant, idp, test_user, expires_in_days=3650)

        rows = database.saml.get_idp_sp_certificates_needing_rotation_or_cleanup()
        assert [r for r in rows if str(r["id"]) == str(cert["id"])] == []

    def test_expired_grace_is_listed_for_cleanup(self, test_tenant, test_user):
        idp = _create_idp(test_tenant, test_user)
        cert = _create_idp_sp_cert(test_tenant, idp, test_user, expires_in_days=3650)
        database.execute(
            test_tenant["id"],
            """
            UPDATE saml_idp_sp_certificates
            SET rotation_grace_period_ends_at = :past WHERE id = :id
            """,
            {"past": datetime.now(UTC) - timedelta(hours=1), "id": str(cert["id"])},
        )

        rows = database.saml.get_idp_sp_certificates_needing_rotation_or_cleanup()
        mine = [r for r in rows if str(r["id"]) == str(cert["id"])]
        assert len(mine) == 1
        assert mine[0]["action"] == "cleanup"


class TestIdpMetadataUrlSweep:
    def test_idp_with_metadata_url_is_listed(self, test_tenant, test_user):
        url = f"https://idp-{uuid4().hex[:8]}.example.com/metadata.xml"
        idp = _create_idp(test_tenant, test_user, metadata_url=url)

        rows = database.saml.get_idps_with_metadata_url()
        mine = [r for r in rows if str(r["id"]) == str(idp["id"])]
        assert len(mine) == 1
        assert mine[0]["metadata_url"] == url
        assert str(mine[0]["tenant_id"]) == str(test_tenant["id"])

    def test_idp_without_metadata_url_is_not_listed(self, test_tenant, test_user):
        idp = _create_idp(test_tenant, test_user, metadata_url=None)

        rows = database.saml.get_idps_with_metadata_url()
        assert [r for r in rows if str(r["id"]) == str(idp["id"])] == []


class TestInactivityThresholdSweep:
    def test_tenant_with_threshold_is_listed(self, test_tenant):
        _set_inactivity_threshold(test_tenant["id"], 90)

        rows = database.security.get_all_tenants_with_inactivity_threshold()
        mine = [r for r in rows if str(r["tenant_id"]) == str(test_tenant["id"])]
        assert len(mine) == 1
        assert mine[0]["inactivity_threshold_days"] == 90

    def test_tenant_without_threshold_is_not_listed(self, test_tenant):
        rows = database.security.get_all_tenants_with_inactivity_threshold()
        assert [r for r in rows if str(r["tenant_id"]) == str(test_tenant["id"])] == []

    def test_sweep_sees_thresholds_across_tenants(self, test_tenant, second_tenant):
        _set_inactivity_threshold(test_tenant["id"], 60)
        _set_inactivity_threshold(second_tenant["id"], 30)

        rows = database.security.get_all_tenants_with_inactivity_threshold()
        by_tenant = {str(r["tenant_id"]): r["inactivity_threshold_days"] for r in rows}
        assert by_tenant.get(str(test_tenant["id"])) == 60
        assert by_tenant.get(str(second_tenant["id"])) == 30
