#!/usr/bin/env python3
"""Cross-tenant SSO test bed.

Provisions a second tenant (sp-test) and wires up cross-tenant SAML
so SP-initiated SSO works end-to-end between dev (IdP) and sp-test (SP).

Usage:
    python ./dev/sso_testbed.py

Idempotent: safe to re-run. Skips resources that already exist.
"""

import logging
import os

import database
import utils.saml
from dev.tenants import provision_tenant
from dev.users import add_user

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SP_TEST_SUBDOMAIN = "sp-test"
SP_TEST_TENANT_NAME = "SP Test"
DEV_SUBDOMAIN = os.environ.get("DEV_SUBDOMAIN", "dev")
DEV_PASSWORD = os.environ.get("DEV_PASSWORD", "devpass123")

BASE_URL_DEV = f"https://{DEV_SUBDOMAIN}.pageloom.localhost"
BASE_URL_SP_TEST = f"https://{SP_TEST_SUBDOMAIN}.pageloom.localhost"

# OID-based attribute mapping matching saml_assertion.py SAML_ATTRIBUTE_URIS
ATTRIBUTE_MAPPING = {
    "email": "urn:oid:0.9.2342.19200300.100.1.3",
    "first_name": "urn:oid:2.5.4.42",
    "last_name": "urn:oid:2.5.4.4",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_tenant_id(subdomain: str) -> str:
    """Look up a tenant by subdomain, return its id."""
    tenant = database.fetchone(
        database.UNSCOPED,
        "select id from tenants where subdomain = :subdomain",
        {"subdomain": subdomain},
    )
    if not tenant:
        raise RuntimeError(f"Tenant '{subdomain}' not found")
    return str(tenant["id"])


def _get_super_admin_id(tenant_id: str) -> str:
    """Get the first super_admin user id for a tenant (for created_by)."""
    user = database.fetchone(
        tenant_id,
        "select id from users where role = 'super_admin' limit 1",
        {},
    )
    if not user:
        raise RuntimeError(f"No super_admin found for tenant {tenant_id}")
    return str(user["id"])


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------


def step_1_ensure_tenants():
    """Ensure both dev and sp-test tenants exist."""
    log.info("--- Step 1: Ensure tenants ---")
    provision_tenant(DEV_SUBDOMAIN, "Development")
    provision_tenant(SP_TEST_SUBDOMAIN, SP_TEST_TENANT_NAME)


def step_2_create_sp_test_users():
    """Create test users in the sp-test tenant."""
    log.info("--- Step 2: Create sp-test users ---")
    add_user(
        SP_TEST_SUBDOMAIN,
        f"super-{SP_TEST_SUBDOMAIN}@acme.com",
        DEV_PASSWORD,
        role="super_admin",
        first_name="Super",
        last_name="Admin",
    )
    add_user(
        SP_TEST_SUBDOMAIN,
        f"member-{SP_TEST_SUBDOMAIN}@acme.com",
        DEV_PASSWORD,
        role="member",
        first_name="Member",
        last_name="User",
    )


def step_3_register_sp_in_dev(dev_tenant_id: str, dev_admin_id: str) -> dict:
    """Register sp-test as a Service Provider in the dev tenant (IdP side).

    Returns the created/existing SP record.
    """
    log.info("--- Step 3: Register sp-test as SP in dev tenant ---")

    entity_id = f"{BASE_URL_SP_TEST}/saml/metadata"
    acs_url = f"{BASE_URL_SP_TEST}/saml/acs"

    existing = database.service_providers.get_service_provider_by_entity_id(
        dev_tenant_id, entity_id
    )
    if existing:
        log.info("SP already registered: %s", entity_id)
        return existing

    sp = database.service_providers.create_service_provider(
        tenant_id=dev_tenant_id,
        tenant_id_value=dev_tenant_id,
        name="SP Test Tenant",
        entity_id=entity_id,
        acs_url=acs_url,
        created_by=dev_admin_id,
    )
    if not sp:
        raise RuntimeError("Failed to create service provider")
    log.info("Created SP: %s (id=%s)", entity_id, sp["id"])
    return sp


def step_3b_create_sp_signing_cert(dev_tenant_id: str, sp_id: str, dev_admin_id: str) -> str:
    """Generate a per-SP signing certificate for the dev tenant's IdP.

    Returns the certificate PEM (needed by the SP side to verify assertions).
    """
    log.info("--- Step 3b: Per-SP signing certificate ---")

    existing = database.sp_signing_certificates.get_signing_certificate(dev_tenant_id, sp_id)
    if existing:
        log.info("Signing certificate already exists for SP %s", sp_id)
        return existing["certificate_pem"]

    cert_pem, key_pem = utils.saml.generate_sp_certificate(dev_tenant_id)
    encrypted_key = utils.saml.encrypt_private_key(key_pem)
    expires_at = utils.saml.get_certificate_expiry(cert_pem)

    database.sp_signing_certificates.create_signing_certificate(
        tenant_id=dev_tenant_id,
        sp_id=sp_id,
        tenant_id_value=dev_tenant_id,
        certificate_pem=cert_pem,
        private_key_pem_enc=encrypted_key,
        expires_at=expires_at,
        created_by=dev_admin_id,
    )
    log.info("Created per-SP signing certificate for SP %s", sp_id)
    return cert_pem


def step_4_create_sp_certificate(sp_test_tenant_id: str, sp_test_admin_id: str) -> None:
    """Create the tenant SP certificate for sp-test (used to sign AuthnRequests)."""
    log.info("--- Step 4: SP certificate for sp-test tenant ---")

    existing = database.saml.certificates.get_sp_certificate(sp_test_tenant_id)
    if existing:
        log.info("SP certificate already exists for sp-test tenant")
        return

    cert_pem, key_pem = utils.saml.generate_sp_certificate(sp_test_tenant_id)
    encrypted_key = utils.saml.encrypt_private_key(key_pem)
    expires_at = utils.saml.get_certificate_expiry(cert_pem)

    database.saml.certificates.create_sp_certificate(
        tenant_id=sp_test_tenant_id,
        tenant_id_value=sp_test_tenant_id,
        certificate_pem=cert_pem,
        private_key_pem_enc=encrypted_key,
        expires_at=expires_at,
        created_by=sp_test_admin_id,
    )
    log.info("Created SP certificate for sp-test tenant")


def step_5_register_idp_in_sp_test(
    sp_test_tenant_id: str,
    sp_test_admin_id: str,
    sp_id: str,
    idp_signing_cert_pem: str,
) -> None:
    """Register dev as an Identity Provider in the sp-test tenant (SP side)."""
    log.info("--- Step 5: Register dev as IdP in sp-test tenant ---")

    idp_entity_id = f"{BASE_URL_DEV}/saml/idp/metadata"
    sso_url = f"{BASE_URL_DEV}/saml/idp/sso"
    sp_entity_id = f"{BASE_URL_SP_TEST}/saml/metadata"

    existing = database.saml.providers.get_identity_provider_by_entity_id(
        sp_test_tenant_id, idp_entity_id
    )
    if existing:
        log.info("IdP already registered: %s", idp_entity_id)
        return

    idp = database.saml.providers.create_identity_provider(
        tenant_id=sp_test_tenant_id,
        tenant_id_value=sp_test_tenant_id,
        name="Dev Tenant IdP",
        provider_type="generic",
        entity_id=idp_entity_id,
        sso_url=sso_url,
        certificate_pem=idp_signing_cert_pem,
        sp_entity_id=sp_entity_id,
        created_by=sp_test_admin_id,
        attribute_mapping=ATTRIBUTE_MAPPING,
        is_enabled=True,
        is_default=True,
        jit_provisioning=True,
    )
    if not idp:
        raise RuntimeError("Failed to create identity provider")
    log.info("Created IdP: %s (id=%s)", idp_entity_id, idp["id"])


def print_summary(sp_id: str):
    """Print test URLs and next steps."""
    log.info("")
    log.info("=" * 60)
    log.info("SSO Test Bed Ready")
    log.info("=" * 60)
    log.info("")
    log.info("Tenants:")
    log.info("  IdP (dev):     %s", BASE_URL_DEV)
    log.info("  SP  (sp-test): %s", BASE_URL_SP_TEST)
    log.info("")
    log.info("Test users (password: %s):", DEV_PASSWORD)
    log.info("  dev tenant:     super-%s@acme.com (super_admin)", DEV_SUBDOMAIN)
    log.info("  sp-test tenant: super-%s@acme.com (super_admin)", SP_TEST_SUBDOMAIN)
    log.info("  sp-test tenant: member-%s@acme.com (member)", SP_TEST_SUBDOMAIN)
    log.info("")
    log.info("SP-initiated SSO flow:")
    log.info("  1. Visit %s/login", BASE_URL_SP_TEST)
    log.info("  2. Click 'Dev Tenant IdP' to start SSO")
    log.info("  3. Log in at dev tenant (super-%s@acme.com)", DEV_SUBDOMAIN)
    log.info("  4. Approve consent screen")
    log.info("  5. Redirected back to sp-test, logged in via JIT")
    log.info("")
    log.info("Admin pages:")
    log.info("  SPs:  %s/admin/settings/service-providers", BASE_URL_DEV)
    log.info("  IdPs: %s/admin/settings/identity-providers", BASE_URL_SP_TEST)
    log.info("")
    log.info("IdP metadata: %s/saml/idp/metadata/%s", BASE_URL_DEV, sp_id)
    log.info("SP metadata:  %s/saml/metadata", BASE_URL_SP_TEST)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    # Step 1: Ensure tenants
    step_1_ensure_tenants()

    # Step 2: Create test users in sp-test
    step_2_create_sp_test_users()

    # Look up tenant IDs and admin user IDs
    dev_tenant_id = _get_tenant_id(DEV_SUBDOMAIN)
    sp_test_tenant_id = _get_tenant_id(SP_TEST_SUBDOMAIN)
    dev_admin_id = _get_super_admin_id(dev_tenant_id)
    sp_test_admin_id = _get_super_admin_id(sp_test_tenant_id)

    # Step 3: Register sp-test as SP in dev tenant
    sp = step_3_register_sp_in_dev(dev_tenant_id, dev_admin_id)
    sp_id = str(sp["id"])

    # Step 3b: Per-SP signing certificate
    idp_signing_cert_pem = step_3b_create_sp_signing_cert(dev_tenant_id, sp_id, dev_admin_id)

    # Step 4: SP certificate for sp-test tenant
    step_4_create_sp_certificate(sp_test_tenant_id, sp_test_admin_id)

    # Step 5: Register dev as IdP in sp-test tenant
    step_5_register_idp_in_sp_test(sp_test_tenant_id, sp_test_admin_id, sp_id, idp_signing_cert_pem)

    # Summary
    print_summary(sp_id)


if __name__ == "__main__":
    main()
