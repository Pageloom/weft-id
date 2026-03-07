#!/usr/bin/env python3
"""Cross-tenant SSO test bed.

Provisions two tenants and wires up cross-tenant SAML so SSO works
end-to-end between one IdP tenant and one SP tenant.

Usage:
    python ./dev/sso_testbed.py                     # interactive (dev / sp-test)
    python ./dev/sso_testbed.py --json                 # JSON output for automation
    python ./dev/sso_testbed.py --idp-subdomain a --sp-subdomain b
    python ./dev/sso_testbed.py --teardown             # delete test tenants

Idempotent: safe to re-run. Skips resources that already exist.
"""

import json
import logging
import os
import sys

import argh
import database
import database.groups
import database.sp_group_assignments
import utils.saml
from dev.tenants import provision_tenant
from dev.users import add_user
from utils.saml import make_sp_entity_id
from utils.saml_idp import make_idp_entity_id

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEV_PASSWORD = os.environ.get("DEV_PASSWORD", "devpass123")

# Attribute mapping: maps WeftId user fields to the SAML attribute names the IdP sends.
# WeftId IdP uses friendly names (email, firstName, lastName) by default,
# so the SP side needs to know to look for those names in the SAML response.
ATTRIBUTE_MAPPING = {
    "email": "email",
    "first_name": "firstName",
    "last_name": "lastName",
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


def _get_super_admin(tenant_id: str) -> dict:
    """Get the first super_admin user for a tenant (id + primary email)."""
    user = database.fetchone(
        tenant_id,
        """
        select u.id, ue.email
        from users u
        join user_emails ue on ue.user_id = u.id and ue.is_primary = true
        where u.role = 'super_admin'
        limit 1
        """,
        {},
    )
    if not user:
        raise RuntimeError(f"No super_admin found for tenant {tenant_id}")
    return {"id": str(user["id"]), "email": user["email"]}


def _base_url(subdomain: str) -> str:
    return f"https://{subdomain}.pageloom.localhost"


def _configure_logging(json_mode: bool) -> logging.Logger:
    """Configure logging. In JSON mode, ALL logs go to stderr so stdout is pure JSON."""
    stream = sys.stderr if json_mode else sys.stdout

    # Configure root logger so imported modules (dev.tenants, dev.users) also route correctly
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=stream, force=True)

    log = logging.getLogger("sso_testbed")
    log.setLevel(logging.INFO)
    return log


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------


def step_1_ensure_tenants(log, idp_subdomain: str, sp_subdomain: str):
    """Ensure both IdP and SP tenants exist."""
    log.info("--- Step 1: Ensure tenants ---")
    provision_tenant(idp_subdomain, f"{idp_subdomain.title()} IdP")
    provision_tenant(sp_subdomain, f"{sp_subdomain.title()} SP")


def step_2_create_test_users(log, idp_subdomain: str, sp_subdomain: str):
    """Create test users in both tenants."""
    log.info("--- Step 2: Create test users ---")
    # IdP super admin (may already exist from tenant provisioning)
    add_user(
        idp_subdomain,
        f"super-{idp_subdomain}@acme.com",
        DEV_PASSWORD,
        role="super_admin",
        first_name="Super",
        last_name="Admin",
    )
    # SP super admin
    add_user(
        sp_subdomain,
        f"super-{sp_subdomain}@acme.com",
        DEV_PASSWORD,
        role="super_admin",
        first_name="Super",
        last_name="Admin",
    )
    # SP member
    add_user(
        sp_subdomain,
        f"member-{sp_subdomain}@acme.com",
        DEV_PASSWORD,
        role="member",
        first_name="Member",
        last_name="User",
    )


def step_3_register_sp(log, idp_tenant_id: str, idp_admin_id: str, sp_subdomain: str) -> dict:
    """Register the SP tenant as a Service Provider in the IdP tenant.

    Creates the SP with a temporary entity_id. The entity_id and acs_url
    are updated to per-IdP format in step_5b after the IdP record is created.

    Returns the created/existing SP record.
    """
    log.info("--- Step 3: Register SP in IdP tenant ---")

    sp_name = f"{sp_subdomain.title()} SP"
    base_url = _base_url(sp_subdomain)

    # Look up by name (entity_id changes to per-IdP format after step 5b)
    existing = database.fetchone(
        idp_tenant_id,
        "select * from service_providers where name = :name limit 1",
        {"name": sp_name},
    )
    if existing:
        log.info("SP already registered: %s (id=%s)", sp_name, existing["id"])
        return existing

    temp_entity_id = f"{base_url}/saml/metadata"
    temp_acs_url = f"{base_url}/saml/acs"

    sp = database.service_providers.create_service_provider(
        tenant_id=idp_tenant_id,
        tenant_id_value=idp_tenant_id,
        name=sp_name,
        entity_id=temp_entity_id,
        acs_url=temp_acs_url,
        slo_url=f"{base_url}/saml/slo",
        created_by=idp_admin_id,
        trust_established=True,
    )
    if not sp:
        raise RuntimeError("Failed to create service provider")
    log.info("Created SP: %s (id=%s)", sp_name, sp["id"])
    return sp


def step_3b_create_sp_signing_cert(log, idp_tenant_id: str, sp_id: str, idp_admin_id: str) -> str:
    """Generate a per-SP signing certificate for the IdP tenant.

    Returns the certificate PEM (needed by the SP side to verify assertions).
    """
    log.info("--- Step 3b: Per-SP signing certificate ---")

    existing = database.sp_signing_certificates.get_signing_certificate(idp_tenant_id, sp_id)
    if existing:
        log.info("Signing certificate already exists for SP %s", sp_id)
        return str(existing["certificate_pem"])

    cert_pem, key_pem = utils.saml.generate_sp_certificate(idp_tenant_id)
    encrypted_key = utils.saml.encrypt_private_key(key_pem)
    expires_at = utils.saml.get_certificate_expiry(cert_pem)

    database.sp_signing_certificates.create_signing_certificate(
        tenant_id=idp_tenant_id,
        sp_id=sp_id,
        tenant_id_value=idp_tenant_id,
        certificate_pem=cert_pem,
        private_key_pem_enc=encrypted_key,
        expires_at=expires_at,
        created_by=idp_admin_id,
    )
    log.info("Created per-SP signing certificate for SP %s", sp_id)
    return cert_pem


def step_4_create_sp_certificate(log, sp_tenant_id: str, sp_admin_id: str):
    """Create the tenant SP certificate (used to sign AuthnRequests)."""
    log.info("--- Step 4: SP certificate for SP tenant ---")

    existing = database.saml.certificates.get_sp_certificate(sp_tenant_id)
    if existing:
        log.info("SP certificate already exists")
        return

    cert_pem, key_pem = utils.saml.generate_sp_certificate(sp_tenant_id)
    encrypted_key = utils.saml.encrypt_private_key(key_pem)
    expires_at = utils.saml.get_certificate_expiry(cert_pem)

    database.saml.certificates.create_sp_certificate(
        tenant_id=sp_tenant_id,
        tenant_id_value=sp_tenant_id,
        certificate_pem=cert_pem,
        private_key_pem_enc=encrypted_key,
        expires_at=expires_at,
        created_by=sp_admin_id,
    )
    log.info("Created SP certificate")


def step_5_register_idp(
    log,
    sp_tenant_id: str,
    sp_admin_id: str,
    idp_tenant_id: str,
    idp_subdomain: str,
    sp_subdomain: str,
    sp_id: str,
    idp_signing_cert_pem: str,
) -> str:
    """Register the IdP tenant as an Identity Provider in the SP tenant.

    The IdP entity_id uses the stable URN format (urn:weftid:{tenant}:idp)
    matching what the IdP uses as the Issuer in SAML Responses.
    The sp_entity_id is set to a temporary value and updated in step_5b.

    Returns the IdP id (as string).
    """
    log.info("--- Step 5: Register IdP in SP tenant ---")

    idp_base_url = _base_url(idp_subdomain)
    sp_base_url = _base_url(sp_subdomain)
    idp_entity_id = make_idp_entity_id(idp_tenant_id)
    sso_url = f"{idp_base_url}/saml/idp/sso"
    # Temp sp_entity_id (updated to per-IdP format in step 5b)
    temp_sp_entity_id = f"{sp_base_url}/saml/metadata"

    existing = database.saml.providers.get_identity_provider_by_entity_id(
        sp_tenant_id, idp_entity_id
    )
    if existing:
        log.info("IdP already registered: %s", idp_entity_id)
        return str(existing["id"])

    slo_url = f"{idp_base_url}/saml/idp/slo"

    idp = database.saml.providers.create_identity_provider(
        tenant_id=sp_tenant_id,
        tenant_id_value=sp_tenant_id,
        name=f"{idp_subdomain.title()} IdP",
        provider_type="generic",
        entity_id=idp_entity_id,
        sso_url=sso_url,
        slo_url=slo_url,
        certificate_pem=idp_signing_cert_pem,
        sp_entity_id=temp_sp_entity_id,
        created_by=sp_admin_id,
        attribute_mapping=ATTRIBUTE_MAPPING,
        is_enabled=True,
        is_default=True,
        jit_provisioning=True,
        trust_established=True,
    )
    if not idp:
        raise RuntimeError("Failed to create identity provider")
    idp_id = str(idp["id"])
    log.info("Created IdP: %s (id=%s)", idp_entity_id, idp_id)

    # Create the base group for this IdP (service layer normally does this,
    # but we created the IdP via the database layer directly).
    from services.groups.idp import create_idp_base_group

    create_idp_base_group(
        tenant_id=sp_tenant_id,
        idp_id=idp_id,
        idp_name=f"{idp_subdomain.title()} IdP",
    )

    return idp_id


def step_5b_update_per_idp_metadata(
    log,
    idp_tenant_id: str,
    sp_tenant_id: str,
    sp_admin_id: str,
    sp_subdomain: str,
    sp_id: str,
    idp_id: str,
):
    """Update SP and IdP records with final entity IDs and per-IdP ACS URL.

    SP entity_id uses the stable URN format (urn:weftid:{tenant}:sp).
    The IdP record's sp_entity_id keeps the per-IdP URL for ACS URL derivation.
    Also creates the per-IdP SP certificate used for signing AuthnRequests.
    """
    log.info("--- Step 5b: Per-IdP SP metadata ---")

    sp_base_url = _base_url(sp_subdomain)
    sp_urn_entity_id = make_sp_entity_id(sp_tenant_id)
    per_idp_sp_url = f"{sp_base_url}/saml/metadata/{idp_id}"
    per_idp_acs_url = f"{sp_base_url}/saml/acs/{idp_id}"

    # Update IdP record's sp_entity_id (per-IdP URL, used for ACS derivation)
    database.saml.providers.update_identity_provider(
        sp_tenant_id, idp_id, sp_entity_id=per_idp_sp_url
    )
    log.info("Updated IdP sp_entity_id to %s", per_idp_sp_url)

    # Update SP record's entity_id (URN) and acs_url at IdP tenant
    database.execute(
        idp_tenant_id,
        """
        update service_providers
        set entity_id = :entity_id, acs_url = :acs_url, updated_at = now()
        where id = cast(:sp_id as uuid)
        """,
        {"entity_id": sp_urn_entity_id, "acs_url": per_idp_acs_url, "sp_id": sp_id},
    )
    log.info("Updated SP entity_id to %s", sp_urn_entity_id)

    # Create per-IdP SP certificate (needs system_context for event logging)
    from services.saml.idp_sp_certificates import get_or_create_idp_sp_certificate
    from utils.request_context import system_context

    with system_context():
        get_or_create_idp_sp_certificate(sp_tenant_id, idp_id, sp_admin_id)
    log.info("Ensured per-IdP SP certificate for IdP %s", idp_id)


def step_6_create_group_and_assign_sp(
    log,
    idp_tenant_id: str,
    idp_admin_id: str,
    sp_id: str,
):
    """Create an 'SSO Users' group in the IdP tenant and assign the SP to it.

    This is required because the SSO consent page checks group-based access.
    Without a group assignment, SSO fails with 'unauthorized_user'.
    """
    log.info("--- Step 6: Create group and assign SP ---")

    # Create or find the group
    group = database.groups.get_weftid_group_by_name(idp_tenant_id, "SSO Users")
    if group:
        group_id = str(group["id"])
        log.info("Group 'SSO Users' already exists (id=%s)", group_id)
    else:
        group = database.groups.create_group(
            tenant_id=idp_tenant_id,
            tenant_id_value=idp_tenant_id,
            name="SSO Users",
            description="Users with access to downstream service providers",
            group_type="weftid",
            created_by=idp_admin_id,
        )
        if not group:
            raise RuntimeError("Failed to create group")
        group_id = str(group["id"])
        log.info("Created group 'SSO Users' (id=%s)", group_id)

    # Add IdP admin to the group
    if not database.groups.is_group_member(idp_tenant_id, group_id, idp_admin_id):
        database.groups.add_group_member(
            tenant_id=idp_tenant_id,
            tenant_id_value=idp_tenant_id,
            group_id=group_id,
            user_id=idp_admin_id,
        )
        log.info("Added admin to 'SSO Users' group")
    else:
        log.info("Admin already in 'SSO Users' group")

    # Assign SP to this group
    existing_assignments = database.sp_group_assignments.list_assignments_for_sp(
        idp_tenant_id, sp_id
    )
    already_assigned = any(str(a["group_id"]) == group_id for a in existing_assignments)
    if not already_assigned:
        database.sp_group_assignments.create_assignment(
            tenant_id=idp_tenant_id,
            tenant_id_value=idp_tenant_id,
            sp_id=sp_id,
            group_id=group_id,
            assigned_by=idp_admin_id,
        )
        log.info("Assigned SP to 'SSO Users' group")
    else:
        log.info("SP already assigned to 'SSO Users' group")

    return group_id


def step_7_create_preexisting_user(
    log,
    sp_subdomain: str,
    sp_tenant_id: str,
    idp_admin_email: str,
    idp_id: str,
):
    """Create a pre-existing user in the SP tenant that matches the IdP admin.

    This user will be matched (not JIT-created) during the SSO flow,
    testing the 'sign in as pre-existing user' scenario.

    The user is linked to the IdP via saml_idp_id so that the email-first
    login flow routes to SAML instead of password (needed for SP-initiated SSO).
    """
    log.info("--- Step 7: Pre-existing user in SP tenant ---")
    add_user(
        sp_subdomain,
        idp_admin_email,
        DEV_PASSWORD,
        role="member",
        first_name="Pre-existing",
        last_name="User",
    )

    # Link the pre-existing user to the IdP so email-first login
    # routes to SAML instead of password login
    database.execute(
        sp_tenant_id,
        """
        update users set saml_idp_id = :idp_id
        where id = (
            select ue.user_id from user_emails ue
            join users u on u.id = ue.user_id
            where ue.email = :email and ue.is_primary = true
            limit 1
        )
        """,
        {"idp_id": idp_id, "email": idp_admin_email},
    )
    log.info("Linked pre-existing user to IdP %s", idp_id)


def _print_summary(log, idp_subdomain: str, sp_subdomain: str, sp_id: str):
    """Print test URLs and next steps."""
    idp_url = _base_url(idp_subdomain)
    sp_url = _base_url(sp_subdomain)

    log.info("")
    log.info("=" * 60)
    log.info("SSO Test Bed Ready")
    log.info("=" * 60)
    log.info("")
    log.info("Tenants:")
    log.info("  IdP (%s):  %s", idp_subdomain, idp_url)
    log.info("  SP  (%s):  %s", sp_subdomain, sp_url)
    log.info("")
    log.info("Test users (password: %s):", DEV_PASSWORD)
    log.info("  IdP tenant: super-%s@acme.com (super_admin)", idp_subdomain)
    log.info("  SP tenant:  super-%s@acme.com (super_admin)", sp_subdomain)
    log.info("  SP tenant:  member-%s@acme.com (member)", sp_subdomain)
    log.info("")
    log.info("SP-initiated SSO flow:")
    log.info("  1. Visit %s/login", sp_url)
    log.info("  2. Enter IdP admin email to start SSO")
    log.info("  3. Log in at IdP (super-%s@acme.com)", idp_subdomain)
    log.info("  4. Approve consent screen")
    log.info("  5. Redirected back to SP, logged in via JIT")
    log.info("")
    log.info("Admin pages:")
    log.info("  SPs:  %s/admin/settings/service-providers", idp_url)
    log.info("  IdPs: %s/admin/settings/identity-providers", sp_url)
    log.info("")
    log.info("IdP metadata: %s/saml/idp/metadata/%s", idp_url, sp_id)
    log.info("SP metadata:  %s/admin/settings/identity-providers (per-IdP URLs)", sp_url)


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------


def _teardown(log, idp_subdomain: str, sp_subdomain: str):
    """Delete both test tenants (CASCADE handles child records)."""
    log.info("Tearing down test tenants: %s, %s", idp_subdomain, sp_subdomain)
    for subdomain in (idp_subdomain, sp_subdomain):
        result = database.execute(
            database.UNSCOPED,
            "delete from tenants where subdomain = :subdomain",
            {"subdomain": subdomain},
        )
        if result:
            log.info("Deleted tenant: %s", subdomain)
        else:
            log.info("Tenant not found (already deleted?): %s", subdomain)
    log.info("Teardown complete")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(
    json_output: bool = False,
    teardown: bool = False,
    idp_subdomain: str = "dev",
    sp_subdomain: str = "sp-test",
):
    """Provision cross-tenant SSO test bed.

    Args:
        json_output: Output config as JSON to stdout (logs go to stderr).
        teardown: Delete test tenants instead of creating them.
        idp_subdomain: Subdomain for the IdP tenant.
        sp_subdomain: Subdomain for the SP tenant.
    """
    log = _configure_logging(json_output)

    if teardown:
        _teardown(log, idp_subdomain, sp_subdomain)
        return

    # Step 1: Ensure tenants
    step_1_ensure_tenants(log, idp_subdomain, sp_subdomain)

    # Step 2: Create test users
    step_2_create_test_users(log, idp_subdomain, sp_subdomain)

    # Look up tenant IDs and admin user info
    idp_tenant_id = _get_tenant_id(idp_subdomain)
    sp_tenant_id = _get_tenant_id(sp_subdomain)
    idp_admin = _get_super_admin(idp_tenant_id)
    sp_admin = _get_super_admin(sp_tenant_id)

    # Step 3: Register SP in IdP tenant
    sp = step_3_register_sp(log, idp_tenant_id, idp_admin["id"], sp_subdomain)
    sp_id = str(sp["id"])

    # Step 3b: Per-SP signing certificate
    idp_signing_cert_pem = step_3b_create_sp_signing_cert(
        log, idp_tenant_id, sp_id, idp_admin["id"]
    )

    # Step 4: SP certificate for SP tenant
    step_4_create_sp_certificate(log, sp_tenant_id, sp_admin["id"])

    # Step 5: Register IdP in SP tenant
    idp_id = step_5_register_idp(
        log,
        sp_tenant_id,
        sp_admin["id"],
        idp_tenant_id,
        idp_subdomain,
        sp_subdomain,
        sp_id,
        idp_signing_cert_pem,
    )

    # Step 5b: Update to per-IdP metadata URLs and create per-IdP SP certificate
    step_5b_update_per_idp_metadata(
        log,
        idp_tenant_id,
        sp_tenant_id,
        sp_admin["id"],
        sp_subdomain,
        sp_id,
        idp_id,
    )

    # Step 6: Create group and assign SP for access control
    group_id = step_6_create_group_and_assign_sp(log, idp_tenant_id, idp_admin["id"], sp_id)

    # Step 7: Pre-existing user in SP tenant (matches IdP admin email)
    idp_admin_email = f"super-{idp_subdomain}@acme.com"
    step_7_create_preexisting_user(log, sp_subdomain, sp_tenant_id, idp_admin_email, idp_id)

    if json_output:
        config = {
            "idp": {
                "tenant_id": idp_tenant_id,
                "subdomain": idp_subdomain,
                "base_url": _base_url(idp_subdomain),
                "admin_email": idp_admin_email,
                "admin_password": DEV_PASSWORD,
                "sp_id": sp_id,
                "group_id": group_id,
            },
            "sp": {
                "tenant_id": sp_tenant_id,
                "subdomain": sp_subdomain,
                "base_url": _base_url(sp_subdomain),
                "admin_email": f"super-{sp_subdomain}@acme.com",
                "admin_password": DEV_PASSWORD,
                "idp_id": idp_id,
                "existing_user_email": idp_admin_email,
            },
        }
        print(json.dumps(config, indent=2))
    else:
        _print_summary(log, idp_subdomain, sp_subdomain, sp_id)


if __name__ == "__main__":
    argh.dispatch_command(main)
