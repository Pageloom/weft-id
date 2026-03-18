#!/usr/bin/env python3
"""Three-tenant chain SSO test bed.

Provisions three tenants wired in a chain for passthrough SSO testing:
    e2e-upstream  (ultimate IdP)
        ↓ SAML
    e2e-mid       (IdP for leaf, SP of upstream)
        ↓ SAML
    e2e-leaf      (leaf SP)

Also sets up:
    - Privileged domain binding at leaf (upstream.test → mid IdP)
    - Group hierarchy at mid (parent/child groups for access testing)

Usage:
    python ./dev/sso_chain_testbed.py --json              # JSON output
    python ./dev/sso_chain_testbed.py --teardown          # delete tenants
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
UPSTREAM_SUBDOMAIN = "e2e-upstream"
MID_SUBDOMAIN = "e2e-mid"
LEAF_SUBDOMAIN = "e2e-leaf"

ATTRIBUTE_MAPPING = {
    "email": "email",
    "first_name": "firstName",
    "last_name": "lastName",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_tenant_id(subdomain: str) -> str:
    tenant = database.fetchone(
        database.UNSCOPED,
        "select id from tenants where subdomain = :subdomain",
        {"subdomain": subdomain},
    )
    if not tenant:
        raise RuntimeError(f"Tenant '{subdomain}' not found")
    return str(tenant["id"])


def _get_super_admin(tenant_id: str) -> dict:
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


def _get_user_by_email(tenant_id: str, email: str) -> dict | None:
    user = database.fetchone(
        tenant_id,
        """
        select u.id from users u
        join user_emails ue on ue.user_id = u.id and ue.is_primary = true
        where ue.email = :email
        """,
        {"email": email},
    )
    if user:
        return {"id": str(user["id"])}
    return None


def _base_url(subdomain: str) -> str:
    return f"https://{subdomain}.weftid.localhost"


def _configure_logging(json_mode: bool) -> logging.Logger:
    stream = sys.stderr if json_mode else sys.stdout
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=stream, force=True)
    log = logging.getLogger("sso_chain_testbed")
    log.setLevel(logging.INFO)
    return log


# ---------------------------------------------------------------------------
# Wiring helper: connect IdP tenant → SP tenant
# ---------------------------------------------------------------------------


def wire_idp_to_sp(
    log,
    idp_tenant_id: str,
    idp_admin_id: str,
    idp_subdomain: str,
    sp_tenant_id: str,
    sp_admin_id: str,
    sp_subdomain: str,
) -> dict:
    """Wire one tenant as IdP for another acting as SP.

    Creates SP at IdP tenant, IdP at SP tenant, per-SP signing cert,
    per-IdP SP cert, and updates entity_ids to per-IdP format.

    Returns dict with sp_id, idp_id, idp_signing_cert_pem, group_id.
    """
    idp_base = _base_url(idp_subdomain)
    sp_base = _base_url(sp_subdomain)
    sp_name = f"{sp_subdomain.title()} SP"

    # --- Register SP in IdP tenant (temp entity_id, updated below) ---
    existing_sp = database.fetchone(
        idp_tenant_id,
        "select * from service_providers where name = :name limit 1",
        {"name": sp_name},
    )
    if existing_sp:
        sp_id = str(existing_sp["id"])
        log.info("SP already registered at %s: %s", idp_subdomain, sp_name)
    else:
        temp_entity_id = f"{sp_base}/saml/metadata"
        temp_acs_url = f"{sp_base}/saml/acs"
        sp = database.service_providers.create_service_provider(
            tenant_id=idp_tenant_id,
            tenant_id_value=idp_tenant_id,
            name=sp_name,
            entity_id=temp_entity_id,
            acs_url=temp_acs_url,
            created_by=idp_admin_id,
            trust_established=True,
        )
        if not sp:
            raise RuntimeError("Failed to create SP")
        sp_id = str(sp["id"])
        log.info("Created SP at %s: %s (id=%s)", idp_subdomain, sp_name, sp_id)

    # --- Per-SP signing certificate ---
    existing_cert = database.sp_signing_certificates.get_signing_certificate(idp_tenant_id, sp_id)
    if existing_cert:
        idp_signing_cert_pem = str(existing_cert["certificate_pem"])
        log.info("Signing cert already exists for SP %s at %s", sp_id, idp_subdomain)
    else:
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
        idp_signing_cert_pem = cert_pem
        log.info("Created signing cert for SP %s at %s", sp_id, idp_subdomain)

    # --- SP certificate at SP tenant ---
    existing_sp_cert = database.saml.certificates.get_sp_certificate(sp_tenant_id)
    if not existing_sp_cert:
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
        log.info("Created SP certificate at %s", sp_subdomain)

    # --- Register IdP in SP tenant (temp sp_entity_id, updated below) ---
    idp_entity_id = make_idp_entity_id(idp_tenant_id, sp_id)
    sso_url = f"{idp_base}/saml/idp/sso"
    temp_sp_entity_id = f"{sp_base}/saml/metadata"

    existing_idp = database.saml.providers.get_identity_provider_by_entity_id(
        sp_tenant_id, idp_entity_id
    )
    if existing_idp:
        idp_id = str(existing_idp["id"])
        log.info("IdP already registered at %s: %s", sp_subdomain, idp_entity_id)
    else:
        idp = database.saml.providers.create_identity_provider(
            tenant_id=sp_tenant_id,
            tenant_id_value=sp_tenant_id,
            name=f"{idp_subdomain.title()} IdP",
            provider_type="generic",
            entity_id=idp_entity_id,
            sso_url=sso_url,
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
            raise RuntimeError("Failed to create IdP")
        idp_id = str(idp["id"])
        log.info("Created IdP at %s: %s (id=%s)", sp_subdomain, idp_entity_id, idp_id)

        # Create IdP base group
        from services.groups.idp import create_idp_base_group

        create_idp_base_group(
            tenant_id=sp_tenant_id,
            idp_id=idp_id,
            idp_name=f"{idp_subdomain.title()} IdP",
        )

    # --- Update to per-IdP SP metadata URLs ---
    sp_urn_entity_id = make_sp_entity_id(sp_tenant_id, idp_id)
    per_idp_sp_url = f"{sp_base}/saml/metadata/{idp_id}"
    per_idp_acs_url = f"{sp_base}/saml/acs/{idp_id}"

    # sp_entity_id keeps per-IdP URL (used for ACS URL derivation)
    database.saml.providers.update_identity_provider(
        sp_tenant_id, idp_id, sp_entity_id=per_idp_sp_url
    )
    # service_providers.entity_id uses stable URN
    database.execute(
        idp_tenant_id,
        """
        update service_providers
        set entity_id = :entity_id, acs_url = :acs_url, updated_at = now()
        where id = cast(:sp_id as uuid)
        """,
        {"entity_id": sp_urn_entity_id, "acs_url": per_idp_acs_url, "sp_id": sp_id},
    )
    log.info("Updated SP entity_id to %s, ACS to %s", sp_urn_entity_id, per_idp_acs_url)

    # --- Per-IdP SP certificate (needs system_context for event logging) ---
    from services.saml.idp_sp_certificates import get_or_create_idp_sp_certificate
    from utils.request_context import system_context

    with system_context():
        get_or_create_idp_sp_certificate(sp_tenant_id, idp_id, sp_admin_id)

    # --- Group and SP assignment in IdP tenant ---
    group_name = f"SSO Users ({sp_subdomain})"
    group = database.groups.get_weftid_group_by_name(idp_tenant_id, group_name)
    if group:
        group_id = str(group["id"])
    else:
        group = database.groups.create_group(
            tenant_id=idp_tenant_id,
            tenant_id_value=idp_tenant_id,
            name=group_name,
            description=f"Users with SSO access to {sp_subdomain}",
            group_type="weftid",
            created_by=idp_admin_id,
        )
        if not group:
            raise RuntimeError("Failed to create group")
        group_id = str(group["id"])
        log.info("Created group '%s' at %s (id=%s)", group_name, idp_subdomain, group_id)

    # Add admin to group
    if not database.groups.is_group_member(idp_tenant_id, group_id, idp_admin_id):
        database.groups.add_group_member(
            tenant_id=idp_tenant_id,
            tenant_id_value=idp_tenant_id,
            group_id=group_id,
            user_id=idp_admin_id,
        )

    # Assign SP to group
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
        log.info("Assigned SP %s to group '%s' at %s", sp_id, group_name, idp_subdomain)

    return {
        "sp_id": sp_id,
        "idp_id": idp_id,
        "idp_signing_cert_pem": idp_signing_cert_pem,
        "group_id": group_id,
    }


# ---------------------------------------------------------------------------
# Chain-specific setup
# ---------------------------------------------------------------------------


def setup_chain_user(
    log,
    upstream_tenant_id: str,
    upstream_subdomain: str,
    upstream_group_id: str,
    mid_tenant_id: str,
    mid_subdomain: str,
    mid_group_id: str,
    upstream_idp_id_at_mid: str,
):
    """Create the chain test user at upstream and mid tenants.

    At upstream: user with password (for authentication).
    At mid: user linked to upstream IdP (no password, SAML-only).
    """
    chain_email = "chain-user@upstream.test"
    log.info("--- Setting up chain user: %s ---", chain_email)

    # Create at upstream with password
    add_user(
        upstream_subdomain,
        chain_email,
        DEV_PASSWORD,
        role="member",
        first_name="Chain",
        last_name="User",
    )

    # Add to upstream group (for SSO access to mid SP)
    upstream_user = _get_user_by_email(upstream_tenant_id, chain_email)
    if upstream_user and not database.groups.is_group_member(
        upstream_tenant_id, upstream_group_id, upstream_user["id"]
    ):
        database.groups.add_group_member(
            tenant_id=upstream_tenant_id,
            tenant_id_value=upstream_tenant_id,
            group_id=upstream_group_id,
            user_id=upstream_user["id"],
        )
        log.info("Added chain-user to upstream group")

    # Create at mid (no password, linked to upstream IdP)
    mid_user = _get_user_by_email(mid_tenant_id, chain_email)
    if not mid_user:
        user = database.fetchone(
            mid_tenant_id,
            """
            insert into users (tenant_id, first_name, last_name, role, saml_idp_id)
            values (:tenant_id, 'Chain', 'User', 'member', :idp_id)
            returning id
            """,
            {"tenant_id": mid_tenant_id, "idp_id": upstream_idp_id_at_mid},
        )
        if not user:
            raise RuntimeError("Failed to create chain user at mid")
        mid_user = {"id": str(user["id"])}

        database.execute(
            mid_tenant_id,
            """
            insert into user_emails (tenant_id, user_id, email, is_primary, verified_at)
            values (:tenant_id, :user_id, :email, true, now())
            """,
            {"tenant_id": mid_tenant_id, "user_id": mid_user["id"], "email": chain_email},
        )
        log.info("Created chain-user at mid (SAML-only)")
    else:
        log.info("Chain-user already exists at mid")

    # Add to mid group (for SSO access to leaf SP)
    if not database.groups.is_group_member(mid_tenant_id, mid_group_id, mid_user["id"]):
        database.groups.add_group_member(
            tenant_id=mid_tenant_id,
            tenant_id_value=mid_tenant_id,
            group_id=mid_group_id,
            user_id=mid_user["id"],
        )
        log.info("Added chain-user to mid group")


def setup_domain_binding(log, leaf_tenant_id: str, leaf_admin_id: str, mid_idp_id: str):
    """Create privileged domain 'upstream.test' at leaf and bind to mid IdP.

    This enables domain-based routing: users with @upstream.test emails
    at the leaf tenant are automatically routed to the mid IdP.
    """
    log.info("--- Setting up domain binding at leaf ---")
    domain_name = "upstream.test"

    # Create privileged domain
    existing = database.fetchone(
        leaf_tenant_id,
        "select id from tenant_privileged_domains where domain = :domain",
        {"domain": domain_name},
    )
    if existing:
        domain_id = str(existing["id"])
        log.info("Privileged domain '%s' already exists at leaf", domain_name)
    else:
        result = database.fetchone(
            leaf_tenant_id,
            """
            insert into tenant_privileged_domains (tenant_id, domain, created_by)
            values (:tenant_id, :domain, :created_by)
            returning id
            """,
            {
                "tenant_id": leaf_tenant_id,
                "domain": domain_name,
                "created_by": leaf_admin_id,
            },
        )
        if not result:
            raise RuntimeError("Failed to create privileged domain")
        domain_id = str(result["id"])
        log.info("Created privileged domain '%s' at leaf", domain_name)

    # Bind domain to mid IdP
    existing_binding = database.fetchone(
        leaf_tenant_id,
        "select id from saml_idp_domain_bindings where domain_id = :domain_id",
        {"domain_id": domain_id},
    )
    if not existing_binding:
        database.execute(
            leaf_tenant_id,
            """
            insert into saml_idp_domain_bindings (tenant_id, domain_id, idp_id, created_by)
            values (:tenant_id, :domain_id, :idp_id, :created_by)
            """,
            {
                "tenant_id": leaf_tenant_id,
                "domain_id": domain_id,
                "idp_id": mid_idp_id,
                "created_by": leaf_admin_id,
            },
        )
        log.info("Bound domain '%s' to mid IdP at leaf", domain_name)
    else:
        log.info("Domain binding already exists at leaf")


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------


def _teardown(log):
    log.info("Tearing down chain test tenants")
    for subdomain in (UPSTREAM_SUBDOMAIN, MID_SUBDOMAIN, LEAF_SUBDOMAIN):
        result = database.execute(
            database.UNSCOPED,
            "delete from tenants where subdomain = :subdomain",
            {"subdomain": subdomain},
        )
        if result:
            log.info("Deleted tenant: %s", subdomain)
        else:
            log.info("Tenant not found: %s", subdomain)
    log.info("Teardown complete")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(
    json_output: bool = False,
    teardown: bool = False,
):
    """Provision three-tenant chain SSO test bed."""
    log = _configure_logging(json_output)

    if teardown:
        _teardown(log)
        return

    # Step 1: Create tenants
    log.info("=== Step 1: Ensure tenants ===")
    provision_tenant(UPSTREAM_SUBDOMAIN, "E2E Upstream IdP")
    provision_tenant(MID_SUBDOMAIN, "E2E Mid IdP/SP")
    provision_tenant(LEAF_SUBDOMAIN, "E2E Leaf SP")

    # Step 2: Create admin users
    log.info("=== Step 2: Create admin users ===")
    add_user(
        UPSTREAM_SUBDOMAIN,
        f"super-{UPSTREAM_SUBDOMAIN}@upstream.test",
        DEV_PASSWORD,
        role="super_admin",
    )
    add_user(
        MID_SUBDOMAIN,
        f"super-{MID_SUBDOMAIN}@mid.test",
        DEV_PASSWORD,
        role="super_admin",
    )
    add_user(
        LEAF_SUBDOMAIN,
        f"super-{LEAF_SUBDOMAIN}@leaf.test",
        DEV_PASSWORD,
        role="super_admin",
    )

    # Look up tenant IDs and admins
    upstream_tid = _get_tenant_id(UPSTREAM_SUBDOMAIN)
    mid_tid = _get_tenant_id(MID_SUBDOMAIN)
    leaf_tid = _get_tenant_id(LEAF_SUBDOMAIN)
    upstream_admin = _get_super_admin(upstream_tid)
    mid_admin = _get_super_admin(mid_tid)
    leaf_admin = _get_super_admin(leaf_tid)

    # Step 3: Wire upstream → mid (upstream is IdP, mid is SP)
    log.info("=== Step 3: Wire upstream → mid ===")
    upstream_mid = wire_idp_to_sp(
        log,
        idp_tenant_id=upstream_tid,
        idp_admin_id=upstream_admin["id"],
        idp_subdomain=UPSTREAM_SUBDOMAIN,
        sp_tenant_id=mid_tid,
        sp_admin_id=mid_admin["id"],
        sp_subdomain=MID_SUBDOMAIN,
    )

    # Step 4: Wire mid → leaf (mid is IdP, leaf is SP)
    log.info("=== Step 4: Wire mid → leaf ===")
    mid_leaf = wire_idp_to_sp(
        log,
        idp_tenant_id=mid_tid,
        idp_admin_id=mid_admin["id"],
        idp_subdomain=MID_SUBDOMAIN,
        sp_tenant_id=leaf_tid,
        sp_admin_id=leaf_admin["id"],
        sp_subdomain=LEAF_SUBDOMAIN,
    )

    # Step 5: Set up chain test user
    log.info("=== Step 5: Chain test user ===")
    setup_chain_user(
        log,
        upstream_tenant_id=upstream_tid,
        upstream_subdomain=UPSTREAM_SUBDOMAIN,
        upstream_group_id=upstream_mid["group_id"],
        mid_tenant_id=mid_tid,
        mid_subdomain=MID_SUBDOMAIN,
        mid_group_id=mid_leaf["group_id"],
        upstream_idp_id_at_mid=upstream_mid["idp_id"],
    )

    # Step 6: Domain binding at leaf
    log.info("=== Step 6: Domain binding at leaf ===")
    setup_domain_binding(
        log,
        leaf_tenant_id=leaf_tid,
        leaf_admin_id=leaf_admin["id"],
        mid_idp_id=mid_leaf["idp_id"],
    )

    if json_output:
        config = {
            "upstream": {
                "tenant_id": upstream_tid,
                "subdomain": UPSTREAM_SUBDOMAIN,
                "base_url": _base_url(UPSTREAM_SUBDOMAIN),
                "admin_email": upstream_admin["email"],
                "admin_password": DEV_PASSWORD,
                "mid_sp_id": upstream_mid["sp_id"],
                "group_id": upstream_mid["group_id"],
            },
            "mid": {
                "tenant_id": mid_tid,
                "subdomain": MID_SUBDOMAIN,
                "base_url": _base_url(MID_SUBDOMAIN),
                "admin_email": mid_admin["email"],
                "admin_password": DEV_PASSWORD,
                "upstream_idp_id": upstream_mid["idp_id"],
                "leaf_sp_id": mid_leaf["sp_id"],
                "group_id": mid_leaf["group_id"],
            },
            "leaf": {
                "tenant_id": leaf_tid,
                "subdomain": LEAF_SUBDOMAIN,
                "base_url": _base_url(LEAF_SUBDOMAIN),
                "admin_email": leaf_admin["email"],
                "admin_password": DEV_PASSWORD,
                "mid_idp_id": mid_leaf["idp_id"],
            },
            "chain_user": {
                "email": "chain-user@upstream.test",
                "password": DEV_PASSWORD,
            },
        }
        print(json.dumps(config, indent=2))
    else:
        log.info("")
        log.info("=" * 60)
        log.info("Chain SSO Test Bed Ready")
        log.info("=" * 60)
        log.info("")
        log.info("  Upstream: %s", _base_url(UPSTREAM_SUBDOMAIN))
        log.info("  Mid:      %s", _base_url(MID_SUBDOMAIN))
        log.info("  Leaf:     %s", _base_url(LEAF_SUBDOMAIN))
        log.info("")
        log.info("  Chain user: chain-user@upstream.test (password: %s)", DEV_PASSWORD)


if __name__ == "__main__":
    argh.dispatch_command(main)
