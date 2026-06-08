#!/usr/bin/env python3
"""Closed-loop SCIM test bed (WeftID outbound -> WeftID inbound).

Provisions two tenants and wires WeftID's *outbound* SCIM at WeftID's own
*inbound* SCIM endpoint, so a worker drain pushes Generic SCIM 2.0 payloads
that must parse cleanly in our own inbound parser. This closes the loop
entirely inside the Docker E2E stack with no external receiver.

Topology:

  source tenant (scim-src)            receiving tenant (scim-dst)
  ----------------------              ---------------------------
  - super admin                       - super admin
  - >=2 member users                  - SAML IdP (key for inbound URL)
  - SP with outbound SCIM enabled  -> - inbound SCIM bearer token
    kind=generic                         (shared secret, imported into the
    target=http://app:8000/scim/v2/       source SP's outbound credential)
      inbound/{idp_id}
    credential = imported inbound token
  - weftid group "Loopback Users"
    with the member users, granted to
    the SP (fan-out enqueues on grant)

The worker reaches the app container at `http://app:8000/...` over the
`devnet` bridge. Plain HTTP is permitted only when IS_DEV is true, and the
`app` hostname is in the SCIM SSRF dev allowlist (see
`services.scim.admin._DEV_HOSTNAME_ALLOWLIST`).

Usage:
    python ./dev/scim_loopback_testbed.py --json-output
    python ./dev/scim_loopback_testbed.py --teardown

Idempotent: safe to re-run. Skips resources that already exist.
"""

from __future__ import annotations

import json
import logging
import os
import sys

import argh
import database
import database.groups
import database.saml.providers
import database.service_providers
import database.sp_group_assignments
from dev.tenants import provision_tenant
from dev.users import add_user
from schemas.scim_admin import ScimConfigUpdate
from services.types import RequestingUser
from utils.request_context import system_context

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEV_PASSWORD = os.environ.get("DEV_PASSWORD", "devpass123")

# Two member users in the source tenant, granted to the SP via the group.
# Distinct enough not to collide with `meridian-health` seed data.
SOURCE_MEMBERS = [
    {"email": "loop-alice@scim-loopback.test", "first_name": "Alice", "last_name": "Loopback"},
    {"email": "loop-bob@scim-loopback.test", "first_name": "Bob", "last_name": "Loopback"},
]

GROUP_NAME = "Loopback Users"
SP_NAME = "Loopback SCIM SP"
IDP_NAME = "Loopback Receiver IdP"

# The inbound endpoint is keyed by {idp_id}; the outbound client appends
# /Users, /Groups, /Users/<id>. So the target is the inbound base WITHOUT a
# trailing resource segment. `app:8000` is the in-stack uvicorn address.
APP_INTERNAL_BASE = os.environ.get("SCIM_LOOPBACK_APP_BASE", "http://app:8000")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _configure_logging(json_mode: bool) -> logging.Logger:
    """Configure logging. In JSON mode, ALL logs go to stderr so stdout is pure JSON."""
    stream = sys.stderr if json_mode else sys.stdout
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=stream, force=True)
    log = logging.getLogger("scim_loopback_testbed")
    log.setLevel(logging.INFO)
    return log


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


def _get_user_id_by_email(tenant_id: str, email: str) -> str:
    row = database.fetchone(
        tenant_id,
        "select user_id from user_emails where email = :email and is_primary = true limit 1",
        {"email": email},
    )
    if not row:
        raise RuntimeError(f"User {email} not found in tenant {tenant_id}")
    return str(row["user_id"])


def _requesting_user(tenant_id: str, user_id: str) -> RequestingUser:
    return RequestingUser(id=user_id, tenant_id=tenant_id, role="super_admin")


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------


def step_1_ensure_tenants(log, src_subdomain: str, dst_subdomain: str):
    log.info("--- Step 1: Ensure tenants ---")
    provision_tenant(src_subdomain, f"{src_subdomain.title()} Source")
    provision_tenant(dst_subdomain, f"{dst_subdomain.title()} Receiver")


def step_2_create_users(log, src_subdomain: str, dst_subdomain: str):
    log.info("--- Step 2: Create tenant users ---")
    # Source + receiving super admins. provision_tenant() does not create a
    # super admin (only the CLI does), so the testbed mints them directly.
    add_user(
        src_subdomain,
        f"super-{src_subdomain}@scim-loopback.test",
        DEV_PASSWORD,
        role="super_admin",
        first_name="Super",
        last_name="Admin",
    )
    add_user(
        dst_subdomain,
        f"super-{dst_subdomain}@scim-loopback.test",
        DEV_PASSWORD,
        role="super_admin",
        first_name="Super",
        last_name="Admin",
    )
    for member in SOURCE_MEMBERS:
        add_user(
            src_subdomain,
            member["email"],
            DEV_PASSWORD,
            role="member",
            first_name=member["first_name"],
            last_name=member["last_name"],
        )


def step_3_create_receiving_idp(log, dst_tenant_id: str, dst_admin_id: str) -> str:
    """Create a SAML IdP in the receiving tenant and its base group.

    The inbound SCIM endpoint is keyed by this IdP id. Returns the idp_id.
    """
    log.info("--- Step 3: Receiving-tenant IdP ---")

    existing = database.fetchone(
        dst_tenant_id,
        "select id from saml_identity_providers where name = :name limit 1",
        {"name": IDP_NAME},
    )
    if existing:
        idp_id = str(existing["id"])
        log.info("IdP already exists: %s (id=%s)", IDP_NAME, idp_id)
        return idp_id

    idp = database.saml.providers.create_identity_provider(
        tenant_id=dst_tenant_id,
        tenant_id_value=dst_tenant_id,
        name=IDP_NAME,
        provider_type="generic",
        entity_id="urn:scim-loopback:receiver:idp",
        sso_url=f"{APP_INTERNAL_BASE}/saml/idp/sso",
        sp_entity_id="urn:scim-loopback:receiver:sp",
        created_by=dst_admin_id,
        is_enabled=True,
        jit_provisioning=True,
        trust_established=True,
    )
    if not idp:
        raise RuntimeError("Failed to create receiving IdP")
    idp_id = str(idp["id"])
    log.info("Created IdP %s (id=%s)", IDP_NAME, idp_id)

    # The service layer normally creates the base group when an IdP is made
    # via the service; we used the database layer directly, so create it here.
    from services.groups.idp import create_idp_base_group

    with system_context():
        create_idp_base_group(tenant_id=dst_tenant_id, idp_id=idp_id, idp_name=IDP_NAME)
    log.info("Ensured base group for IdP %s", idp_id)
    return idp_id


def step_4_mint_inbound_token(log, dst_tenant_id: str, dst_admin_id: str, idp_id: str) -> str:
    """Mint an inbound SCIM bearer token for the receiving IdP.

    Inbound tokens are hash-only; the plaintext is returned exactly once.
    Re-runs always mint a fresh token (cheap, and the import step below
    keeps it in lockstep with the outbound credential).
    """
    log.info("--- Step 4: Inbound SCIM token (receiving tenant) ---")
    from services.scim.inbound_credentials import create_token

    ru = _requesting_user(dst_tenant_id, dst_admin_id)
    with system_context():
        created = create_token(ru, idp_id, name="scim-loopback")
    log.info("Minted inbound token id=%s", created.id)
    return created.plaintext


def step_5_register_sp(log, src_tenant_id: str, src_admin_id: str) -> str:
    """Register the outbound SP in the source tenant. Returns sp_id."""
    log.info("--- Step 5: Register outbound SP (source tenant) ---")

    existing = database.fetchone(
        src_tenant_id,
        "select id from service_providers where name = :name limit 1",
        {"name": SP_NAME},
    )
    if existing:
        sp_id = str(existing["id"])
        log.info("SP already registered: %s (id=%s)", SP_NAME, sp_id)
        return sp_id

    sp = database.service_providers.create_service_provider(
        tenant_id=src_tenant_id,
        tenant_id_value=src_tenant_id,
        name=SP_NAME,
        created_by=src_admin_id,
    )
    if not sp:
        raise RuntimeError("Failed to create service provider")
    sp_id = str(sp["id"])
    log.info("Created SP %s (id=%s)", SP_NAME, sp_id)
    return sp_id


def step_6_configure_outbound_scim(
    log, src_tenant_id: str, src_admin_id: str, sp_id: str, idp_id: str, inbound_plaintext: str
):
    """Enable outbound SCIM on the SP and import the shared bearer token.

    The target URL is the receiving tenant's inbound base. `update_scim_config`
    runs the SSRF validator against `http://app:8000/...`; the dev allowlist
    is what unblocks it. The imported credential is the SAME secret minted in
    step 4 -- that shared secret is the whole point of the loop.
    """
    log.info("--- Step 6: Configure outbound SCIM (source SP) ---")
    from services.scim.admin import import_credential, update_scim_config

    target_url = f"{APP_INTERNAL_BASE}/scim/v2/inbound/{idp_id}"
    ru = _requesting_user(src_tenant_id, src_admin_id)

    with system_context():
        update_scim_config(
            ru,
            sp_id,
            ScimConfigUpdate(
                scim_enabled=True,
                scim_target_url=target_url,
                scim_kind="generic",
                scim_membership_mode="effective",
            ),
        )
    log.info("Outbound SCIM enabled, target=%s", target_url)

    # Import the inbound plaintext as the outbound credential. Idempotent
    # enough: clear prior credentials so a re-run keeps exactly one usable
    # row matching the freshly-minted inbound token.
    database.execute(
        src_tenant_id,
        "delete from sp_scim_credentials where sp_id = cast(:sp_id as uuid)",
        {"sp_id": sp_id},
    )
    with system_context():
        import_credential(ru, sp_id, inbound_plaintext)
    log.info("Imported shared bearer token into outbound credential")


def step_7_create_group_and_grant(
    log, src_tenant_id: str, src_admin_id: str, sp_id: str
) -> tuple[str, list[str]]:
    """Create the source group with the member users and grant it to the SP.

    Granting the SP to the group logs `sp_group_assigned`, which fires the
    SCIM dispatch hook (`enqueue_grant_fan_out`) and enqueues every member
    plus the group itself -- but only because SCIM is already enabled on the
    SP (step 6 must run first). Returns (group_id, [member_user_ids]).
    """
    log.info("--- Step 7: Group + grant (drives fan-out) ---")
    from services.service_providers.group_assignments import assign_sp_to_group

    group = database.groups.get_weftid_group_by_name(src_tenant_id, GROUP_NAME)
    if group:
        group_id = str(group["id"])
        log.info("Group %s already exists (id=%s)", GROUP_NAME, group_id)
    else:
        group = database.groups.create_group(
            tenant_id=src_tenant_id,
            tenant_id_value=src_tenant_id,
            name=GROUP_NAME,
            description="Users provisioned to the loopback SCIM receiver",
            group_type="weftid",
            created_by=src_admin_id,
        )
        if not group:
            raise RuntimeError("Failed to create group")
        group_id = str(group["id"])
        log.info("Created group %s (id=%s)", GROUP_NAME, group_id)

    member_ids: list[str] = []
    for member in SOURCE_MEMBERS:
        user_id = _get_user_id_by_email(src_tenant_id, member["email"])
        member_ids.append(user_id)
        if not database.groups.is_group_member(src_tenant_id, group_id, user_id):
            database.groups.add_group_member(
                tenant_id=src_tenant_id,
                tenant_id_value=src_tenant_id,
                group_id=group_id,
                user_id=user_id,
            )
            log.info("Added %s to group", member["email"])

    # Grant the SP to the group. This is the event that fans out into
    # scim_push_queue. Skip if already assigned (re-run).
    assignments = database.sp_group_assignments.list_assignments_for_sp(src_tenant_id, sp_id)
    already = any(str(a["group_id"]) == group_id for a in assignments)
    ru = _requesting_user(src_tenant_id, src_admin_id)
    if already:
        log.info("SP already granted to group; re-enqueuing fan-out via re-grant")
        # Re-fire the fan-out directly so a re-run still has pending work.
        from services.scim.dispatch import enqueue_grant_fan_out

        with system_context():
            enqueue_grant_fan_out(
                tenant_id=src_tenant_id,
                artifact_id=sp_id,
                metadata={"group_id": group_id},
            )
    else:
        with system_context():
            assign_sp_to_group(ru, sp_id, group_id)
        log.info("Granted SP to group (fan-out enqueued)")

    return group_id, member_ids


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------


def _teardown(log, src_subdomain: str, dst_subdomain: str):
    log.info("Tearing down loopback tenants: %s, %s", src_subdomain, dst_subdomain)
    for subdomain in (src_subdomain, dst_subdomain):
        database.execute(
            database.UNSCOPED,
            "delete from tenants where subdomain = :subdomain",
            {"subdomain": subdomain},
        )
        log.info("Deleted tenant (if present): %s", subdomain)
    log.info("Teardown complete")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(
    json_output: bool = False,
    teardown: bool = False,
    src_subdomain: str = "scim-src",
    dst_subdomain: str = "scim-dst",
):
    """Provision the closed-loop SCIM test bed.

    Args:
        json_output: Emit config as JSON to stdout (logs go to stderr).
        teardown: Delete the loopback tenants instead of creating them.
        src_subdomain: Subdomain for the source (outbound) tenant.
        dst_subdomain: Subdomain for the receiving (inbound) tenant.
    """
    log = _configure_logging(json_output)

    if teardown:
        _teardown(log, src_subdomain, dst_subdomain)
        return

    step_1_ensure_tenants(log, src_subdomain, dst_subdomain)
    step_2_create_users(log, src_subdomain, dst_subdomain)

    src_tenant_id = _get_tenant_id(src_subdomain)
    dst_tenant_id = _get_tenant_id(dst_subdomain)
    src_admin = _get_super_admin(src_tenant_id)
    dst_admin = _get_super_admin(dst_tenant_id)

    idp_id = step_3_create_receiving_idp(log, dst_tenant_id, dst_admin["id"])
    inbound_plaintext = step_4_mint_inbound_token(log, dst_tenant_id, dst_admin["id"], idp_id)
    sp_id = step_5_register_sp(log, src_tenant_id, src_admin["id"])
    step_6_configure_outbound_scim(
        log, src_tenant_id, src_admin["id"], sp_id, idp_id, inbound_plaintext
    )
    group_id, member_ids = step_7_create_group_and_grant(log, src_tenant_id, src_admin["id"], sp_id)

    config = {
        "source": {
            "tenant_id": src_tenant_id,
            "subdomain": src_subdomain,
            "admin_email": src_admin["email"],
            "admin_password": DEV_PASSWORD,
            "sp_id": sp_id,
            "group_id": group_id,
            "member_user_ids": member_ids,
            "member_emails": [m["email"] for m in SOURCE_MEMBERS],
        },
        "receiver": {
            "tenant_id": dst_tenant_id,
            "subdomain": dst_subdomain,
            "admin_email": dst_admin["email"],
            "admin_password": DEV_PASSWORD,
            "idp_id": idp_id,
        },
        "target_url": f"{APP_INTERNAL_BASE}/scim/v2/inbound/{idp_id}",
        "group_name": GROUP_NAME,
    }

    if json_output:
        print(json.dumps(config, indent=2))
    else:
        log.info("")
        log.info("=" * 60)
        log.info("SCIM Loopback Test Bed Ready")
        log.info("=" * 60)
        log.info(json.dumps(config, indent=2))


if __name__ == "__main__":
    argh.dispatch_command(main)
