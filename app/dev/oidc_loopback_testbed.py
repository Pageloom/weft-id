#!/usr/bin/env python3
"""Closed-loop upstream OIDC test bed (WeftID as its own upstream IdP).

Provisions two tenants and points one tenant's *upstream* OIDC connection at
the other tenant's *downstream* OpenID Provider, so a real browser can drive
the full relying-party login (authorize -> consent -> callback -> token
exchange -> ID-token validation -> JIT provisioning) entirely inside the
Docker E2E stack with no external IdP.

Topology:

  provider tenant (e2e-oidc-op)          relying-party tenant (e2e-oidc-rp)
  ----------------------------           ----------------------------------
  - member user (the end user)           - super admin (owns the connection)
  - OAuth2 client, oidc_enabled +     <- - generic OIDC connection:
    available_to_all, redirect_uri =         issuer = https://e2e-oidc-op...
    https://e2e-oidc-rp.../auth/oidc/        client_id/secret = the OP client
    {connection_id}/callback                 enabled, default, JIT on
                                           - discovery run against the OP

Reachability: the RP's outbound fetches (discovery, JWKS, token, userinfo)
go through the SSRF guard, whose dev-only ``dev_base_domain_rewrite`` routes
``*.BASE_DOMAIN`` targets to the ``reverse-proxy`` container with the Host
header preserved. That switch is inert outside ``IS_DEV``.

Session isolation: the two tenants are distinct hosts, and the session cookie
is host-only, so the OP session and the RP session never collide.

Usage:
    python ./dev/oidc_loopback_testbed.py --json-output
    python ./dev/oidc_loopback_testbed.py --teardown

Idempotent: safe to re-run. The OAuth2 client and the OIDC connection are
recreated on every run so the client secret (only returned at creation) is
always the one stored on the connection.
"""

from __future__ import annotations

import json
import logging
import os
import sys

import argh
import database
import database.oauth2
import database.oidc_upstream
import services.oidc_upstream as oidc_service
from dev.tenants import provision_tenant
from dev.users import add_user
from schemas.oidc_upstream import OIDCConnectionCreate, OIDCConnectionUpdate
from services.types import RequestingUser
from utils.request_context import system_context

DEV_PASSWORD = os.environ.get("DEV_PASSWORD", "devpass123")

BASE_DOMAIN = os.environ.get("BASE_DOMAIN", "weftid.localhost")
OP_SUBDOMAIN = "e2e-oidc-op"
RP_SUBDOMAIN = "e2e-oidc-rp"

# The end user lives in the provider tenant only; the RP tenant JIT-creates
# a matching account on first sign-in. `example.com` validates cleanly in
# every email validator on the path (`.test` does not).
OP_USER_EMAIL = "loop-user@oidc-loopback.example.com"
OP_USER_FIRST_NAME = "Loop"
OP_USER_LAST_NAME = "User"
RP_ADMIN_EMAIL = "super-rp@oidc-loopback.example.com"

CLIENT_NAME = "Upstream OIDC Loopback RP"
CONNECTION_NAME = "Loopback OP"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _configure_logging(json_mode: bool) -> logging.Logger:
    """In JSON mode all logs go to stderr so stdout stays pure JSON."""
    stream = sys.stderr if json_mode else sys.stdout
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=stream, force=True)
    return logging.getLogger("oidc_loopback_testbed")


def _tenant_id(subdomain: str) -> str:
    row = database.fetchone(
        database.UNSCOPED,
        "select id from tenants where subdomain = :subdomain",
        {"subdomain": subdomain},
    )
    if not row:
        raise RuntimeError(f"Tenant '{subdomain}' not found")
    return str(row["id"])


def _user_id(tenant_id: str, email: str) -> str:
    from services.users import get_user_id_by_email

    uid = get_user_id_by_email(tenant_id, email)
    if uid is None:
        raise RuntimeError(f"User {email} not found in tenant {tenant_id}")
    return str(uid)


def _base_url(subdomain: str) -> str:
    return f"https://{subdomain}.{BASE_DOMAIN}"


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------


def step_1_tenants_and_users(log: logging.Logger) -> tuple[str, str]:
    log.info("--- Step 1: Tenants and users ---")
    provision_tenant(OP_SUBDOMAIN, "OIDC Loopback Provider")
    provision_tenant(RP_SUBDOMAIN, "OIDC Loopback Relying Party")
    op_tid = _tenant_id(OP_SUBDOMAIN)
    rp_tid = _tenant_id(RP_SUBDOMAIN)

    add_user(
        OP_SUBDOMAIN,
        OP_USER_EMAIL,
        DEV_PASSWORD,
        role="member",
        first_name=OP_USER_FIRST_NAME,
        last_name=OP_USER_LAST_NAME,
    )
    add_user(
        RP_SUBDOMAIN,
        RP_ADMIN_EMAIL,
        DEV_PASSWORD,
        role="super_admin",
        first_name="Super",
        last_name="Admin",
    )
    return op_tid, rp_tid


def step_2_rp_connection(log: logging.Logger, rp_tid: str, rp_admin: RequestingUser) -> str:
    """Create the RP's upstream connection (recreated on every run).

    Created BEFORE the OP client because the OP must register the RP's
    callback URL, which embeds the connection id. Client credentials are
    attached in step 4 once the OP client exists.
    """
    log.info("--- Step 2: RP upstream OIDC connection ---")
    rp_base = _base_url(RP_SUBDOMAIN)

    for existing in database.oidc_upstream.list_connections(rp_tid):
        if existing["name"] == CONNECTION_NAME:
            with system_context():
                # The service refuses to delete an enabled connection.
                if existing.get("is_enabled"):
                    oidc_service.set_connection_enabled(
                        rp_admin, str(existing["id"]), False, base_url=rp_base
                    )
                oidc_service.delete_connection(rp_admin, str(existing["id"]))
            log.info("Deleted stale connection %s", existing["id"])

    op_base = _base_url(OP_SUBDOMAIN)
    with system_context():
        conn = oidc_service.create_connection(
            rp_admin,
            OIDCConnectionCreate(
                name=CONNECTION_NAME,
                provider_type="generic",
                issuer=op_base,
                discovery_url=f"{op_base}/.well-known/openid-configuration",
                scopes="openid profile email",
                is_enabled=False,  # enabled in step 4, once credentials exist
                is_default=True,
                jit_provisioning=True,
            ),
            base_url=rp_base,
        )
    log.info("Created connection %s (id=%s)", CONNECTION_NAME, conn.id)
    return conn.id


def step_3_op_client(log: logging.Logger, op_tid: str, callback_url: str) -> dict:
    """Register the RP as an OIDC-enabled client on the provider tenant."""
    log.info("--- Step 3: OP OAuth2 client ---")
    op_user_id = _user_id(op_tid, OP_USER_EMAIL)

    for existing in database.oauth2.get_all_clients(op_tid, client_type="normal"):
        if existing["name"] == CLIENT_NAME:
            database.oauth2.delete_client(op_tid, existing["client_id"])
            log.info("Deleted stale client %s", existing["client_id"])

    client = database.oauth2.create_normal_client(
        tenant_id=op_tid,
        tenant_id_value=op_tid,
        name=CLIENT_NAME,
        redirect_uris=[callback_url],
        created_by=op_user_id,
    )
    if client is None:
        raise RuntimeError("Failed to create OP OAuth2 client")

    updated = database.oauth2.update_client_oidc_settings(
        op_tid,
        client["client_id"],
        oidc_enabled=True,
        available_to_all=True,
    )
    if not updated or not updated["oidc_enabled"]:
        raise RuntimeError("Failed to enable OIDC on the OP client")
    log.info("Created OIDC-enabled client %s", client["client_id"])
    return client


def step_4_wire_and_discover(
    log: logging.Logger,
    rp_tid: str,
    rp_admin: RequestingUser,
    connection_id: str,
    client: dict,
) -> None:
    """Attach the OP client credentials, run discovery, and enable."""
    log.info("--- Step 4: Wire credentials + discovery ---")
    rp_base = _base_url(RP_SUBDOMAIN)

    with system_context():
        oidc_service.update_connection(
            rp_admin,
            connection_id,
            OIDCConnectionUpdate(
                client_id=client["client_id"],
                client_secret=client["client_secret"],
            ),
            base_url=rp_base,
        )
        # Real discovery against the OP tenant, through the SSRF guard's dev
        # base-domain rewrite. This is the first loopback hop and fails loudly
        # if the reverse proxy is not reachable from the app container.
        row = oidc_service.run_discovery(rp_tid, connection_id, force=True)
        log.info("Discovery OK: token_endpoint=%s", row.get("token_endpoint"))
        oidc_service.set_connection_enabled(rp_admin, connection_id, True, base_url=rp_base)
    log.info("Connection enabled")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def setup(log: logging.Logger) -> dict:
    op_tid, rp_tid = step_1_tenants_and_users(log)
    rp_admin = RequestingUser(
        id=_user_id(rp_tid, RP_ADMIN_EMAIL), tenant_id=rp_tid, role="super_admin"
    )

    connection_id = step_2_rp_connection(log, rp_tid, rp_admin)
    callback_url = f"{_base_url(RP_SUBDOMAIN)}/auth/oidc/{connection_id}/callback"
    client = step_3_op_client(log, op_tid, callback_url)
    step_4_wire_and_discover(log, rp_tid, rp_admin, connection_id, client)

    return {
        "op": {
            "tenant_id": op_tid,
            "subdomain": OP_SUBDOMAIN,
            "base_url": _base_url(OP_SUBDOMAIN),
            "user_email": OP_USER_EMAIL,
            "user_first_name": OP_USER_FIRST_NAME,
            "user_last_name": OP_USER_LAST_NAME,
            "client_id": client["client_id"],
        },
        "rp": {
            "tenant_id": rp_tid,
            "subdomain": RP_SUBDOMAIN,
            "base_url": _base_url(RP_SUBDOMAIN),
            "admin_email": RP_ADMIN_EMAIL,
            "connection_id": connection_id,
            "callback_url": callback_url,
        },
    }


def teardown_testbed(log: logging.Logger) -> None:
    """Delete both tenants (cascades to users, clients, connections, links)."""
    for subdomain in (RP_SUBDOMAIN, OP_SUBDOMAIN):
        database.execute(
            database.UNSCOPED,
            "delete from tenants where subdomain = :subdomain",
            {"subdomain": subdomain},
        )
        log.info("Deleted tenant '%s'", subdomain)


def main(json_output: bool = False, teardown: bool = False):
    """Entry point.

    Args:
        json_output: print the config as JSON on stdout (for test automation).
        teardown: delete both testbed tenants and exit.
    """
    log = _configure_logging(json_output)
    if teardown:
        teardown_testbed(log)
        return
    config = setup(log)
    if json_output:
        print(json.dumps(config))
    else:
        for side, values in config.items():
            for k, v in values.items():
                print(f"{side}.{k}: {v}", file=sys.stderr)


if __name__ == "__main__":
    argh.dispatch_command(main)
