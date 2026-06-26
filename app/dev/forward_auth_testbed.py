#!/usr/bin/env python3
"""Cross-domain forward-auth test bed.

Provisions everything the forward-auth cross-domain E2E test needs:

  * a WeftID tenant on the base domain (``<sub>.weftid.localhost``),
  * a granted user,
  * a VERIFIED protected domain on a SECOND domain (``protected.localhost``)
    with a portal host (``auth.<sub>.protected.localhost``),
  * an enabled proxy app fronting the app host (``<sub>.protected.localhost``),
    emitting all four ``X-Forwarded-*`` identity headers,
  * a group granting the user access to that proxy app.

The second domain is deliberately unrelated to the WeftID base domain so the
test exercises the real cross-domain handshake (per-domain cookie scoped to
``protected.localhost``, distinct from the tenant session on
``weftid.localhost``).

Usage:
    python ./dev/forward_auth_testbed.py --json-output
    python ./dev/forward_auth_testbed.py --teardown

Idempotent: safe to re-run. Skips resources that already exist.
"""

import json
import logging
import os
import sys

import argh
import database
import database.groups
import database.protected_domains
import database.proxy_apps
import database.sp_group_assignments
from dev.tenants import provision_tenant
from dev.users import add_user

log = logging.getLogger("forward_auth_testbed")

DEV_PASSWORD = os.environ.get("DEV_PASSWORD", "devpass123")

# Base (tenant) domain vs. the second (protected) domain.
BASE_DOMAIN = "weftid.localhost"
PROTECTED_DOMAIN = "protected.localhost"

SUBDOMAIN = "e2e-fa"
USER_EMAIL = "fa-user@e2e-fa.test"
GROUP_NAME = "Forward Auth Users"
APP_NAME = "Forward Auth Demo App"


def _tenant_id(subdomain: str) -> str:
    row = database.fetchone(
        database.UNSCOPED,
        "select id from tenants where subdomain = :subdomain",
        {"subdomain": subdomain},
    )
    if not row:
        raise RuntimeError(f"Tenant '{subdomain}' not found")
    return str(row["id"])


def _portal_host() -> str:
    return f"auth.{SUBDOMAIN}.{PROTECTED_DOMAIN}"


def _app_host() -> str:
    return f"{SUBDOMAIN}.{PROTECTED_DOMAIN}"


def _domain() -> str:
    # The protected domain string. The portal/app hosts are under it.
    return f"{SUBDOMAIN}.{PROTECTED_DOMAIN}"


def setup() -> dict:
    """Provision the testbed and return its config as a dict."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    provision_tenant(SUBDOMAIN, "Forward Auth E2E")
    tid = _tenant_id(SUBDOMAIN)

    add_user(
        SUBDOMAIN,
        USER_EMAIL,
        DEV_PASSWORD,
        role="admin",
        first_name="Fae",
        last_name="Tester",
    )
    from services.users import get_user_id_by_email

    uid = get_user_id_by_email(tid, USER_EMAIL)
    assert uid is not None, "user not created"

    # Verified protected domain on the SECOND domain.
    domain = database.protected_domains.get_protected_domain_by_domain(tid, _domain())
    if domain is None:
        domain = database.protected_domains.create_protected_domain(
            tenant_id=tid,
            tenant_id_value=tid,
            domain=_domain(),
            portal_host=_portal_host(),
            created_by=str(uid),
            verification_status="verified",
        )
        log.info("Created verified protected domain: %s", _domain())
    else:
        log.info("Protected domain already exists: %s", _domain())
    assert domain is not None, "protected domain not created"

    # Enabled proxy app fronting the app host, emitting all identity headers.
    app_url = f"https://{_app_host()}"
    existing_apps = database.proxy_apps.list_proxy_apps_for_domain(tid, str(domain["id"]))
    app = next((a for a in existing_apps if a["name"] == APP_NAME), None)
    if app is None:
        app = database.proxy_apps.create_proxy_app(
            tenant_id=tid,
            tenant_id_value=tid,
            protected_domain_id=str(domain["id"]),
            name=APP_NAME,
            external_url=app_url,
            created_by=str(uid),
            public_paths=["/public/*"],
            header_config={"user": True, "email": True, "groups": True, "display_name": True},
            available_to_all=False,
            enabled=True,
        )
        log.info("Created proxy app: %s -> %s", APP_NAME, app_url)
    else:
        log.info("Proxy app already exists: %s", APP_NAME)
    assert app is not None, "proxy app not created"

    # Group granting the user access to the proxy app.
    groups = database.groups.list_groups(tid)
    group = next((g for g in groups if g["name"] == GROUP_NAME), None)
    if group is None:
        group = database.groups.create_group(
            tenant_id=tid,
            tenant_id_value=tid,
            name=GROUP_NAME,
            description="Grants forward-auth demo app access",
            group_type="weftid",
        )
    assert group is not None, "group not created"
    database.groups.add_group_member(tid, tid, str(group["id"]), str(uid))
    # Idempotent grant: skip if it already exists.
    existing_grants = database.sp_group_assignments.list_assignments_for_proxy_app(
        tid, str(app["id"])
    )
    if not any(str(g["group_id"]) == str(group["id"]) for g in existing_grants):
        database.sp_group_assignments.create_proxy_app_assignment(
            tid, tid, str(app["id"]), str(group["id"]), str(uid)
        )
        log.info("Granted '%s' access to proxy app", GROUP_NAME)

    return {
        "tenant_id": tid,
        "subdomain": SUBDOMAIN,
        "tenant_host": f"{SUBDOMAIN}.{BASE_DOMAIN}",
        "canonical_base_url": f"https://{SUBDOMAIN}.{BASE_DOMAIN}",
        "protected_domain": _domain(),
        "portal_host": _portal_host(),
        "portal_base_url": f"https://{_portal_host()}",
        "app_host": _app_host(),
        "app_url": f"https://{_app_host()}",
        "proxy_app_id": str(app["id"]),
        "user_email": USER_EMAIL,
        "password": DEV_PASSWORD,
    }


def teardown():
    """Delete the testbed tenant (cascades to domains, apps, grants, users)."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    database.execute(
        database.UNSCOPED,
        "delete from tenants where subdomain = :subdomain",
        {"subdomain": SUBDOMAIN},
    )
    log.info("Deleted tenant '%s'", SUBDOMAIN)


def main(json_output: bool = False, teardown_flag: bool = False):
    """Entry point.

    Args:
        json_output: print the config as JSON (for test automation).
        teardown_flag: delete the testbed tenant and exit.
    """
    if teardown_flag:
        teardown()
        return
    config = setup()
    if json_output:
        print(json.dumps(config))
    else:
        for k, v in config.items():
            print(f"{k}: {v}", file=sys.stderr)


if __name__ == "__main__":
    # argh maps --json-output / --teardown-flag from the kwargs above.
    argh.dispatch_command(main)
