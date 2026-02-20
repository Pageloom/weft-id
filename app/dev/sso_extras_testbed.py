#!/usr/bin/env python3
"""Extra test data for the two-tenant E2E testbed.

Adds to the existing sso_testbed setup:
  - A domain-binding test user at the IdP tenant
  - Privileged domain + binding at the SP tenant
  - Parent/child group hierarchy at the IdP tenant for inherited access tests
  - A no-access user (not in any group) for access denial tests
  - A second SSO user for switch-account tests

Requires: sso_testbed.py to have run first.

Usage:
    python ./dev/sso_extras_testbed.py --json
    python ./dev/sso_extras_testbed.py --teardown
"""

import json
import logging
import os
import sys

import argh
import database
import database.groups
import database.sp_group_assignments
from dev.users import add_user

DEV_PASSWORD = os.environ.get("DEV_PASSWORD", "devpass123")


def _get_tenant_id(subdomain: str) -> str:
    tenant = database.fetchone(
        database.UNSCOPED,
        "select id from tenants where subdomain = :subdomain",
        {"subdomain": subdomain},
    )
    if not tenant:
        raise RuntimeError(f"Tenant '{subdomain}' not found")
    return str(tenant["id"])


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
        raise RuntimeError(f"No super_admin for tenant {tenant_id}")
    return {"id": str(user["id"]), "email": user["email"]}


def _configure_logging(json_mode: bool) -> logging.Logger:
    stream = sys.stderr if json_mode else sys.stdout
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=stream, force=True)
    log = logging.getLogger("sso_extras")
    log.setLevel(logging.INFO)
    return log


def main(
    json_output: bool = False,
    teardown: bool = False,
    idp_subdomain: str = "e2e-idp",
    sp_subdomain: str = "e2e-sp",
):
    """Add extra test data to the existing two-tenant testbed."""
    log = _configure_logging(json_output)

    if teardown:
        log.info("Extras teardown: nothing to do (data deleted with tenant)")
        return

    idp_tid = _get_tenant_id(idp_subdomain)
    sp_tid = _get_tenant_id(sp_subdomain)
    idp_admin = _get_super_admin(idp_tid)
    sp_admin = _get_super_admin(sp_tid)

    # --- 1. Domain binding test: user at IdP, domain binding at SP ---
    log.info("--- Domain binding test user ---")
    domain_test_email = "domain-test@acme.com"
    add_user(
        idp_subdomain,
        domain_test_email,
        DEV_PASSWORD,
        role="member",
        first_name="Domain",
        last_name="Test",
    )

    # Add to IdP group that has SP access
    domain_user = _get_user_by_email(idp_tid, domain_test_email)
    # Find the SSO Users group (created by base testbed)
    sso_group = database.groups.get_weftid_group_by_name(idp_tid, "SSO Users")
    if sso_group and domain_user:
        group_id = str(sso_group["id"])
        if not database.groups.is_group_member(idp_tid, group_id, domain_user["id"]):
            database.groups.add_group_member(
                tenant_id=idp_tid,
                tenant_id_value=idp_tid,
                group_id=group_id,
                user_id=domain_user["id"],
            )
            log.info("Added %s to SSO Users group at IdP", domain_test_email)

    # Create privileged domain at SP
    sp_idp = database.fetchone(
        sp_tid,
        """
        select id from saml_identity_providers
        where is_enabled = true
        limit 1
        """,
        {},
    )
    sp_idp_id = str(sp_idp["id"]) if sp_idp else None

    domain_name = "acme.com"
    existing_domain = database.fetchone(
        sp_tid,
        "select id from tenant_privileged_domains where domain = :domain",
        {"domain": domain_name},
    )
    if existing_domain:
        domain_id = str(existing_domain["id"])
        log.info("Privileged domain '%s' already exists at SP", domain_name)
    else:
        result = database.fetchone(
            sp_tid,
            """
            insert into tenant_privileged_domains (tenant_id, domain, created_by)
            values (:tenant_id, :domain, :created_by)
            returning id
            """,
            {"tenant_id": sp_tid, "domain": domain_name, "created_by": sp_admin["id"]},
        )
        if not result:
            raise RuntimeError("Failed to create privileged domain")
        domain_id = str(result["id"])
        log.info("Created privileged domain '%s' at SP", domain_name)

    # Bind domain to IdP
    if sp_idp_id:
        existing_binding = database.fetchone(
            sp_tid,
            "select id from saml_idp_domain_bindings where domain_id = :domain_id",
            {"domain_id": domain_id},
        )
        if not existing_binding:
            database.execute(
                sp_tid,
                """
                insert into saml_idp_domain_bindings (tenant_id, domain_id, idp_id, created_by)
                values (:tenant_id, :domain_id, :idp_id, :created_by)
                """,
                {
                    "tenant_id": sp_tid,
                    "domain_id": domain_id,
                    "idp_id": sp_idp_id,
                    "created_by": sp_admin["id"],
                },
            )
            log.info("Bound '%s' to IdP at SP", domain_name)

    # --- 2. Group hierarchy test ---
    log.info("--- Group hierarchy test ---")

    # Get the existing SP ID at IdP tenant (entity_id uses per-IdP format)
    sp_base = f"https://{sp_subdomain}.pageloom.localhost"
    per_idp_entity_id = f"{sp_base}/saml/metadata/{sp_idp_id}" if sp_idp_id else None
    sp_record = None
    if per_idp_entity_id:
        sp_record = database.service_providers.get_service_provider_by_entity_id(
            idp_tid, per_idp_entity_id
        )
    sp_id = str(sp_record["id"]) if sp_record else None

    # Create parent group "All Staff"
    parent_group = database.groups.get_weftid_group_by_name(idp_tid, "All Staff")
    if parent_group:
        parent_group_id = str(parent_group["id"])
        log.info("Parent group 'All Staff' already exists")
    else:
        parent_group = database.groups.create_group(
            tenant_id=idp_tid,
            tenant_id_value=idp_tid,
            name="All Staff",
            description="Parent group for hierarchy test",
            group_type="weftid",
            created_by=idp_admin["id"],
        )
        if not parent_group:
            raise RuntimeError("Failed to create parent group")
        parent_group_id = str(parent_group["id"])
        log.info("Created parent group 'All Staff' (id=%s)", parent_group_id)

    # Create child group "Engineering"
    child_group = database.groups.get_weftid_group_by_name(idp_tid, "Engineering")
    if child_group:
        child_group_id = str(child_group["id"])
        log.info("Child group 'Engineering' already exists")
    else:
        child_group = database.groups.create_group(
            tenant_id=idp_tid,
            tenant_id_value=idp_tid,
            name="Engineering",
            description="Child group for hierarchy test",
            group_type="weftid",
            created_by=idp_admin["id"],
        )
        if not child_group:
            raise RuntimeError("Failed to create child group")
        child_group_id = str(child_group["id"])
        log.info("Created child group 'Engineering' (id=%s)", child_group_id)

    # Create parent-child relationship (Engineering is child of All Staff)
    if not database.groups.relationship_exists(idp_tid, parent_group_id, child_group_id):
        database.groups.add_group_relationship(
            tenant_id=idp_tid,
            tenant_id_value=idp_tid,
            parent_group_id=parent_group_id,
            child_group_id=child_group_id,
        )
        log.info("Created relationship: All Staff → Engineering")

    # Assign SP to parent group (All Staff)
    if sp_id:
        existing_assignments = database.sp_group_assignments.list_assignments_for_sp(idp_tid, sp_id)
        already_assigned = any(str(a["group_id"]) == parent_group_id for a in existing_assignments)
        if not already_assigned:
            database.sp_group_assignments.create_assignment(
                tenant_id=idp_tid,
                tenant_id_value=idp_tid,
                sp_id=sp_id,
                group_id=parent_group_id,
                assigned_by=idp_admin["id"],
            )
            log.info("Assigned SP to 'All Staff' group")

    # Create user in child group only
    hierarchy_email = "engineer@acme.com"
    add_user(
        idp_subdomain,
        hierarchy_email,
        DEV_PASSWORD,
        role="member",
        first_name="Test",
        last_name="Engineer",
    )

    hierarchy_user = _get_user_by_email(idp_tid, hierarchy_email)
    if hierarchy_user and not database.groups.is_group_member(
        idp_tid, child_group_id, hierarchy_user["id"]
    ):
        database.groups.add_group_member(
            tenant_id=idp_tid,
            tenant_id_value=idp_tid,
            group_id=child_group_id,
            user_id=hierarchy_user["id"],
        )
        log.info("Added %s to 'Engineering' group", hierarchy_email)

    # Create pre-existing user at SP for hierarchy user (linked to IdP)
    add_user(
        sp_subdomain,
        hierarchy_email,
        DEV_PASSWORD,
        role="member",
        first_name="Test",
        last_name="Engineer",
    )
    # Link to IdP
    if sp_idp_id:
        database.execute(
            sp_tid,
            """
            update users set saml_idp_id = :idp_id
            where id = (
                select ue.user_id from user_emails ue
                join users u on u.id = ue.user_id
                where ue.email = :email and ue.is_primary = true
                limit 1
            )
            """,
            {"idp_id": sp_idp_id, "email": hierarchy_email},
        )

    # --- 3. No-access user (for access denial tests) ---
    log.info("--- No-access user ---")
    no_access_email = "no-access@acme.com"
    add_user(
        idp_subdomain,
        no_access_email,
        DEV_PASSWORD,
        role="member",
        first_name="NoAccess",
        last_name="User",
    )
    log.info("Created no-access user %s (not in any group)", no_access_email)

    # --- 4. Second SSO user (for switch-account tests) ---
    log.info("--- Second SSO user ---")
    second_sso_email = "sso-user-b@acme.com"
    add_user(
        idp_subdomain,
        second_sso_email,
        DEV_PASSWORD,
        role="member",
        first_name="Second",
        last_name="SsoUser",
    )

    # Add to SSO Users group so they have SP access
    second_sso_user = _get_user_by_email(idp_tid, second_sso_email)
    if sso_group and second_sso_user:
        group_id = str(sso_group["id"])
        if not database.groups.is_group_member(idp_tid, group_id, second_sso_user["id"]):
            database.groups.add_group_member(
                tenant_id=idp_tid,
                tenant_id_value=idp_tid,
                group_id=group_id,
                user_id=second_sso_user["id"],
            )
            log.info("Added %s to SSO Users group at IdP", second_sso_email)

    # Create pre-existing user at SP for second SSO user (linked to IdP)
    add_user(
        sp_subdomain,
        second_sso_email,
        DEV_PASSWORD,
        role="member",
        first_name="Second",
        last_name="SsoUser",
    )
    if sp_idp_id:
        database.execute(
            sp_tid,
            """
            update users set saml_idp_id = :idp_id
            where id = (
                select ue.user_id from user_emails ue
                join users u on u.id = ue.user_id
                where ue.email = :email and ue.is_primary = true
                limit 1
            )
            """,
            {"idp_id": sp_idp_id, "email": second_sso_email},
        )

    if json_output:
        config = {
            "domain_binding": {
                "test_email": domain_test_email,
                "test_password": DEV_PASSWORD,
                "domain": domain_name,
                "domain_id": domain_id,
                "sp_idp_id": sp_idp_id,
            },
            "group_hierarchy": {
                "parent_group_id": parent_group_id,
                "parent_group_name": "All Staff",
                "child_group_id": child_group_id,
                "child_group_name": "Engineering",
                "test_email": hierarchy_email,
                "test_password": DEV_PASSWORD,
                "sp_id": sp_id,
            },
            "no_access_user": {
                "email": no_access_email,
                "password": DEV_PASSWORD,
            },
            "second_sso_user": {
                "email": second_sso_email,
                "password": DEV_PASSWORD,
            },
        }
        print(json.dumps(config, indent=2))

    log.info("Extras setup complete")


if __name__ == "__main__":
    argh.dispatch_command(main)
