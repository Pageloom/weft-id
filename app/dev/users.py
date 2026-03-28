#!/usr/bin/env python3
import logging

import argh
import database
import utils.password
import utils.validate


def add_user(
    subdomain: str,
    email: str,
    password: str,
    role: str = "member",
    first_name: str | None = None,
    last_name: str | None = None,
):
    """Create a user with a specified role, email, and password for a tenant.

    Args:
        subdomain: Tenant subdomain
        email: User email address
        password: User password
        role: User role ('super_admin', 'admin', or 'member'). Defaults to 'member'.
        first_name: User's first name (optional, defaults based on role)
        last_name: User's last name (optional, defaults based on role)
    """
    utils.validate.subdomain(subdomain)

    # Validate role
    valid_roles = ["super_admin", "admin", "member"]
    if role not in valid_roles:
        raise ValueError(f"Invalid role: {role}. Must be one of {valid_roles}")

    # Set default names based on a role if not provided
    if first_name is None or last_name is None:
        role_defaults = {
            "super_admin": ("Super", "Admin"),
            "admin": ("Admin", "User"),
            "member": ("Member", "User"),
        }
        default_first, default_last = role_defaults[role]
        first_name = first_name or default_first
        last_name = last_name or default_last

    # Get tenant ID from subdomain
    tenant = database.fetchone(
        database.UNSCOPED,
        "select id from tenants where subdomain = :subdomain",
        {"subdomain": subdomain},
    )

    if not tenant:
        raise ValueError(f"Tenant with subdomain {subdomain} not found")

    tenant_id = tenant["id"]

    # Check if user with this email already exists
    existing = database.fetchone(
        tenant_id,
        "select user_id from user_emails where email = :email",
        {"email": email},
    )

    if existing:
        logging.info("User %s already exists for tenant %s", email, subdomain)
        return

    password_hash = utils.password.hash_password(password)

    # Create user
    user = database.fetchone(
        tenant_id,
        """
        insert into users (tenant_id, first_name, last_name, role, password_hash)
        values (:tenant_id, :first_name, :last_name, :role, :password_hash)
        returning id
        """,
        {
            "tenant_id": tenant_id,
            "first_name": first_name,
            "last_name": last_name,
            "role": role,
            "password_hash": password_hash,
        },
    )

    if not user:
        raise RuntimeError("Failed to create user")

    user_id = user["id"]

    # Create email (primary and verified)
    database.execute(
        tenant_id,
        """
        insert into user_emails (tenant_id, user_id, email, is_primary, verified_at, domain)
        values (:tenant_id, :user_id, :email, true, now(), :domain)
        """,
        {"tenant_id": tenant_id, "user_id": user_id, "email": email, "domain": email.split("@")[1]},
    )

    logging.info("Created %s user %s for tenant %s", role, email, subdomain)


if __name__ == "__main__":
    argh.dispatch_command(add_user)
