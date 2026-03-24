"""Provision a new tenant and super admin via CLI.

Usage:
    python -m app.cli.provision_tenant \
        --subdomain acme \
        --tenant-name "Acme Corp" \
        --email admin@acme.com \
        --first-name Jane \
        --last-name Smith
"""

import argparse
import os
import sys

# Add app directory to path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import database.branding  # noqa: E402
import database.tenants  # noqa: E402
import settings  # noqa: E402
import utils.validate  # noqa: E402
from dev.tenants import provision_tenant  # noqa: E402
from services.branding import _rasterize_to_png  # noqa: E402
from services.event_log import SYSTEM_ACTOR_ID, log_event  # noqa: E402
from services.users.utilities import (  # noqa: E402
    add_unverified_email_with_nonce,
    create_user_raw,
    email_exists,
)
from utils.email import send_provisioning_invitation  # noqa: E402
from utils.mandala import generate_mandala_svg  # noqa: E402
from utils.request_context import system_context  # noqa: E402


def _validate_args(args: argparse.Namespace) -> list[str]:
    """Validate all arguments up front. Returns list of error messages."""
    errors = []

    try:
        utils.validate.subdomain(args.subdomain)
    except ValueError as e:
        errors.append(f"Invalid subdomain: {e}")

    if not args.email or "@" not in args.email:
        errors.append("Invalid email address")

    if not args.first_name or len(args.first_name.strip()) == 0:
        errors.append("First name cannot be empty")
    elif len(args.first_name) > 255:
        errors.append("First name too long (max 255 characters)")

    if not args.last_name or len(args.last_name.strip()) == 0:
        errors.append("Last name cannot be empty")
    elif len(args.last_name) > 255:
        errors.append("Last name too long (max 255 characters)")

    if not args.tenant_name or len(args.tenant_name.strip()) == 0:
        errors.append("Tenant name cannot be empty")
    elif len(args.tenant_name) > 80:
        errors.append("Tenant name too long (max 80 characters)")

    return errors


def main(args: argparse.Namespace) -> int:
    """Run tenant provisioning. Returns exit code."""
    # Validate all inputs before any DB writes
    errors = _validate_args(args)
    if errors:
        for error in errors:
            print(f"Error: {error}", file=sys.stderr)
        return 1

    with system_context():
        # Provision tenant (idempotent via ON CONFLICT)
        provision_tenant(args.subdomain, args.tenant_name)

        tenant = database.tenants.get_tenant_by_subdomain(args.subdomain)
        if not tenant:
            print("Error: Failed to create or find tenant", file=sys.stderr)
            return 1

        tenant_id = str(tenant["id"])
        print(f"Tenant: {args.tenant_name} ({args.subdomain})")
        print(f"Tenant ID: {tenant_id}")

        # Pre-rasterize default mandala for email branding
        light_svg, _dark_svg, _favicon_svg = generate_mandala_svg(tenant_id)
        png_data = _rasterize_to_png(light_svg.encode("utf-8"), "image/svg+xml")
        if png_data:
            database.branding.upsert_email_logo_png(
                tenant_id=tenant_id,
                tenant_id_value=tenant_id,
                png_data=png_data,
            )

        # Check for duplicate email
        if email_exists(tenant_id, args.email):
            print(f"Error: Email {args.email} already exists in this tenant", file=sys.stderr)
            return 1

        # Create super admin user
        user_result = create_user_raw(
            tenant_id, args.first_name, args.last_name, args.email, "super_admin"
        )
        if not user_result:
            print("Error: Failed to create user", file=sys.stderr)
            return 1

        user_id = str(user_result["user_id"])

        # Add unverified email
        email_result = add_unverified_email_with_nonce(tenant_id, user_id, args.email)
        if not email_result:
            print("Error: Failed to add email address", file=sys.stderr)
            return 1

        email_id = str(email_result["id"])
        verify_nonce = email_result["verify_nonce"]

        # Log event
        log_event(
            tenant_id=tenant_id,
            actor_user_id=SYSTEM_ACTOR_ID,
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_created",
            metadata={"role": "super_admin", "email": args.email, "source": "cli"},
        )

        # Build verification URL
        verification_url = (
            f"https://{args.subdomain}.{settings.BASE_DOMAIN}"
            f"/verify-email/{email_id}/{verify_nonce}"
        )

        # Send invitation email
        email_sent = send_provisioning_invitation(
            args.email, args.tenant_name, verification_url, tenant_id=tenant_id
        )
        if not email_sent:
            print("Warning: Failed to send invitation email", file=sys.stderr)
            print(f"Verification URL: {verification_url}")
        else:
            print(f"Invitation sent to {args.email}")

        print(f"Super admin created: {args.first_name} {args.last_name} ({args.email})")

    return 0


def cli() -> int:
    """Parse arguments and run provisioning."""
    parser = argparse.ArgumentParser(description="Provision a new tenant and super admin")
    parser.add_argument("--subdomain", required=True, help="Tenant subdomain")
    parser.add_argument("--tenant-name", required=True, help="Tenant display name")
    parser.add_argument("--email", required=True, help="Super admin email address")
    parser.add_argument("--first-name", required=True, help="Super admin first name")
    parser.add_argument("--last-name", required=True, help="Super admin last name")

    args = parser.parse_args()
    return main(args)


if __name__ == "__main__":
    sys.exit(cli())
