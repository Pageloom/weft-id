"""Reactivate an inactivated user account via CLI.

This is the out-of-band escape hatch for reactivating users when no active
admin is available to do it through the web interface. The primary use case
is recovering from a state where all super admins have been inactivated
(e.g., by the auto-inactivation job).

Usage:
    python -m app.cli.reactivate_user \
        --subdomain acme \
        --email admin@acme.com
"""

import argparse
import os
import sys

# Add app directory to path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import database.tenants  # noqa: E402
import database.user_emails  # noqa: E402
import database.users  # noqa: E402
from services.event_log import SYSTEM_ACTOR_ID, log_event  # noqa: E402
from utils.request_context import system_context  # noqa: E402


def main(args: argparse.Namespace) -> int:
    """Run user reactivation. Returns exit code."""
    email = args.email.strip().lower()

    if not email or "@" not in email:
        print("Error: Invalid email address", file=sys.stderr)
        return 1

    with system_context():
        # Look up tenant
        tenant = database.tenants.get_tenant_by_subdomain(args.subdomain)
        if not tenant:
            print(f"Error: Tenant '{args.subdomain}' not found", file=sys.stderr)
            return 1

        tenant_id = str(tenant["id"])

        # Look up user by email
        user = database.users.get_user_by_email_with_status(tenant_id, email)
        if not user:
            print(
                f"Error: No user found with email '{email}' in tenant '{args.subdomain}'",
                file=sys.stderr,
            )
            return 1

        user_id = str(user["id"])
        user_name = f"{user['first_name']} {user['last_name']}"

        # Check if already active
        if not user.get("inactivated_at"):
            print(f"User {user_name} ({email}) is already active. Nothing to do.", file=sys.stderr)
            return 1

        # Reactivate
        database.users.reactivate_user(tenant_id, user_id)
        database.users.clear_reactivation_denied(tenant_id, user_id)

        # Log event
        log_event(
            tenant_id=tenant_id,
            actor_user_id=SYSTEM_ACTOR_ID,
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_reactivated_cli",
            metadata={"source": "cli", "email": email, "role": user["role"]},
        )

        print(f"Reactivated: {user_name} ({email}), role: {user['role']}")

    return 0


def cli() -> int:
    """Parse arguments and run reactivation."""
    parser = argparse.ArgumentParser(description="Reactivate an inactivated user account")
    parser.add_argument("--subdomain", required=True, help="Tenant subdomain")
    parser.add_argument("--email", required=True, help="User's primary email address")

    args = parser.parse_args()
    return main(args)


if __name__ == "__main__":
    sys.exit(cli())
