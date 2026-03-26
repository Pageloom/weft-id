#!/usr/bin/env python3
"""Send preview versions of every email type to MailDev.

Sends one example of each email function with sample data so you can
visually inspect the branded layout, inline styles, header/footer, and
CTA buttons in the MailDev web UI (http://localhost:1080).

Usage:
    docker compose exec app python ./dev/preview_emails.py

Optionally pass a tenant subdomain to use that tenant's real branding:
    docker compose exec app python ./dev/preview_emails.py \
        --tenant meridian-health
"""

import argparse
import sys

import database
import database.tenants
from utils import email as em

TO = "preview@example.com"
BASE = "https://acme.example.com"


def _send_all(kw: dict) -> list[tuple[str, bool]]:
    """Send every email type and return (name, success) pairs."""
    verify = f"{BASE}/verify-email/abc/def"
    cred_set = f"{BASE}/set-password?email_id=abc&nonce=1"  # noqa: S105 (not a real credential)
    cred_reset = f"{BASE}/reset-password/token123"  # noqa: S105
    login = f"{BASE}/login"
    reqs = f"{BASE}/admin/reactivation-requests"

    return [
        ("Sign-in code", em.send_email_possession_code(TO, "847291", **kw)),
        ("MFA code", em.send_mfa_code_email(TO, "583016", **kw)),
        ("Email verification", em.send_email_verification(TO, verify, **kw)),
        (
            "Secondary email added",
            em.send_secondary_email_added_notification(TO, "alt@example.com", "Jane Admin", **kw),
        ),
        (
            "Secondary email removed",
            em.send_secondary_email_removed_notification(TO, "old@example.com", "Jane Admin", **kw),
        ),
        (
            "Primary email changed",
            em.send_primary_email_changed_notification(TO, "new@example.com", "Jane Admin", **kw),
        ),
        (
            "Welcome (privileged domain)",
            em.send_new_user_privileged_domain_notification(
                TO, "Jane Admin", "Acme Corp", cred_set, **kw
            ),
        ),
        (
            "Invitation (verification)",
            em.send_new_user_invitation(TO, "Jane Admin", "Acme Corp", verify, **kw),
        ),
        ("Account reactivated", em.send_account_reactivated_notification(TO, login, **kw)),
        ("Reactivation denied", em.send_reactivation_denied_notification(TO, **kw)),
        (
            "Reactivation request (admin)",
            em.send_reactivation_request_admin_notification(
                TO, "John Doe", "john@example.com", reqs, **kw
            ),
        ),
        ("Provisioning invitation", em.send_provisioning_invitation(TO, "Acme Corp", verify, **kw)),
        (
            "MFA reset",
            em.send_mfa_reset_notification(TO, "Jane Admin", "2026-03-24 14:30 UTC", **kw),
        ),
        ("Forgot-credential reset", em.send_password_reset_email(TO, cred_reset, **kw)),
        ("HIBP breach (admin)", em.send_hibp_breach_admin_notification(TO, 3, **kw)),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Send preview emails to MailDev",
    )
    parser.add_argument(
        "--tenant",
        help="Subdomain for real branding (omit for unbranded)",
    )
    args = parser.parse_args()

    tenant_id = None
    if args.tenant:
        tenant = database.tenants.get_tenant_by_subdomain(args.tenant)
        if not tenant:
            print(f"Tenant '{args.tenant}' not found", file=sys.stderr)
            return 1
        tenant_id = str(tenant["id"])
        print(f"Branding from: {args.tenant} ({tenant_id})")
    else:
        print("Sending without tenant branding (no --tenant)")

    results = _send_all({"tenant_id": tenant_id})

    sent = 0
    for name, ok in results:
        status = "OK" if ok else "FAILED"
        print(f"  [{status}] {name}")
        if ok:
            sent += 1

    print(f"\n{sent}/{len(results)} sent. MailDev: http://localhost:1080")
    return 0 if sent == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
