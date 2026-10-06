"""Email confirmation for sign-ins through untrusted-email providers.

A provider whose preset has ``email_linking_trusted=False`` (Facebook,
Microsoft personal accounts) does not prove that the user controls the email
address it reports. JIT provisioning still creates the user from it, but
stores the address unverified and holds back the email-domain group
assignment. The sign-in then completes only after the user enters a code
WeftID sent to that address; :func:`confirm_sign_in_email` marks it verified
and runs the domain group assignment the public verification link would.

Until the address is confirmed, every sign-in through such a provider asks
for it again. Trusted providers are unaffected: their JIT users get a
verified address, as before.
"""

from __future__ import annotations

import database
from services.event_log import log_event
from services.oidc_upstream.presets import email_linking_trusted


def requires_confirmed_email(provider_type: str | None) -> bool:
    """Whether a provider's sign-ins must confirm the user's email with WeftID."""
    return not email_linking_trusted(provider_type or "")


def pending_email_confirmation(tenant_id: str, connection: dict, user_id: str) -> dict | None:
    """Return the address a sign-in must confirm before it completes, if any.

    Returns ``{"email_id", "email"}`` when the connection's provider is
    untrusted and the user's primary address is unverified; None otherwise.
    No authorization: called from the public sign-in callback with a user the
    provider has just authenticated.
    """
    if not requires_confirmed_email(connection.get("provider_type")):
        return None
    row = database.user_emails.get_primary_email_for_resend(tenant_id, user_id)
    if row is None or row.get("verified_at"):
        return None
    return {"email_id": str(row["id"]), "email": row["email"]}


def confirm_sign_in_email(
    tenant_id: str,
    user_id: str,
    email_id: str,
    connection_id: str,
) -> None:
    """Mark a sign-in's email confirmed (the user entered the emailed code).

    Logs ``email_verified`` and assigns the user to the groups linked to the
    address's domain, as verifying through the emailed link does. The caller
    has checked the code against this user and address.
    """
    from services import settings as settings_service

    row = database.user_emails.get_primary_email_for_resend(tenant_id, user_id)
    if row is None or str(row["id"]) != email_id or row.get("verified_at"):
        return

    database.user_emails.verify_email(tenant_id, email_id)
    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        artifact_type="user",
        artifact_id=user_id,
        event_type="email_verified",
        metadata={
            "email_id": email_id,
            "email": row["email"],
            "flow": "oidc_sign_in",
            "idp_id": connection_id,
        },
    )
    settings_service.auto_assign_user_to_domain_groups(tenant_id, user_id, row["email"], user_id)
