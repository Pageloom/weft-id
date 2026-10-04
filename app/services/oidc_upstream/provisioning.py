"""OIDC upstream JIT provisioning and authentication completion.

Mirrors ``services.saml.provisioning`` for the relying-party direction of
OIDC. Correlation is on the ``(idp_id, sub)`` pair (where ``sub`` is the claim
named by the connection's ``correlation_claim``), not on email: the OIDC
``sub`` is the stable subject and survives upstream email changes.

The flow has three branches for an unrecognized subject:

1. An existing ``oidc_idp_user_links`` row authenticates that user.
2. No link + ``allow_email_linking`` + a provider trusted for email linking
   + ``email_verified: true`` + a matching existing email links the subject
   to that account.
3. No link + JIT enabled provisions a new user.

``allow_email_linking=false`` never attaches an unrecognized subject to an
existing account (account-takeover guard). A user may hold links to several
connections, but only one per connection: email linking never attaches a
second upstream account to a user already linked on the connection.

A user assigned to a SAML IdP is refused on every branch. SAML assignment is
the tenant's policy for that user and an OIDC link must not bypass it.

Every successful sign-in stamps the link's ``last_used_at``, which
email-first routing uses to pick among a user's links.
"""

import logging

import database
from services.event_log import log_event
from services.exceptions import ForbiddenError, NotFoundError, ValidationError
from services.oidc_upstream.email_confirmation import requires_confirmed_email
from services.oidc_upstream.presets import email_linking_trusted
from utils.validate import is_email_like

# How a user reached the provider, recorded on sign-in audit events: a
# "Continue with ..." button on the sign-in page, or any other route (email-
# first routing, the default connection, a direct link).
ENTRY_LOGIN_BUTTON = "login_button"
ENTRY_ROUTED = "routed"

logger = logging.getLogger(__name__)


def _extract_claims(claims: dict, claim_mapping: dict[str, str]) -> dict[str, str | None]:
    """Map OIDC claims to WeftID standard attributes via the claim mapping.

    The mapping is ``{weftid_attribute: oidc_claim}`` (e.g. ``{"email":
    "email", "first_name": "given_name"}``). Returns a dict of
    ``{weftid_attribute: value}`` with missing claims as ``None``.
    """
    result: dict[str, str | None] = {}
    for attr, claim in claim_mapping.items():
        value = claims.get(claim)
        result[attr] = value if isinstance(value, str) else None
    return result


def _extract_standard_attributes(
    claims: dict,
    claim_mapping: dict[str, str],
) -> dict[str, str]:
    """Lift the 14 standard registry attributes from OIDC claims.

    The claim_mapping is ``{weftid_attribute: oidc_claim}``. For each standard
    registry key present in the mapping, look up the mapped OIDC claim in the
    claims and return non-empty string values. Fixed keys (email, first_name,
    last_name) are not standard attributes and are excluded here -- they are
    handled by ``_extract_claims`` for JIT provisioning.
    """
    from constants.user_attributes import STANDARD_ATTRIBUTES

    result: dict[str, str] = {}
    for attr in STANDARD_ATTRIBUTES:
        claim = claim_mapping.get(attr.key)
        if not claim:
            continue
        value = claims.get(claim)
        if isinstance(value, str) and value.strip():
            result[attr.key] = value
    return result


def jit_provision_user(
    tenant_id: str,
    connection: dict,
    sub: str,
    claims: dict,
    entry: str = ENTRY_ROUTED,
) -> dict:
    """Create a new user via JIT provisioning from OIDC claims.

    Creates a user with a NULL password (OIDC-only authentication), an email
    (verified, unless the provider's emails are untrusted: then the sign-in
    must confirm it), an ``oidc_idp_user_links`` row, base-group membership, domain-group
    auto-assignment, and logs ``oidc_user_jit_provisioned``.

    Args:
        tenant_id: Tenant ID.
        connection: The OIDC connection row (dict).
        sub: The correlation subject (the ``correlation_claim`` value).
        claims: The validated ID-token claims (plus any userinfo claims).
        entry: How the user reached the provider, recorded on the event.

    Returns:
        The created user dict (for session creation).

    Raises:
        ValidationError if the email is not email-shaped or user creation fails.
    """
    from services import settings as settings_service
    from services import users as users_service

    claim_mapping = connection.get("claim_mapping") or {}
    attrs = _extract_claims(claims, claim_mapping)

    email = attrs.get("email")
    first_name = attrs.get("first_name") or "OIDC"
    last_name = attrs.get("last_name") or "User"

    if not email or not is_email_like(email):
        raise ValidationError(
            message="OIDC claims did not provide a valid email address",
            code="oidc_jit_invalid_email",
        )

    # Account-takeover guard: JIT must never attach to a pre-existing account.
    # OIDC correlates on (idp_id, sub), not email; an email match here means
    # the email is already claimed by a different account. Reject rather than
    # silently authenticating as that account (which would bypass the
    # allow_email_linking guard and the email_verified check).
    if users_service.email_exists(tenant_id, email):
        raise ValidationError(
            message="Email already exists for another account",
            code="oidc_jit_email_exists",
        )

    result = users_service.create_user_raw(
        tenant_id=tenant_id,
        first_name=first_name,
        last_name=last_name,
        email=email,
        role="member",
    )

    if not result:
        raise ValidationError(
            message="Failed to create user via OIDC JIT provisioning",
            code="oidc_jit_user_creation_failed",
        )

    user_id = str(result["user_id"])

    # A provider that does not prove the address (Facebook, Microsoft
    # personal) gets it stored unverified; the sign-in then asks the user to
    # confirm it (services.oidc_upstream.email_confirmation).
    unconfirmed = requires_confirmed_email(connection.get("provider_type"))
    if unconfirmed:
        users_service.add_unverified_email_with_nonce(
            tenant_id=tenant_id,
            user_id=user_id,
            email=email,
            is_primary=True,
        )
    else:
        users_service.add_verified_email_with_nonce(
            tenant_id=tenant_id,
            user_id=user_id,
            email=email,
            is_primary=True,
        )

    # Link the user to the (idp_id, sub) pair.
    database.oidc_upstream.create_link(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        idp_id=str(connection["id"]),
        sub=sub,
        user_id=user_id,
    )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        artifact_type="user",
        artifact_id=user_id,
        event_type="user_oidc_idp_assigned",
        metadata={
            "idp_id": str(connection["id"]),
            "idp_name": connection["name"],
            "sub": sub,
            "assigned_via": "jit_provisioning",
        },
    )

    # Base-group membership and group-claim sync happen in
    # ``authenticate_via_oidc`` after provisioning, on the same path as the
    # existing-link and email-link branches.

    # Auto-assign to domain-linked groups (protocol-agnostic, email-domain
    # based, so it works for OIDC users unchanged). An unconfirmed address
    # proves nothing about its domain: confirming it assigns them instead.
    if not unconfirmed:
        settings_service.auto_assign_user_to_domain_groups(tenant_id, user_id, email, user_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        artifact_type="user",
        artifact_id=user_id,
        event_type="oidc_user_jit_provisioned",
        metadata={
            "idp_id": str(connection["id"]),
            "idp_name": connection["name"],
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "sub": sub,
            "entry": entry,
            "email_verified": not unconfirmed,
        },
    )

    # The usual lookup only sees verified addresses.
    if unconfirmed:
        user = database.users.get_user_by_email_for_saml(tenant_id, email)
    else:
        user = database.users.get_user_by_email_with_status(tenant_id, email)
    if not user:
        raise ValidationError(
            message="Failed to retrieve created user",
            code="oidc_jit_user_retrieval_failed",
        )

    return user


def authenticate_via_oidc(
    tenant_id: str,
    connection: dict,
    sub: str,
    claims: dict,
    entry: str = ENTRY_ROUTED,
) -> dict:
    """Complete OIDC authentication and return the user.

    Correlation order:

    1. Existing ``(idp_id, sub)`` link -> authenticate that user.
    2. No link + ``allow_email_linking`` + trusted provider +
       ``email_verified: true`` + matching email -> link and authenticate.
    3. No link + JIT enabled -> provision.
    4. Otherwise -> reject.

    Inactivated users are rejected (matching SAML). Users assigned to a SAML
    IdP are rejected (``saml_assigned_user``), as is an email link to a user
    already linked to this connection under another subject
    (``oidc_connection_already_linked``). Both log
    ``oidc_login_refused``.

    Args:
        tenant_id: Tenant ID.
        connection: The OIDC connection row (dict).
        sub: The correlation subject.
        claims: The validated ID-token claims.
        entry: How the user reached the provider (``ENTRY_LOGIN_BUTTON`` or
            ``ENTRY_ROUTED``), recorded on the sign-in and refusal events.

    Returns:
        The user dict for session creation.

    Raises:
        NotFoundError if no link, no email-link, and JIT disabled.
        ForbiddenError if the user is inactivated, assigned to a SAML IdP, or
        already linked to this connection under another subject.
    """
    connection_id = str(connection["id"])

    # 1. Existing link.
    linked_user_id = database.oidc_upstream.get_user_id_by_sub(tenant_id, connection_id, sub)
    if linked_user_id is not None:
        user = database.users.get_user_by_id(tenant_id, linked_user_id)
        if user is None:
            raise NotFoundError(
                message="Linked user account not found",
                code="oidc_linked_user_not_found",
            )
        if user.get("inactivated_at"):
            raise ForbiddenError(
                message="User account is inactivated",
                code="user_inactivated",
            )
        _refuse_saml_assigned(tenant_id, user, connection, sub, entry)
        _apply_oidc_idp_attributes_safe(tenant_id, str(user["id"]), connection, claims)
        _sync_groups(tenant_id, str(user["id"]), connection, claims, user)
        database.oidc_upstream.touch_link(tenant_id, connection_id, sub)
        _log_sign_in(tenant_id, str(user["id"]), connection, sub, entry)
        return user

    # 2. Email linking (opt-in, gated on email_verified).
    # The trust rule is checked here as well as on save: a connection saved
    # before the rule existed must still not email-link.
    if connection.get("allow_email_linking") and email_linking_trusted(
        connection.get("provider_type") or ""
    ):
        email = _extract_claims(claims, connection.get("claim_mapping") or {}).get("email")
        if email and claims.get("email_verified") is True:
            existing = database.users.get_user_by_email_for_saml(tenant_id, email)
            if existing is not None:
                if existing.get("inactivated_at"):
                    raise ForbiddenError(
                        message="User account is inactivated",
                        code="user_inactivated",
                    )
                _refuse_saml_assigned(tenant_id, existing, connection, sub, entry)
                user_id = str(existing["id"])
                if database.oidc_upstream.get_link_for_user_idp(tenant_id, user_id, connection_id):
                    _log_refusal(tenant_id, user_id, connection, sub, "already_linked", entry)
                    raise ForbiddenError(
                        message="User is already linked to this connection",
                        code="oidc_connection_already_linked",
                    )
                if not existing.get("email_verified"):
                    database.user_emails.verify_email(tenant_id, str(existing["email_id"]))
                database.oidc_upstream.create_link(
                    tenant_id=tenant_id,
                    tenant_id_value=tenant_id,
                    idp_id=connection_id,
                    sub=sub,
                    user_id=user_id,
                )
                log_event(
                    tenant_id=tenant_id,
                    actor_user_id=user_id,
                    artifact_type="user",
                    artifact_id=user_id,
                    event_type="user_oidc_idp_linked",
                    metadata={
                        "idp_id": connection_id,
                        "idp_name": connection["name"],
                        "sub": sub,
                        "email": email,
                    },
                )
                log_event(
                    tenant_id=tenant_id,
                    actor_user_id=user_id,
                    artifact_type="user",
                    artifact_id=user_id,
                    event_type="user_oidc_idp_assigned",
                    metadata={
                        "idp_id": connection_id,
                        "idp_name": connection["name"],
                        "sub": sub,
                        "assigned_via": "email_linking",
                    },
                )
                _apply_oidc_idp_attributes_safe(tenant_id, user_id, connection, claims)
                _sync_groups(tenant_id, user_id, connection, claims, existing)
                database.oidc_upstream.touch_link(tenant_id, connection_id, sub)
                _log_sign_in(tenant_id, user_id, connection, sub, entry)
                return existing

    # 3. JIT provisioning.
    if connection.get("jit_provisioning"):
        # Recorded by oidc_user_jit_provisioned alone, mirroring SAML JIT.
        user = jit_provision_user(tenant_id, connection, sub, claims, entry)
        _apply_oidc_idp_attributes_safe(tenant_id, str(user["id"]), connection, claims)
        _sync_groups(tenant_id, str(user["id"]), connection, claims, user)
        database.oidc_upstream.touch_link(tenant_id, connection_id, sub)
        return user

    # 4. Reject.
    raise NotFoundError(
        message="User account not found",
        code="user_not_found",
        details={"sub": sub},
    )


def _refuse_saml_assigned(
    tenant_id: str,
    user: dict,
    connection: dict,
    sub: str,
    entry: str,
) -> None:
    """Refuse an OIDC sign-in for a user assigned to a SAML IdP."""
    if not user.get("saml_idp_id"):
        return
    user_id = str(user["id"])
    _log_refusal(tenant_id, user_id, connection, sub, "saml_assigned_user", entry)
    raise ForbiddenError(
        message="User signs in through a SAML identity provider",
        code="saml_assigned_user",
    )


def _log_refusal(
    tenant_id: str,
    user_id: str,
    connection: dict,
    sub: str,
    reason: str,
    entry: str,
) -> None:
    """Log ``oidc_login_refused`` for a known user turned away by policy."""
    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        artifact_type="user",
        artifact_id=user_id,
        event_type="oidc_login_refused",
        metadata={
            "idp_id": str(connection["id"]),
            "idp_name": connection["name"],
            "sub": sub,
            "reason": reason,
            "entry": entry,
        },
    )


def _sync_groups(
    tenant_id: str,
    user_id: str,
    connection: dict,
    claims: dict,
    user: dict,
) -> None:
    """Base-group membership plus group-claim sync for a signed-in user.

    Not soft-failed on purpose: group membership gates application access,
    so a sync that cannot complete fails the sign-in (the callback maps the
    exception to ``auth_failed``) instead of leaving stale memberships.
    """
    from services.oidc_upstream.groups import sync_groups_from_claims

    email = _extract_claims(claims, connection.get("claim_mapping") or {}).get("email")
    user_email = email or user.get("email") or ""
    sync_groups_from_claims(tenant_id, user_id, user_email, connection, claims)


def _apply_oidc_idp_attributes_safe(
    tenant_id: str,
    user_id: str,
    connection: dict,
    claims: dict,
) -> None:
    """Wrapper around ``apply_oidc_idp_attributes`` that swallows exceptions.

    The OIDC IdP-mirror write must never break the authentication flow.
    Internal validation already drops malformed values silently; this wrapper
    only catches infrastructure failures (DB outages, etc.) so the user can
    still sign in. On failure we both log to stderr (for ops) and emit a
    structured ``user_idp_attribute_mirror_failed`` audit event so a recurring
    failure surfaces in the admin event log instead of only the container logs.
    """
    from services.oidc_upstream.attributes import apply_oidc_idp_attributes

    claim_mapping = connection.get("claim_mapping") or {}
    standard_attributes = _extract_standard_attributes(claims, claim_mapping)

    try:
        apply_oidc_idp_attributes(
            tenant_id=tenant_id,
            user_id=user_id,
            idp_id=str(connection["id"]),
            attributes=standard_attributes,
            actor_user_id=user_id,
        )
    except Exception as exc:
        logger.warning(
            "Failed to apply OIDC IdP attributes for user %s (connection %s)",
            user_id,
            connection["id"],
            exc_info=True,
        )
        try:
            log_event(
                tenant_id=tenant_id,
                actor_user_id=user_id,
                artifact_type="user",
                artifact_id=user_id,
                event_type="user_idp_attribute_mirror_failed",
                metadata={
                    "idp_id": str(connection["id"]),
                    "error_class": type(exc).__name__,
                },
            )
        except Exception:
            logger.warning(
                "Failed to emit user_idp_attribute_mirror_failed event for user %s",
                user_id,
                exc_info=True,
            )


def _log_sign_in(
    tenant_id: str,
    user_id: str,
    connection: dict,
    sub: str,
    entry: str,
) -> None:
    """Log the ``oidc_login_completed`` event."""
    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        artifact_type="user",
        artifact_id=user_id,
        event_type="oidc_login_completed",
        metadata={
            "idp_id": str(connection["id"]),
            "idp_name": connection["name"],
            "sub": sub,
            "entry": entry,
        },
    )
