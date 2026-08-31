"""OIDC upstream JIT provisioning and authentication completion.

Mirrors ``services.saml.provisioning`` for the relying-party direction of
OIDC. Correlation is on the ``(idp_id, sub)`` pair (where ``sub`` is the claim
named by the connection's ``correlation_claim``), not on email: the OIDC
``sub`` is the stable subject and survives upstream email changes.

The flow has three branches for an unrecognized subject:

1. An existing ``oidc_idp_user_links`` row authenticates that user.
2. No link + ``allow_email_linking`` + ``email_verified: true`` + a matching
   existing email links the subject to that account.
3. No link + JIT enabled provisions a new user.

``allow_email_linking=false`` never attaches an unrecognized subject to an
existing account (account-takeover guard).
"""

import logging

import database
from services.event_log import log_event
from services.exceptions import ForbiddenError, NotFoundError, ValidationError
from utils.validate import is_email_like

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
) -> dict:
    """Create a new user via JIT provisioning from OIDC claims.

    Creates a user with a NULL password (OIDC-only authentication), a verified
    email, an ``oidc_idp_user_links`` row, base-group membership, domain-group
    auto-assignment, and logs ``oidc_user_jit_provisioned``.

    Args:
        tenant_id: Tenant ID.
        connection: The OIDC connection row (dict).
        sub: The correlation subject (the ``correlation_claim`` value).
        claims: The validated ID-token claims (plus any userinfo claims).

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

    # NOTE: The SAML "base group" step is intentionally omitted here. The
    # base-group infrastructure is SAML-specific: ``groups.idp_id`` FKs to
    # ``saml_identity_providers``, so an OIDC connection id cannot be stored
    # there without a migration (out of scope for Iteration 3, which has no
    # database layer). OIDC base-group support is a follow-on.

    # Auto-assign to domain-linked groups (protocol-agnostic, email-domain
    # based, so it works for OIDC users unchanged).
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
        },
    )

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
) -> dict:
    """Complete OIDC authentication and return the user.

    Correlation order:

    1. Existing ``(idp_id, sub)`` link -> authenticate that user.
    2. No link + ``allow_email_linking`` + ``email_verified: true`` + matching
       email -> link and authenticate.
    3. No link + JIT enabled -> provision.
    4. Otherwise -> reject.

    Inactivated users are rejected (matching SAML).

    Args:
        tenant_id: Tenant ID.
        connection: The OIDC connection row (dict).
        sub: The correlation subject.
        claims: The validated ID-token claims.

    Returns:
        The user dict for session creation.

    Raises:
        NotFoundError if no link, no email-link, and JIT disabled.
        ForbiddenError if the user is inactivated.
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
        _apply_oidc_idp_attributes_safe(tenant_id, str(user["id"]), connection, claims)
        _log_sign_in(tenant_id, str(user["id"]), connection, sub, claims)
        return user

    # 2. Email linking (opt-in, gated on email_verified).
    if connection.get("allow_email_linking"):
        email = _extract_claims(claims, connection.get("claim_mapping") or {}).get("email")
        if email and claims.get("email_verified") is True:
            existing = database.users.get_user_by_email_for_saml(tenant_id, email)
            if existing is not None:
                if existing.get("inactivated_at"):
                    raise ForbiddenError(
                        message="User account is inactivated",
                        code="user_inactivated",
                    )
                if not existing.get("email_verified"):
                    database.user_emails.verify_email(tenant_id, str(existing["email_id"]))
                user_id = str(existing["id"])
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
                _apply_oidc_idp_attributes_safe(tenant_id, user_id, connection, claims)
                _log_sign_in(tenant_id, user_id, connection, sub, claims)
                return existing

    # 3. JIT provisioning.
    if connection.get("jit_provisioning"):
        user = jit_provision_user(tenant_id, connection, sub, claims)
        _apply_oidc_idp_attributes_safe(tenant_id, str(user["id"]), connection, claims)
        return user

    # 4. Reject.
    raise NotFoundError(
        message="User account not found",
        code="user_not_found",
        details={"sub": sub},
    )


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
    claims: dict,
) -> None:
    """Log the ``oidc_login_completed`` event for an existing user."""
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
        },
    )
