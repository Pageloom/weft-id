"""SP lookup and SSO response building.

Functions used by the SSO flow for looking up SPs, getting user consent info,
and building signed SAML responses.
"""

import logging

import database
from schemas.service_providers import AssertionPreview, SPConfig
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.service_providers._converters import _row_to_config
from services.types import RequestingUser
from utils.saml_idp import make_idp_entity_id

logger = logging.getLogger(__name__)


def get_groups_for_assertion(
    tenant_id: str,
    user_id: str,
    sp_id: str,
    sp_row: dict,
) -> list[str]:
    """Compute the group names to include in a SAML assertion.

    Resolves the effective scope (SP override, then tenant default) and returns
    the filtered group list. Returns an empty list if include_group_claims is
    false or no groups match.
    """
    if not sp_row.get("include_group_claims", False):
        return []

    # Resolve effective scope: SP override > tenant default > "access_relevant"
    scope = sp_row.get("group_assertion_scope") or database.security.get_group_assertion_scope(
        tenant_id
    )

    if scope == "all":
        return database.groups.get_effective_group_names(tenant_id, user_id)
    elif scope == "trunk":
        return database.groups.get_trunk_group_names(tenant_id, user_id)
    else:
        # access_relevant: fall back to trunk for available_to_all SPs
        if sp_row.get("available_to_all", False):
            return database.groups.get_trunk_group_names(tenant_id, user_id)
        return database.groups.get_access_relevant_group_names(tenant_id, user_id, sp_id)


def get_groups_for_consent(
    tenant_id: str,
    user_id: str,
    sp_id: str,
) -> list[str]:
    """Compute the group names that will be disclosed on the consent screen.

    Fetches the SP row and delegates to get_groups_for_assertion(). Used by the
    consent page to show the same group list that will appear in the assertion.
    """
    sp_row = database.service_providers.get_service_provider(tenant_id, sp_id)
    if sp_row is None:
        return []
    return get_groups_for_assertion(tenant_id, user_id, str(sp_row["id"]), sp_row)


def _build_assertion_attributes(
    tenant_id: str,
    user_id: str,
    *,
    email: str,
    first_name: str,
    last_name: str,
    group_names: list[str],
    attribute_mapping: dict[str, str] | None,
) -> dict[str, str | list[str]]:
    """Build the user_attributes dict for SAML assertion emission.

    Bridges between the SP's ``attribute_mapping`` and the value sources:

    * Fixed keys (email/firstName/lastName/displayName) come from the users
      row + primary_email. ``displayName`` is composed from first+last.
    * ``groups`` comes from the precomputed ``group_names`` list (already
      filtered by include_group_claims + scope).
    * Standard-attribute registry keys are read from ``user_attributes``
      (the canonical EAV table). A registry key is emitted iff (a) the tenant
      has it enabled in ``tenant_attribute_config`` (when a config row exists),
      (b) the SP's ``attribute_mapping`` includes it (when one is configured),
      and (c) the user has a non-empty value.

    Empty / missing values are dropped so ``build_saml_response`` does not
    emit empty ``<saml:Attribute>`` elements (Iteration 6 acceptance criterion).

    Wire-name collision precedence: the registry key ``display_name`` and the
    fixed key ``displayName`` both resolve to the same wire name (the registry
    entry's ``default_friendly_name`` is ``"displayName"``). When the tenant
    enables ``display_name`` and the user has a stored value, the EAV value
    wins; otherwise the fixed first+last composition wins. The downstream
    emitter looks up each result-dict key in ``attribute_mapping``, so we drop
    the fixed ``displayName`` entry when the registry-sourced value will fill
    the same wire slot.

    The downstream emitter (``build_saml_response``) consumes
    ``attribute_mapping`` to look up the wire name per key, so this helper does
    not transform key names -- it only decides which keys (with values) belong
    in the dict.
    """
    from constants.user_attributes import ATTRIBUTE_KEYS, deserialize

    result: dict[str, str | list[str]] = {}

    # Fixed keys
    if email:
        result["email"] = email
    if first_name:
        result["firstName"] = first_name
    if last_name:
        result["lastName"] = last_name
    display_name = f"{first_name} {last_name}".strip()
    if display_name:
        result["displayName"] = display_name
    if group_names:
        result["groups"] = group_names

    # Tenant attribute config (enabled flags). A registry key is only emitted
    # when the tenant config row exists AND enabled=true. Without this filter,
    # disabling an attribute after an SP's mapping was seeded would silently
    # keep leaking the value out to that SP.
    try:
        config_rows = database.tenant_attribute_config.list_config(tenant_id)
    except Exception as exc:  # noqa: BLE001 -- never break SSO over an attribute fetch
        logger.warning(
            "Failed to load tenant_attribute_config for tenant_id=%s; "
            "assertion omits standard attrs",
            tenant_id,
            exc_info=True,
        )
        config_rows = []
        # Audit-trail event so a recurring outage surfaces in the admin
        # event log, not just container stderr. Wrapped in try/except so
        # an audit-log failure (e.g. the same DB outage that broke this
        # read) still cannot cascade into the SSO path. The exception
        # message is deliberately excluded -- it may carry SQL fragments
        # or connection-string fragments depending on the failure mode.
        try:
            log_event(
                tenant_id=tenant_id,
                actor_user_id=user_id,
                artifact_type="tenant",
                artifact_id=tenant_id,
                event_type="tenant_attribute_config_read_failed",
                metadata={
                    "phase": "config",
                    "error_class": type(exc).__name__,
                },
            )
        except Exception:
            logger.warning(
                "Failed to emit tenant_attribute_config_read_failed event for tenant_id=%s",
                tenant_id,
                exc_info=True,
            )
    enabled_tenant_keys = {row.get("attribute_key") for row in config_rows if row.get("enabled")}

    # Standard attributes from EAV. Read once; merge by registry key.
    try:
        rows = database.user_attributes.list_attributes(tenant_id, user_id)
    except Exception as exc:  # noqa: BLE001 -- never break SSO over an attribute fetch
        logger.warning(
            "Failed to load user_attributes for user_id=%s; assertion omits standard attrs",
            user_id,
            exc_info=True,
        )
        rows = []
        # Mirror the same audit precedent as the config read above. We
        # reuse the ``tenant_attribute_config_read_failed`` event type
        # with ``phase=user_attributes`` rather than minting a second
        # type because both failures share the same operational signal
        # (DB read for assertion attributes failed) and the same
        # admin-side remediation (check the database).
        try:
            log_event(
                tenant_id=tenant_id,
                actor_user_id=user_id,
                artifact_type="user",
                artifact_id=user_id,
                event_type="tenant_attribute_config_read_failed",
                metadata={
                    "phase": "user_attributes",
                    "error_class": type(exc).__name__,
                },
            )
        except Exception:
            logger.warning(
                "Failed to emit tenant_attribute_config_read_failed event for user_id=%s",
                user_id,
                exc_info=True,
            )

    # When attribute_mapping is provided, only include keys present in the
    # mapping. Otherwise, include every value the user has. This honors the
    # "empty values not emitted" rule AND the "only configured keys emitted"
    # rule together: a key is emitted iff (mapping says emit it) AND (user has
    # a non-empty value).
    allowed_keys: set[str] | None = None
    if attribute_mapping is not None:
        allowed_keys = {k for k in attribute_mapping if k in ATTRIBUTE_KEYS}

    for row in rows:
        key = row.get("attribute_key")
        raw = row.get("value")
        if not key or raw is None or raw == "":
            continue
        if key not in ATTRIBUTE_KEYS:
            continue
        if allowed_keys is not None and key not in allowed_keys:
            continue
        # Tenant-disabled attributes do not leak even if the SP mapping still
        # references the key. (Skip the check only when no config rows were
        # loaded at all -- e.g., DB read failure -- so a transient outage does
        # not silently drop every standard attribute.)
        if config_rows and key not in enabled_tenant_keys:
            continue
        try:
            typed = deserialize(key, str(raw))
        except ValueError:
            # Corrupt row (fails the registry validator) -- skip rather than
            # break the assertion. ``deserialize`` is guaranteed to return a
            # non-empty string on success (empty values raise), so there is no
            # need to re-check emptiness here.
            continue
        result[key] = typed

    # Resolve display_name / displayName collision: when the EAV merge placed a
    # non-empty ``display_name`` value, drop the fixed ``displayName`` so the
    # downstream emitter never produces two ``<saml:Attribute>`` elements that
    # represent the same logical field. The registry-sourced value wins (admin
    # intent: explicit > composed).
    #
    # This runs in BOTH branches:
    #   - When ``attribute_mapping`` is provided: the fixed key would otherwise
    #     emit its mapped wire name (e.g. ``displayName``) alongside the EAV
    #     key's mapped wire name (also ``displayName`` per the standard preset),
    #     producing two ``<saml:Attribute Name="displayName">`` elements.
    #   - When ``attribute_mapping`` is None: the fixed key falls back to the
    #     ``SAML_ATTRIBUTE_URIS["displayName"]`` URI, while the EAV key falls
    #     back to ``display_name``. The SP still sees two attributes carrying
    #     the same logical field; the same drop rule yields exactly one.
    if "display_name" in result and result.get("display_name"):
        result.pop("displayName", None)

    return result


def get_service_provider_by_id(tenant_id: str, sp_id: str) -> dict | None:
    """Look up an SP by ID. No auth check required.

    Used by the SSO router for IdP-initiated flows.
    Tenant scoping is enforced by RLS at the database layer.

    Returns:
        Raw database row dict, or None if not found.
    """
    return database.service_providers.get_service_provider(tenant_id, sp_id)


def get_user_consent_info(tenant_id: str, user_id: str) -> dict | None:
    """Get user display info for the SSO consent screen.

    Returns dict with email, first_name, last_name, or None if user or
    primary email not found. No authorization check needed (user is
    viewing their own info).
    """
    user = database.users.get_user_by_id(tenant_id, user_id)
    if user is None:
        return None
    primary_email = database.user_emails.get_primary_email(tenant_id, user_id)
    if primary_email is None:
        return None
    return {
        "email": primary_email["email"],
        "first_name": user.get("first_name", ""),
        "last_name": user.get("last_name", ""),
    }


def get_sp_by_entity_id(tenant_id: str, entity_id: str) -> SPConfig | None:
    """Look up an SP by entity ID. No auth check required.

    Used by the SSO endpoint to find the SP that sent the AuthnRequest.
    Tenant scoping is enforced by RLS at the database layer.
    """
    row = database.service_providers.get_service_provider_by_entity_id(tenant_id, entity_id)
    if row is None:
        return None
    return _row_to_config(row)


def build_sso_response(
    tenant_id: str,
    user_id: str,
    sp_entity_id: str,
    authn_request_id: str | None,
    base_url: str,
) -> tuple[str, str, str]:
    """Build a signed SAML Response for an SSO assertion.

    Args:
        tenant_id: Tenant ID
        user_id: Authenticated user's ID
        sp_entity_id: Entity ID of the requesting SP
        authn_request_id: ID from the AuthnRequest (for InResponseTo)
        base_url: Base URL for building entity ID

    Returns:
        Tuple of (base64_encoded_response, acs_url, session_index)

    Raises:
        NotFoundError: If SP or signing certificate not found
        ValidationError: If user data is missing
    """
    from utils.saml import decrypt_private_key
    from utils.saml_assertion import build_saml_response

    # 1. Look up SP
    sp_row = database.service_providers.get_service_provider_by_entity_id(tenant_id, sp_entity_id)
    if sp_row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    # 1b. Reject SPs where trust has not been established
    if not sp_row.get("trust_established", False):
        raise ValidationError(
            message="Service provider setup is not complete",
            code="sp_trust_not_established",
        )

    # 2. Get signing certificate (per-SP first, then tenant fallback)
    sp_id = str(sp_row["id"])
    cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if cert is None:
        cert = database.saml.get_sp_certificate(tenant_id)
    if cert is None:
        raise NotFoundError(
            message="IdP signing certificate not configured",
            code="idp_certificate_not_found",
        )

    # 3. Decrypt private key
    private_key_pem = decrypt_private_key(cert["private_key_pem_enc"])

    # 4. Get user info
    user = database.users.get_user_by_id(tenant_id, user_id)
    if user is None:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
        )

    primary_email_row = database.user_emails.get_primary_email(tenant_id, user_id)
    if primary_email_row is None:
        raise ValidationError(
            message="User has no primary email",
            code="user_no_email",
        )

    email = primary_email_row["email"]

    # 5. Build user attributes (bridge between mapping + value sources).
    # Fixed keys come from the users row; standard attribute registry keys
    # come from the user_attributes EAV table. Empty values are dropped so
    # no empty <saml:Attribute> elements are emitted.
    first_name = user.get("first_name", "") or ""
    last_name = user.get("last_name", "") or ""

    # 5b. Include group claims based on assertion scope
    group_names = get_groups_for_assertion(tenant_id, user_id, sp_id, sp_row)

    # 6b. Get per-SP attribute mapping (if configured) -- determines which
    # standard-attribute keys are emitted at all.
    attribute_mapping = sp_row.get("attribute_mapping")

    user_attributes = _build_assertion_attributes(
        tenant_id,
        user_id,
        email=email,
        first_name=first_name,
        last_name=last_name,
        group_names=group_names,
        attribute_mapping=attribute_mapping,
    )

    # 6. Resolve NameID value and format
    from services.service_providers.nameid import resolve_name_id

    issuer_entity_id = make_idp_entity_id(tenant_id, sp_id)
    name_id_format = sp_row.get(
        "nameid_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    )

    name_id, resolved_format = resolve_name_id(
        tenant_id=tenant_id,
        user_id=user_id,
        sp_id=sp_id,
        nameid_format=name_id_format,
        user_email=email,
    )

    # 6c. Encrypt assertion if SP provides an encryption certificate
    encryption_cert = sp_row.get("encryption_certificate_pem")
    assertion_encrypted = encryption_cert is not None
    encryption_algorithm = sp_row.get("assertion_encryption_algorithm", "aes256-cbc")

    saml_response_b64, session_index = build_saml_response(
        issuer_entity_id=issuer_entity_id,
        sp_entity_id=sp_entity_id,
        sp_acs_url=sp_row["acs_url"],
        name_id=name_id,
        name_id_format=resolved_format,
        authn_request_id=authn_request_id,
        user_attributes=user_attributes,
        certificate_pem=cert["certificate_pem"],
        private_key_pem=private_key_pem,
        attribute_mapping=attribute_mapping,
        encryption_certificate_pem=encryption_cert,
        assertion_encryption_algorithm=encryption_algorithm,
    )

    # 7. Log event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        artifact_type="service_provider",
        artifact_id=str(sp_row["id"]),
        event_type="sso_assertion_issued",
        metadata={
            "sp_entity_id": sp_entity_id,
            "sp_name": sp_row["name"],
            "assertion_encrypted": assertion_encrypted,
            "assertion_encryption_algorithm": encryption_algorithm if assertion_encrypted else None,
        },
    )

    return saml_response_b64, sp_row["acs_url"], session_index


def preview_assertion(
    requesting_user: RequestingUser,
    sp_id: str,
    target_user_id: str,
) -> AssertionPreview:
    """Preview what a SAML assertion would contain for a user + SP pair.

    Reuses the same attribute building, group resolution, and NameID logic
    as build_sso_response(), but does not build, sign, or encrypt XML.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # 1. Look up SP
    sp_row = database.service_providers.get_service_provider(tenant_id, sp_id)
    if sp_row is None:
        raise NotFoundError(message="Service provider not found", code="sp_not_found")

    # 2. Look up target user
    user = database.users.get_user_by_id(tenant_id, target_user_id)
    if user is None:
        raise NotFoundError(message="User not found", code="user_not_found")

    primary_email_row = database.user_emails.get_primary_email(tenant_id, target_user_id)
    if primary_email_row is None:
        raise ValidationError(message="User has no primary email", code="user_no_email")

    email = primary_email_row["email"]
    first_name = user.get("first_name", "") or ""
    last_name = user.get("last_name", "") or ""

    # 3. Build user attributes via the same bridge helper used by build_sso_response,
    # so preview matches actual emission. Standard-attribute keys from the EAV
    # are merged in; empty values are dropped.
    sp_id_str = str(sp_row["id"])
    group_names = get_groups_for_assertion(tenant_id, target_user_id, sp_id_str, sp_row)
    attribute_mapping = sp_row.get("attribute_mapping")
    user_attributes = _build_assertion_attributes(
        tenant_id,
        target_user_id,
        email=email,
        first_name=first_name,
        last_name=last_name,
        group_names=group_names,
        attribute_mapping=attribute_mapping,
    )

    # 5. Resolve NameID
    from services.service_providers.nameid import resolve_name_id

    name_id_format = sp_row.get(
        "nameid_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    )
    name_id, resolved_format = resolve_name_id(
        tenant_id=tenant_id,
        user_id=target_user_id,
        sp_id=sp_id_str,
        nameid_format=name_id_format,
        user_email=email,
    )

    # 7. Check access
    from services.service_providers.group_assignments import check_user_sp_access

    has_access = bool(sp_row.get("available_to_all", False)) or check_user_sp_access(
        tenant_id, target_user_id, sp_id_str
    )

    # 8. Encryption status
    encryption_cert = sp_row.get("encryption_certificate_pem")
    assertion_encrypted = encryption_cert is not None
    encryption_algorithm = (
        sp_row.get("assertion_encryption_algorithm", "aes256-cbc") if assertion_encrypted else None
    )

    # 9. Group assertion scope
    scope = sp_row.get("group_assertion_scope") or (
        database.security.get_group_assertion_scope(tenant_id) or "access_relevant"
    )

    # 10. Log event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="service_provider",
        artifact_id=sp_id_str,
        event_type="assertion_preview_viewed",
        metadata={
            "sp_name": sp_row["name"],
            "target_user_id": target_user_id,
            "target_user_email": email,
        },
    )

    return AssertionPreview(
        user_id=target_user_id,
        user_email=email,
        user_first_name=first_name,
        user_last_name=last_name,
        name_id=name_id,
        name_id_format=resolved_format,
        attributes=user_attributes,
        attribute_mapping=attribute_mapping,
        group_names=group_names,
        group_assertion_scope=scope,
        has_access=has_access,
        assertion_encrypted=assertion_encrypted,
        encryption_algorithm=encryption_algorithm,
        sp_name=sp_row["name"],
        sp_entity_id=sp_row.get("entity_id"),
    )
