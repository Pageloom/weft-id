"""NameID resolution for SAML IdP assertions.

Resolves the correct NameID value and format URI based on the SP's
configured nameid_format.
"""

import uuid

import database
from constants.nameid_formats import (
    NAMEID_FORMAT_EMAIL,
    NAMEID_FORMAT_PERSISTENT,
    NAMEID_FORMAT_TRANSIENT,
    NAMEID_FORMAT_UNSPECIFIED,
    NAMEID_FORMAT_URI_TO_LABEL,
)


def resolve_name_id(
    tenant_id: str,
    user_id: str,
    sp_id: str,
    nameid_format: str,
    user_email: str,
) -> tuple[str, str]:
    """Resolve the NameID value and format URI for a SAML assertion.

    Args:
        tenant_id: Tenant ID (for DB scoping)
        user_id: Authenticated user's ID
        sp_id: Service provider ID
        nameid_format: The SP's configured nameid_format URI
        user_email: User's primary email address

    Returns:
        Tuple of (name_id_value, name_id_format_uri)
    """
    label = NAMEID_FORMAT_URI_TO_LABEL.get(nameid_format)

    if label == "persistent":
        mapping = database.sp_nameid_mappings.get_or_create_nameid_mapping(
            tenant_id=tenant_id,
            tenant_id_value=tenant_id,
            user_id=user_id,
            sp_id=sp_id,
        )
        return mapping["nameid_value"], NAMEID_FORMAT_PERSISTENT

    if label == "transient":
        return str(uuid.uuid4()), NAMEID_FORMAT_TRANSIENT

    # emailAddress, unspecified, or unknown: return email
    if label == "unspecified":
        return user_email, NAMEID_FORMAT_UNSPECIFIED

    return user_email, NAMEID_FORMAT_EMAIL
