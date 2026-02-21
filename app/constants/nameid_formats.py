"""NameID format constants for SAML IdP assertions.

Maps short labels used in the UI/API to full SAML NameID format URIs.
"""

NAMEID_FORMAT_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
NAMEID_FORMAT_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
NAMEID_FORMAT_TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
NAMEID_FORMAT_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

# Short label -> full URI
NAMEID_FORMAT_LABELS: dict[str, str] = {
    "emailAddress": NAMEID_FORMAT_EMAIL,
    "persistent": NAMEID_FORMAT_PERSISTENT,
    "transient": NAMEID_FORMAT_TRANSIENT,
    "unspecified": NAMEID_FORMAT_UNSPECIFIED,
}

# Full URI -> short label
NAMEID_FORMAT_URI_TO_LABEL: dict[str, str] = {v: k for k, v in NAMEID_FORMAT_LABELS.items()}
