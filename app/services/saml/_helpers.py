"""SAML attribute extraction helpers.

These private helpers extract and normalize SAML attributes from responses.
They are used by the auth module for processing SAML responses.
"""


def get_saml_attribute(attributes: dict, attr_name: str) -> str | None:
    """Extract a SAML attribute value (handles list values)."""
    value = attributes.get(attr_name)
    if value is None:
        return None
    if isinstance(value, list):
        return value[0] if value else None
    return str(value)


def get_saml_group_attributes(attributes: dict, attr_name: str) -> list[str]:
    """
    Extract group claim values from SAML attributes.

    SAML group claims can be:
    - A list of strings: ["group1", "group2"]
    - A single string: "group1"
    - Comma-separated: "group1,group2"

    This function normalizes all formats to a list of strings.
    """
    value = attributes.get(attr_name)
    if value is None:
        return []

    # Handle list of values
    if isinstance(value, list):
        groups: list[str] = []
        for v in value:
            if v:
                # Handle comma-separated values within list items
                if isinstance(v, str) and "," in v:
                    groups.extend(s.strip() for s in v.split(",") if s.strip())
                else:
                    groups.append(str(v).strip())
        return groups

    # Handle single string value
    if isinstance(value, str):
        # Check for comma-separated
        if "," in value:
            return [s.strip() for s in value.split(",") if s.strip()]
        return [value.strip()] if value.strip() else []

    return []
