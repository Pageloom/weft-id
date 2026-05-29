def is_email_like(value: str | None) -> bool:
    """Return True if `value` has a plausible email shape (`local@domain.tld`).

    Deliberately permissive: a full RFC 5322 parse is overkill for the
    one thing callers need, which is to avoid storing a bare identifier
    (e.g. an IdP-supplied `userName` of "alice.smith") in an email
    column. Requires exactly one `@`, a non-empty local part, and a
    domain that contains a dot with non-empty labels on both sides.
    """
    if not value:
        return False
    s = value.strip()
    if s.count("@") != 1:
        return False
    local, _, domain = s.partition("@")
    if not local or not domain:
        return False
    if "." not in domain:
        return False
    # No empty labels and no leading/trailing dot in the domain.
    labels = domain.split(".")
    return all(labels) and not domain.startswith(".") and not domain.endswith(".")


def subdomain(_subdomain: str) -> bool:
    if not _subdomain:
        raise ValueError("Subdomain cannot be empty")
    if len(_subdomain) > 63:
        raise ValueError("Subdomain too long (max 63 characters)")
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-")
    if any(c not in allowed for c in _subdomain):
        raise ValueError("Subdomain can only contain lowercase letters, digits, and hyphens")
    if _subdomain[0] == "-" or _subdomain[-1] == "-":
        raise ValueError("Subdomain cannot start or end with a hyphen")
    return True
