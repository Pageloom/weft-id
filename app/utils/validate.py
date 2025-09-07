def subdomain(_subdomain: str) -> bool:
    if not _subdomain:
        raise ValueError('Subdomain cannot be empty')
    if len(_subdomain) > 63:
        raise ValueError('Subdomain too long (max 63 characters)')
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-")
    if any(c not in allowed for c in _subdomain):
        raise ValueError('Subdomain can only contain lowercase letters, digits, and hyphens')
    if _subdomain[0] == '-' or _subdomain[-1] == '-':
        raise ValueError('Subdomain cannot start or end with a hyphen')
    return True
