"""SCIM 2.0 resource payload builders.

Produces spec-correct `User` and `Group` representations from WeftID's
internal dict shapes (the rows returned by `database.users` and
`database.groups`). Only attributes the source actually has populated are
emitted -- no synthetic empty strings, no placeholder `null`s.

Per RFC 7643:

- Every resource carries a `schemas` array. For User, this is the core
  schema URN, plus the EnterpriseUser extension URN when enterprise
  attributes are present.
- The `id` is the SP's id for the resource. We use WeftID's id as our
  `externalId`; the SP returns its own id after create. Until then we omit
  `id` from outbound payloads (POST cannot dictate the SP's id).
- `members` on Group is a list of `{value, $ref, display}`. `value` is the
  SP-side user id. We populate `$ref` with the SCIM-style relative reference
  `Users/<value>` and `display` with the user's email or full name.

The user dict is expected to expose at least:
    id, email
Optionally:
    first_name, last_name, is_inactivated (bool), active (bool)
    (Plus any EnterpriseUser fields passed via the `enterprise=` kwarg.)

The group dict is expected to expose at least:
    id, name
Optional:
    description (currently unused -- SCIM Group has no description field per
    RFC 7643; we drop it).

The members list passed to `build_group_resource` is a list of dicts each
exposing: id, optionally email and first_name/last_name for display.
"""

from __future__ import annotations

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
ENTERPRISE_USER_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"


def _full_name(first: str | None, last: str | None) -> str | None:
    """Concatenate first/last into a display name, or None if neither is set."""
    parts = [p for p in (first, last) if p]
    return " ".join(parts) if parts else None


def _is_active(user: dict) -> bool:
    """Derive `active` from `is_inactivated` (preferred) or explicit `active`.

    Defaults to True if neither flag is present.
    """
    if "is_inactivated" in user:
        return not bool(user["is_inactivated"])
    if "active" in user:
        return bool(user["active"])
    return True


def build_user_resource(
    user: dict,
    *,
    enterprise: dict | None = None,
) -> dict:
    """Build a spec-correct SCIM 2.0 User resource from a WeftID user dict.

    Only emits attributes the user actually has populated. The EnterpriseUser
    extension is included only when `enterprise` is a non-empty dict.

    Args:
        user: WeftID user dict. Required: `id`, `email`. Optional:
            `first_name`, `last_name`, `is_inactivated` or `active`.
        enterprise: Optional EnterpriseUser extension attributes (e.g.,
            `employeeNumber`, `department`, `manager`). Pass-through; the
            caller is responsible for shape correctness.

    Returns:
        A dict suitable for JSON-serializing as a SCIM 2.0 User.
    """
    user_id = str(user["id"])
    email = user["email"]
    first_name = user.get("first_name")
    last_name = user.get("last_name")

    schemas: list[str] = [USER_SCHEMA]
    payload: dict = {
        "schemas": schemas,
        "externalId": user_id,
        "userName": email,
        "active": _is_active(user),
        "emails": [
            {
                "value": email,
                "primary": True,
                "type": "work",
            }
        ],
    }

    name_obj: dict = {}
    if first_name:
        name_obj["givenName"] = first_name
    if last_name:
        name_obj["familyName"] = last_name
    full = _full_name(first_name, last_name)
    if full:
        name_obj["formatted"] = full
    if name_obj:
        payload["name"] = name_obj
    if full:
        payload["displayName"] = full

    if enterprise:
        schemas.append(ENTERPRISE_USER_SCHEMA)
        payload[ENTERPRISE_USER_SCHEMA] = dict(enterprise)

    return payload


def _member_display(member: dict) -> str | None:
    """Pick the best display string for a group member: full name or email."""
    full = _full_name(member.get("first_name"), member.get("last_name"))
    if full:
        return full
    email = member.get("email")
    if email:
        return str(email)
    return None


def build_group_resource(group: dict, members: list[dict]) -> dict:
    """Build a spec-correct SCIM 2.0 Group resource.

    Args:
        group: WeftID group dict. Required: `id`, `name`.
        members: List of member dicts. Each must expose `id`; optional
            `email`, `first_name`, `last_name` for the `display` attribute.

    Returns:
        A dict suitable for JSON-serializing as a SCIM 2.0 Group. Empty
        groups produce an empty `members` array (spec-permitted).
    """
    group_id = str(group["id"])
    name = group["name"]

    member_entries: list[dict] = []
    for m in members:
        value = str(m["id"])
        entry: dict = {
            "value": value,
            "$ref": f"Users/{value}",
        }
        display = _member_display(m)
        if display:
            entry["display"] = display
        member_entries.append(entry)

    payload: dict = {
        "schemas": [GROUP_SCHEMA],
        "externalId": group_id,
        "displayName": name,
        "members": member_entries,
    }
    return payload
