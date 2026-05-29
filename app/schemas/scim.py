"""SCIM 2.0 resource models (RFC 7643 / 7644).

These models back the inbound SCIM endpoint family at
`/scim/v2/inbound/{idp_id}/`. They are intentionally permissive on
write paths (extra attributes are ignored, not 400'd) and strict on
read paths (only WeftID-mintable fields are emitted) so vendor quirk
modules can layer on top without duplicating shape definitions.

Iteration 2 only consumes the read shapes (`ScimUser`, `ScimGroup`,
`ScimListResponse`, the metadata documents, and `ScimError`). The
write shapes are sketched here so iteration 3 / 4 can reuse the same
type definitions instead of shipping a parallel set.

Naming convention: SCIM JSON attributes are camelCase. We use
Pydantic's `Field(alias=...)` so the model holds the JSON name as the
serialised attribute, but in Python we still write `userName`,
`displayName`, etc. as actual attribute names where Python permits.
For the few that aren't valid Python identifiers (`$ref`), the alias
mechanism is used.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Schema URNs
# ---------------------------------------------------------------------------

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
ENTERPRISE_USER_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
SERVICE_PROVIDER_CONFIG_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
RESOURCE_TYPE_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema"
LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


# ---------------------------------------------------------------------------
# Common pieces
# ---------------------------------------------------------------------------


class ScimMeta(BaseModel):
    """SCIM `meta` block (RFC 7643 §3.1).

    `resourceType` identifies the resource family (e.g. "User").
    `location` is an absolute URL the client can GET to refetch.
    `created` and `lastModified` are timestamps. WeftID does not track
    a separate SCIM-only `version` ETag yet, so it is omitted.
    """

    resourceType: str  # noqa: N815 -- SCIM spec attribute name (RFC 7643)
    location: str
    created: datetime | None = None
    lastModified: datetime | None = None  # noqa: N815 -- SCIM spec


class ScimEmail(BaseModel):
    """One entry in a SCIM `emails` array (RFC 7643 §4.1.2)."""

    value: str
    type: str | None = None
    primary: bool | None = None
    display: str | None = None


class ScimName(BaseModel):
    """SCIM `name` complex attribute (RFC 7643 §4.1.1)."""

    formatted: str | None = None
    familyName: str | None = None  # noqa: N815 -- SCIM spec
    givenName: str | None = None  # noqa: N815 -- SCIM spec


class ScimGroupMember(BaseModel):
    """One entry in a Group `members` array (RFC 7643 §4.2).

    `value` is the member's resource id; `$ref` is the SCIM-style
    relative reference (e.g. `Users/<uuid>`); `type` is the resource
    type ("User" or "Group"). `display` is an optional human-readable
    label the IdP may surface in its UI.
    """

    model_config = ConfigDict(populate_by_name=True)

    value: str
    ref: str = Field(alias="$ref")
    type: str = "User"
    display: str | None = None


class ScimEnterpriseUser(BaseModel):
    """EnterpriseUser extension attributes (RFC 7643 §4.3).

    All optional; we surface only what we have. Iteration 3 will wire
    these up to the existing IdP attribute mirroring pipeline.
    """

    employeeNumber: str | None = None  # noqa: N815 -- SCIM spec
    department: str | None = None
    organization: str | None = None
    division: str | None = None
    costCenter: str | None = None  # noqa: N815 -- SCIM spec
    manager: dict | None = None  # SCIM manager is a complex with value + $ref


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------


class ScimUser(BaseModel):
    """SCIM 2.0 User resource (RFC 7643 §4.1)."""

    model_config = ConfigDict(populate_by_name=True)

    schemas: list[str]
    id: str
    externalId: str | None = None  # noqa: N815 -- SCIM spec
    userName: str  # noqa: N815 -- SCIM spec
    name: ScimName | None = None
    displayName: str | None = None  # noqa: N815 -- SCIM spec
    emails: list[ScimEmail] = Field(default_factory=list)
    active: bool = True
    meta: ScimMeta
    # EnterpriseUser extension lives under its URN key when populated.
    # We use a manual model_dump path to attach it to keep the by_alias
    # path simple. See `scim_user_to_dict` below.


class ScimGroup(BaseModel):
    """SCIM 2.0 Group resource (RFC 7643 §4.2)."""

    schemas: list[str]
    id: str
    externalId: str | None = None  # noqa: N815 -- SCIM spec
    displayName: str  # noqa: N815 -- SCIM spec
    members: list[ScimGroupMember] = Field(default_factory=list)
    meta: ScimMeta


# ---------------------------------------------------------------------------
# List / error envelopes (RFC 7644)
# ---------------------------------------------------------------------------


class ScimListResponse(BaseModel):
    """ListResponse envelope (RFC 7644 §3.4.2).

    `startIndex` and `itemsPerPage` are 1-indexed per the spec. The
    `Resources` array contains the page of results; `totalResults` is
    the total across all pages.
    """

    schemas: list[str] = Field(default_factory=lambda: [LIST_RESPONSE_SCHEMA])
    totalResults: int  # noqa: N815 -- SCIM spec
    startIndex: int = 1  # noqa: N815 -- SCIM spec
    itemsPerPage: int  # noqa: N815 -- SCIM spec
    Resources: list[dict]


class ScimError(BaseModel):
    """SCIM 2.0 Error response (RFC 7644 §3.12).

    `status` is the HTTP status as a string (per the spec). `scimType`
    is an optional machine-readable error class for 400-family errors
    (e.g. `invalidFilter`, `mutability`, `invalidValue`). `detail` is
    the human-readable description.
    """

    schemas: list[str] = Field(default_factory=lambda: [ERROR_SCHEMA])
    status: str
    scimType: str | None = None  # noqa: N815 -- SCIM spec
    detail: str | None = None


# ---------------------------------------------------------------------------
# Metadata documents (RFC 7644 §4)
#
# These are returned by /ServiceProviderConfig, /ResourceTypes, /Schemas.
# Rather than model every nested complex attribute as its own class, we
# build them as plain dicts in `app/routers/scim/inbound/metadata.py`
# (and keep the URNs / shape constants here so tests can assert on them
# without importing the router).
# ---------------------------------------------------------------------------


def supported_filter_attributes() -> list[str]:
    """Attributes we accept in `filter=<attr> eq "<value>"` expressions.

    Mirrors the iteration's scope: `eq` on `userName` / `externalId` /
    `displayName` only. Anything else returns `400 invalidFilter`.
    """
    return ["userName", "externalId", "displayName"]


# ---------------------------------------------------------------------------
# Write-path schemas (iteration 3+ -- defined here to be shared)
#
# These describe the inbound payloads Okta / Entra send on POST / PUT.
# We keep them permissive (`extra="allow"`) so vendor quirks don't 422
# on attributes we don't yet store. The service layer is responsible
# for plucking out the attributes it cares about.
# ---------------------------------------------------------------------------


class ScimUserWrite(BaseModel):
    """Inbound User payload (POST / PUT). Iteration 3 consumer.

    String fields carry `max_length` so the model is safe to wire in as
    a typed body without re-auditing. The routers currently accept raw
    `dict` bodies (size-capped by the proxy), so these bounds are
    dormant until a future iteration adopts strict typed validation.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    schemas: list[str] | None = None
    externalId: str | None = Field(default=None, max_length=255)  # noqa: N815 -- SCIM spec
    userName: str | None = Field(default=None, max_length=320)  # noqa: N815 -- SCIM spec
    name: ScimName | None = None
    displayName: str | None = Field(default=None, max_length=255)  # noqa: N815 -- SCIM spec
    emails: list[ScimEmail] = Field(default_factory=list)
    active: bool | None = None


class ScimGroupWrite(BaseModel):
    """Inbound Group payload (POST / PUT). Iteration 4 consumer.

    See `ScimUserWrite` for why the `max_length` bounds are present but
    dormant.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    schemas: list[str] | None = None
    externalId: str | None = Field(default=None, max_length=255)  # noqa: N815 -- SCIM spec
    displayName: str | None = Field(default=None, max_length=255)  # noqa: N815 -- SCIM spec
    members: list[dict[str, Any]] = Field(default_factory=list)


class ScimPatchOperation(BaseModel):
    """One operation in a SCIM PATCH payload (RFC 7644 §3.5.2)."""

    model_config = ConfigDict(populate_by_name=True)

    op: str = Field(max_length=20)
    path: str | None = Field(default=None, max_length=512)
    value: Any | None = None


class ScimPatchRequest(BaseModel):
    """SCIM PATCH request body (RFC 7644 §3.5.2)."""

    schemas: list[str] = Field(default_factory=lambda: [PATCH_OP_SCHEMA])
    Operations: list[ScimPatchOperation]
