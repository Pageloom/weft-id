"""SCIM 2.0 metadata endpoints.

Three discovery endpoints per RFC 7644 §4:

- `GET /ServiceProviderConfig` -- features the SP supports
  (auth schemes, filter / pagination / bulk / etc).
- `GET /ResourceTypes` -- the resource families the SP exposes.
- `GET /Schemas` -- the attribute-level schema for each resource.

These responses are static for a given deployment; we build them
on each request so absolute `location` URLs honour `x-forwarded-host`
without having to invalidate a cache when the tenant subdomain
configuration changes.

The endpoints are NOT bearer-authenticated -- per RFC 7644 §4 they
are intended as public discovery so a client can decide what it can
talk to before attempting auth. We do still require the `{idp_id}`
to exist in the URL (it doesn't have to resolve to anything in
particular at this layer; the URL family lives behind the auth dep
for everything else).
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from schemas.scim import (
    ENTERPRISE_USER_SCHEMA,
    GROUP_SCHEMA,
    RESOURCE_TYPE_SCHEMA,
    SERVICE_PROVIDER_CONFIG_SCHEMA,
    USER_SCHEMA,
)
from utils.scim_responses import scim_json_response
from utils.urls import tenant_base_url

router = APIRouter()


def _base_for(request: Request, idp_id: str) -> str:
    """Absolute base URL for this IdP's inbound SCIM endpoints."""
    return f"{tenant_base_url(request)}/scim/v2/inbound/{idp_id}"


# ---------------------------------------------------------------------------
# /ServiceProviderConfig
# ---------------------------------------------------------------------------


def _service_provider_config(base: str) -> dict:
    return {
        "schemas": [SERVICE_PROVIDER_CONFIG_SCHEMA],
        "documentationUri": "https://weftid.com/docs/admin-guide/identity-providers/inbound-scim",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        # `eq` only, on a small attribute allowlist. Anything more
        # exotic returns 400 invalidFilter from the read endpoints.
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": (
                    "Bearer tokens issued by WeftID via the SCIM Provisioning "
                    "tab on the SAML identity-provider detail page."
                ),
                "specUri": "https://datatracker.ietf.org/doc/html/rfc6750",
                "primary": True,
            }
        ],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": f"{base}/ServiceProviderConfig",
        },
    }


@router.get("/ServiceProviderConfig")
def get_service_provider_config(
    request: Request,
    idp_id: str,
):
    base = _base_for(request, idp_id)
    return scim_json_response(_service_provider_config(base))


# ---------------------------------------------------------------------------
# /ResourceTypes
# ---------------------------------------------------------------------------


def _resource_type_user(base: str) -> dict:
    return {
        "schemas": [RESOURCE_TYPE_SCHEMA],
        "id": "User",
        "name": "User",
        "endpoint": "/Users",
        "description": "User Account",
        "schema": USER_SCHEMA,
        "schemaExtensions": [
            {
                "schema": ENTERPRISE_USER_SCHEMA,
                "required": False,
            },
        ],
        "meta": {
            "resourceType": "ResourceType",
            "location": f"{base}/ResourceTypes/User",
        },
    }


def _resource_type_group(base: str) -> dict:
    return {
        "schemas": [RESOURCE_TYPE_SCHEMA],
        "id": "Group",
        "name": "Group",
        "endpoint": "/Groups",
        "description": "Group",
        "schema": GROUP_SCHEMA,
        "meta": {
            "resourceType": "ResourceType",
            "location": f"{base}/ResourceTypes/Group",
        },
    }


@router.get("/ResourceTypes")
def get_resource_types(
    request: Request,
    idp_id: str,
):
    base = _base_for(request, idp_id)
    return scim_json_response(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 2,
            "startIndex": 1,
            "itemsPerPage": 2,
            "Resources": [_resource_type_user(base), _resource_type_group(base)],
        }
    )


@router.get("/ResourceTypes/{resource_type}")
def get_resource_type(
    request: Request,
    idp_id: str,
    resource_type: str,
):
    base = _base_for(request, idp_id)
    if resource_type == "User":
        return scim_json_response(_resource_type_user(base))
    if resource_type == "Group":
        return scim_json_response(_resource_type_group(base))
    # Defer import to keep the metadata module independent.
    from .errors import ScimErrorException

    raise ScimErrorException(status_code=404, detail=f"Unknown ResourceType: {resource_type}")


# ---------------------------------------------------------------------------
# /Schemas
#
# We ship abbreviated schema documents (id + name + attributes shape).
# Most SCIM clients only check that the schema URN is advertised; the
# detailed attribute breakdown is useful for human inspection and for
# the few clients that do introspect (e.g. Postman's SCIM plugin).
# ---------------------------------------------------------------------------


def _schema_user(base: str) -> dict:
    return {
        "id": USER_SCHEMA,
        "name": "User",
        "description": "User Account",
        "attributes": [
            _attr("userName", "string", required=True, unique="server"),
            _attr("externalId", "string"),
            {
                "name": "name",
                "type": "complex",
                "subAttributes": [
                    _attr("formatted", "string"),
                    _attr("familyName", "string"),
                    _attr("givenName", "string"),
                ],
                "multiValued": False,
                "required": False,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none",
            },
            _attr("displayName", "string"),
            {
                "name": "emails",
                "type": "complex",
                "multiValued": True,
                "required": False,
                "subAttributes": [
                    _attr("value", "string"),
                    _attr("type", "string"),
                    _attr("primary", "boolean"),
                ],
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none",
            },
            _attr("active", "boolean"),
        ],
        "meta": {
            "resourceType": "Schema",
            "location": f"{base}/Schemas/{USER_SCHEMA}",
        },
    }


def _schema_enterprise_user(base: str) -> dict:
    return {
        "id": ENTERPRISE_USER_SCHEMA,
        "name": "EnterpriseUser",
        "description": "Enterprise User",
        "attributes": [
            _attr("employeeNumber", "string"),
            _attr("department", "string"),
            _attr("organization", "string"),
            _attr("division", "string"),
            _attr("costCenter", "string"),
            {
                "name": "manager",
                "type": "complex",
                "multiValued": False,
                "required": False,
                "subAttributes": [
                    _attr("value", "string"),
                    _attr("$ref", "reference"),
                    _attr("displayName", "string"),
                ],
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none",
            },
        ],
        "meta": {
            "resourceType": "Schema",
            "location": f"{base}/Schemas/{ENTERPRISE_USER_SCHEMA}",
        },
    }


def _schema_group(base: str) -> dict:
    return {
        "id": GROUP_SCHEMA,
        "name": "Group",
        "description": "Group",
        "attributes": [
            _attr("displayName", "string", required=True),
            _attr("externalId", "string"),
            {
                "name": "members",
                "type": "complex",
                "multiValued": True,
                "required": False,
                "subAttributes": [
                    _attr("value", "string"),
                    _attr("$ref", "reference"),
                    _attr("type", "string"),
                    _attr("display", "string"),
                ],
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none",
            },
        ],
        "meta": {
            "resourceType": "Schema",
            "location": f"{base}/Schemas/{GROUP_SCHEMA}",
        },
    }


def _attr(
    name: str,
    type_: str,
    *,
    required: bool = False,
    unique: str = "none",
) -> dict:
    """Build a SCIM Schema-attribute descriptor."""
    return {
        "name": name,
        "type": type_,
        "multiValued": False,
        "required": required,
        "caseExact": False,
        "mutability": "readWrite",
        "returned": "default",
        "uniqueness": unique,
    }


@router.get("/Schemas")
def get_schemas(
    request: Request,
    idp_id: str,
):
    base = _base_for(request, idp_id)
    schemas = [_schema_user(base), _schema_enterprise_user(base), _schema_group(base)]
    return scim_json_response(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(schemas),
            "startIndex": 1,
            "itemsPerPage": len(schemas),
            "Resources": schemas,
        }
    )


@router.get("/Schemas/{schema_id:path}")
def get_schema(
    request: Request,
    idp_id: str,
    schema_id: str,
):
    base = _base_for(request, idp_id)
    if schema_id == USER_SCHEMA:
        return scim_json_response(_schema_user(base))
    if schema_id == ENTERPRISE_USER_SCHEMA:
        return scim_json_response(_schema_enterprise_user(base))
    if schema_id == GROUP_SCHEMA:
        return scim_json_response(_schema_group(base))
    from .errors import ScimErrorException

    raise ScimErrorException(status_code=404, detail=f"Unknown Schema: {schema_id}")
