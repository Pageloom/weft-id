"""Pydantic schemas for proxy-app (forward-auth) management.

A proxy app is an HTTP application behind a verified protected domain that WeftID
gates as a forward-auth authority. Each proxy app declares its public external URL,
optional public (unauthenticated) paths, and which X-Forwarded-* identity headers to
emit on allow. Access is controlled via the shared group-grant model
(sp_group_assignments) or the available_to_all flag.
"""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field

# The set of X-Forwarded-* identity headers a proxy app may emit on allow.
# Keys are the only accepted header_config keys; values are booleans.
SUPPORTED_HEADER_KEYS: frozenset[str] = frozenset({"user", "email", "groups", "display_name"})

# Bounds on the JSONB collections, to keep payloads sane.
MAX_PUBLIC_PATHS = 50
MAX_PUBLIC_PATH_LENGTH = 2048


class ProxyAppCreate(BaseModel):
    """Request schema for creating a proxy app."""

    protected_domain_id: str = Field(
        ...,
        min_length=1,
        max_length=50,
        description="ID of the (verified) protected domain this app lives under.",
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Display name for the app, e.g. 'Grafana'.",
    )
    external_url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description=(
            "Public https URL of the app, e.g. 'https://grafana.acme-corp.com'. "
            "Must be a well-formed https URL whose host is under the protected domain."
        ),
    )
    description: str | None = Field(
        None,
        max_length=2000,
        description="Optional description of the app.",
    )
    public_paths: list[Annotated[str, Field(max_length=MAX_PUBLIC_PATH_LENGTH)]] = Field(
        default_factory=list,
        max_length=MAX_PUBLIC_PATHS,
        description=(
            "Rooted relative path patterns that bypass auth (login pages, health "
            "checks, static assets), e.g. ['/health', '/public/*']. Each must start "
            "with '/'."
        ),
    )
    header_config: dict[str, bool] = Field(
        default_factory=dict,
        description=(
            "Which X-Forwarded-* identity headers to emit on allow. Keys are "
            "restricted to: user, email, groups, display_name. Values are booleans."
        ),
    )
    available_to_all: bool = Field(
        False,
        description="If true, every authenticated tenant user can access (no grant needed).",
    )
    enabled: bool = Field(True, description="Whether forward auth is enabled for this app.")


class ProxyAppUpdate(BaseModel):
    """Request schema for updating a proxy app. All fields optional."""

    name: str | None = Field(None, min_length=1, max_length=255)
    external_url: str | None = Field(None, min_length=1, max_length=2048)
    description: str | None = Field(None, max_length=2000)
    public_paths: list[Annotated[str, Field(max_length=MAX_PUBLIC_PATH_LENGTH)]] | None = Field(
        None, max_length=MAX_PUBLIC_PATHS
    )
    header_config: dict[str, bool] | None = None
    available_to_all: bool | None = None
    enabled: bool | None = None


class ProxyApp(BaseModel):
    """Response schema for a proxy app."""

    id: str = Field(..., description="Proxy-app ID")
    protected_domain_id: str = Field(..., description="Owning protected-domain ID")
    domain: str | None = Field(None, description="The owning protected domain")
    name: str = Field(..., description="Display name")
    external_url: str = Field(..., description="Public https URL of the app")
    description: str | None = Field(None, description="Optional description")
    public_paths: list[str] = Field(default_factory=list, description="Auth-bypass path patterns")
    header_config: dict[str, bool] = Field(
        default_factory=dict, description="X-Forwarded-* header emission flags"
    )
    available_to_all: bool = Field(..., description="Whether all users can access")
    enabled: bool = Field(..., description="Whether forward auth is enabled")
    created_at: datetime = Field(..., description="When the app was created")
    updated_at: datetime = Field(..., description="When the app was last updated")
    created_by_name: str | None = Field(None, description="Name of the registering admin")


class ProxyAppList(BaseModel):
    """List response for proxy apps."""

    items: list[ProxyApp]
    total: int


class ProxyAppGrant(BaseModel):
    """A group grant on a proxy app."""

    id: str = Field(..., description="Grant ID")
    proxy_app_id: str = Field(..., description="Proxy-app ID")
    group_id: str = Field(..., description="Granted group ID")
    group_name: str = Field(..., description="Granted group name")
    group_description: str | None = Field(None, description="Group description")
    group_type: str = Field(..., description="Group type (weftid | idp)")
    assigned_by: str = Field(..., description="ID of the admin who created the grant")
    assigned_at: datetime = Field(..., description="When the grant was created")


class ProxyAppGrantList(BaseModel):
    """List response for proxy-app group grants."""

    items: list[ProxyAppGrant]
    total: int


class ProxyAppGrantAdd(BaseModel):
    """Request schema for adding a group grant to a proxy app."""

    group_id: str = Field(..., min_length=1, max_length=50, description="Group ID to grant access.")
