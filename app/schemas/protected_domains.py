"""Pydantic schemas for protected-domain (forward-auth) management.

A protected domain is a real DNS/web domain a tenant registers so WeftID can act
as its forward-auth authority: issue per-domain cookies and TLS certificates for a
portal host under that domain. Ownership is proven via a DNS-TXT challenge before
the domain becomes 'verified'.

This is unrelated to privileged (email) domains, which route identity by the
right-hand side of a user's email address and carry no ownership proof.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class ProtectedDomainCreate(BaseModel):
    """Request schema for registering a protected domain."""

    domain: str = Field(
        ...,
        min_length=3,
        max_length=253,
        description=(
            "The DNS domain you want to protect with forward auth, e.g. "
            "'acme-corp.com'. WeftID will issue per-domain cookies and certs for "
            "a portal host under it."
        ),
    )
    portal_host: str = Field(
        ...,
        min_length=3,
        max_length=253,
        description=(
            "The WeftID portal hostname under that domain, e.g. "
            "'auth.acme-corp.com'. Point this host at WeftID via DNS."
        ),
    )


class ProtectedDomain(BaseModel):
    """Response schema for a registered protected domain."""

    id: str = Field(..., description="Protected-domain ID")
    domain: str = Field(..., description="The protected DNS domain")
    portal_host: str = Field(..., description="The WeftID portal host under that domain")
    verification_status: Literal["pending", "verified", "failed"] = Field(
        ..., description="DNS-TXT ownership verification state"
    )
    verification_token: str | None = Field(
        None, description="The DNS-TXT challenge token to publish (null once verified)"
    )
    verification_record_name: str = Field(
        ...,
        description="The DNS name where the TXT record must be published",
    )
    verification_record_value: str | None = Field(
        None,
        description="The full TXT record value to publish for the challenge",
    )
    verified_at: datetime | None = Field(None, description="When ownership was verified")
    enabled: bool = Field(..., description="Whether forward auth is enabled for this domain")
    created_at: datetime = Field(..., description="When the domain was registered")
    created_by_name: str | None = Field(None, description="Name of the registering admin")


class ProtectedDomainList(BaseModel):
    """List response for protected domains."""

    items: list[ProtectedDomain]
    total: int


class ProtectedDomainVerifyResult(BaseModel):
    """Result of a (re-runnable) DNS-TXT verification attempt."""

    verified: bool = Field(..., description="Whether the domain is now verified")
    status: Literal["pending", "verified", "failed"] = Field(
        ..., description="The resulting verification status"
    )
    message: str = Field(..., description="Human-readable detail about the attempt")
