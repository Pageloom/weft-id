"""Pydantic schemas for WebAuthn (passkey) operations."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class BeginRegistrationResponse(BaseModel):
    """Envelope for the ``PublicKeyCredentialCreationOptions`` returned to the browser.

    The browser's ``navigator.credentials.create()`` expects its input under
    ``publicKey`` -- we keep the alias to match the Web IDL shape but store
    the field internally as ``public_key`` to satisfy PEP 8 / ruff N815.
    """

    public_key: dict = Field(
        ...,
        alias="publicKey",
        description="WebAuthn PublicKeyCredentialCreationOptions",
    )

    model_config = ConfigDict(populate_by_name=True)


class CompleteRegistrationRequest(BaseModel):
    """Payload the browser posts back after ``navigator.credentials.create()``."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="User-chosen label for the passkey",
    )
    response: dict = Field(
        ...,
        description="PublicKeyCredential JSON produced by navigator.credentials.create()",
    )


class PasskeyResponse(BaseModel):
    """Public, JSON-safe view of a registered passkey."""

    id: str
    name: str = Field(..., max_length=100)
    transports: list[str] | None = None
    backup_eligible: bool
    backup_state: bool
    created_at: datetime = Field(..., description="Registration timestamp (UTC)")
    last_used_at: datetime | None = Field(
        default=None, description="Last authentication timestamp (UTC) or null"
    )


class CompleteRegistrationResponse(BaseModel):
    """Response for a successful passkey registration.

    ``backup_codes`` is populated only on the first successful passkey
    registration when the user has no existing backup codes. It is never
    returned again (show-once).
    """

    credential: PasskeyResponse
    backup_codes: list[str] | None = Field(
        default=None,
        description="One-time backup codes issued on first passkey registration",
    )


class RenamePasskeyRequest(BaseModel):
    """Payload for renaming a passkey."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=100)


class BeginAuthenticationRequest(BaseModel):
    """Payload the browser posts to start a passkey login ceremony."""

    model_config = ConfigDict(extra="forbid")

    email: str = Field(..., min_length=1, max_length=320)


class BeginAuthenticationResponse(BaseModel):
    """Envelope for the ``PublicKeyCredentialRequestOptions`` returned to the browser.

    The browser's ``navigator.credentials.get()`` expects its input under
    ``publicKey``; we keep the alias for Web IDL compatibility while storing
    the field internally as ``public_key``.
    """

    public_key: dict = Field(
        ...,
        alias="publicKey",
        description="WebAuthn PublicKeyCredentialRequestOptions",
    )

    model_config = ConfigDict(populate_by_name=True)


class CompleteAuthenticationRequest(BaseModel):
    """Payload the browser posts back after ``navigator.credentials.get()``."""

    model_config = ConfigDict(extra="forbid")

    response: dict = Field(
        ...,
        description="PublicKeyCredential JSON produced by navigator.credentials.get()",
    )


class CompleteAuthenticationResponse(BaseModel):
    """Response for a successful passkey authentication."""

    redirect_url: str = Field(..., max_length=2048)
