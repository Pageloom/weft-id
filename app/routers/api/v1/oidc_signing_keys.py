"""OIDC signing-key management API endpoints.

Operator surface for the per-tenant OIDC signing key: inspect the current
key metadata, rotate with an overlap grace period, and trigger retired-key
cleanup. Only non-sensitive metadata ever crosses this boundary; private key
material never leaves the service layer.
"""

from typing import Annotated

from api_dependencies import require_admin_api, require_super_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends
from schemas.oidc import (
    OIDCSigningKeyCleanupResult,
    OIDCSigningKeyRotateRequest,
    OIDCSigningKeyRotationResult,
    OIDCSigningKeyStatus,
)
from services.exceptions import ServiceError
from services.oidc import keys as oidc_keys_service
from utils.service_errors import translate_to_http_exception

router = APIRouter(prefix="/api/v1/oidc/signing-key", tags=["OIDC Signing Key"])


@router.get("", response_model=OIDCSigningKeyStatus)
def get_signing_key_status(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
):
    """Get metadata about the tenant's OIDC signing key.

    Requires admin role. Provisions the key lazily if the tenant has never
    served its JWKS before.

    Returns:
        kid, algorithm, created_at for the active key, plus previous_kid,
        previous_created_at and rotation_grace_period_ends_at when a rotation
        is within its grace period, and rotation_in_progress. No key material
        is ever returned (the kid values are already public via the JWKS
        endpoint).
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        return oidc_keys_service.get_signing_key_status(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/rotate", response_model=OIDCSigningKeyRotationResult)
def rotate_signing_key(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_super_admin_api)],
    data: OIDCSigningKeyRotateRequest | None = None,
):
    """Rotate the tenant's OIDC signing key.

    Requires super_admin role.

    A new RSA-2048 key becomes the active signing key immediately; the
    retired key stays published in the JWKS for the grace period so relying
    parties can still verify in-flight ID tokens. Rotation is refused (400)
    while a prior rotation is still within its grace period.

    Request Body (optional):
        grace_period_hours: How long the retired key stays published in JWKS
            (1 to 720 hours). Defaults to 24.

    Returns:
        kid (new active key id), previous_kid, rotated_at, and
        grace_period_ends_at. No key material is returned.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    grace_period_hours = data.grace_period_hours if data is not None else 24
    try:
        return oidc_keys_service.rotate_signing_key(
            requesting_user, grace_period_hours=grace_period_hours
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/cleanup", response_model=OIDCSigningKeyCleanupResult)
def cleanup_previous_signing_key(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_super_admin_api)],
):
    """Remove the tenant's retired OIDC signing key from the JWKS.

    Requires super_admin role.

    Only clears a retired key whose rotation grace period has already ended;
    a key still within its grace window is left in place so relying parties
    can finish verifying in-flight tokens. The periodic worker sweep performs
    the same cleanup automatically, so this endpoint is only needed to force
    the removal without waiting for the next sweep.

    Returns:
        cleaned_up: True if an expired retired key was removed, False if
        there was no retired key or its grace period has not ended yet.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        return OIDCSigningKeyCleanupResult(
            cleaned_up=oidc_keys_service.force_cleanup_previous_signing_key(requesting_user)
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
