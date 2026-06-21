"""Protected-domain (forward-auth) management service.

A protected domain is a real DNS/web domain a tenant registers so WeftID can act
as its forward-auth authority for HTTP apps under it. WeftID must be reachable at
a portal host under that domain (e.g. auth.acme-corp.com) to set the per-domain
forward-auth cookie and have certs issued.

Ownership is proven via a DNS-TXT challenge: WeftID issues a unique token, the
operator publishes it as a TXT record, and WeftID verifies it before flipping the
domain to 'verified'. Only verified domains may serve cookies or get certificates.

This is deliberately separate from privileged (email) domains
(services.settings.domains): those route identity by the right-hand side of a
user's email address and carry no DNS ownership proof. The same string may be
registered as both; they answer different questions.
"""

import logging
import secrets
from datetime import UTC, datetime

import database
import dns.exception
import dns.resolver
from schemas.protected_domains import (
    ProtectedDomain,
    ProtectedDomainCreate,
    ProtectedDomainList,
    ProtectedDomainVerifyResult,
)
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import ConflictError, NotFoundError, ValidationError
from services.types import RequestingUser

log = logging.getLogger(__name__)

# DNS name under the protected domain where the challenge TXT record is published.
# A dedicated subdomain avoids clobbering the domain's root TXT (SPF, etc.).
_CHALLENGE_PREFIX = "_weftid-challenge"
# Prefix on the TXT value so the record is unambiguous and self-describing.
_CHALLENGE_VALUE_PREFIX = "weftid-domain-verification="

# Multi-label public suffixes a tenant must never register as a protected
# domain: setting a forward-auth cookie with Domain=<suffix> would scope it
# across every registrable domain beneath the suffix. Single-label TLDs
# (com, net, ...) are already rejected by the "must contain a dot" rule, so
# this list covers only the common multi-label ones. It is a defense-in-depth
# denylist, NOT a full public-suffix list; the DNS-TXT ownership challenge is
# the primary control (an attacker cannot publish TXT under a suffix they do
# not control).
_PUBLIC_SUFFIX_DENYLIST = frozenset(
    {
        "co.uk",
        "org.uk",
        "gov.uk",
        "ac.uk",
        "ltd.uk",
        "plc.uk",
        "me.uk",
        "net.uk",
        "sch.uk",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "id.au",
        "co.nz",
        "net.nz",
        "org.nz",
        "govt.nz",
        "ac.nz",
        "co.za",
        "org.za",
        "co.jp",
        "ne.jp",
        "or.jp",
        "go.jp",
        "ac.jp",
        "com.br",
        "net.br",
        "org.br",
        "gov.br",
        "com.mx",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "com.sg",
        "com.hk",
        "co.in",
        "net.in",
        "org.in",
        "gen.in",
        "firm.in",
        "co.kr",
        "or.kr",
        "com.tr",
        "com.tw",
        "com.ar",
        "com.co",
    }
)


# =============================================================================
# Validation helpers (private)
# =============================================================================


def _normalize_host(value: str) -> str:
    """Normalize a domain/host: strip, lowercase, drop trailing dot and @ prefix."""
    value = value.strip().lower().rstrip(".")
    if value.startswith("@"):
        value = value[1:]
    return value


def _validate_host(value: str, field: str) -> None:
    """Validate a domain/host string. Raises ValidationError if invalid."""
    if not value:
        raise ValidationError(
            message="This field cannot be empty.", code="invalid_domain", field=field
        )
    if " " in value:
        raise ValidationError(
            message="Domains cannot contain spaces.", code="invalid_domain", field=field
        )
    if "." not in value:
        raise ValidationError(
            message="Enter a fully-qualified domain name (e.g. acme-corp.com).",
            code="invalid_domain",
            field=field,
        )
    if len(value) < 3 or len(value) > 253:
        raise ValidationError(
            message="Domains must be 3-253 characters.",
            code="invalid_domain_length",
            field=field,
        )
    # Conservative hostname charset: letters, digits, hyphen, dot.
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    if any(ch not in allowed for ch in value):
        raise ValidationError(
            message="Domains may only contain letters, digits, hyphens, and dots.",
            code="invalid_domain",
            field=field,
        )
    # Reject bare public suffixes so a forward-auth cookie can't be scoped
    # across an entire registry (e.g. Domain=co.uk).
    if value in _PUBLIC_SUFFIX_DENYLIST:
        raise ValidationError(
            message="Enter a registrable domain, not a public suffix (e.g. acme-corp.co.uk).",
            code="public_suffix_not_allowed",
            field=field,
        )


def challenge_record_name(domain: str) -> str:
    """Return the DNS name where the challenge TXT record must be published."""
    return f"{_CHALLENGE_PREFIX}.{domain}"


def challenge_record_value(token: str) -> str:
    """Return the full TXT record value the operator must publish."""
    return f"{_CHALLENGE_VALUE_PREFIX}{token}"


def _resolve_txt(name: str, timeout: float = 5.0) -> list[str]:
    """Resolve TXT records for *name*. Returns decoded strings or empty list.

    Mirrors the resolver pattern in app/cli/verify_email.py. Fails closed: any
    DNS error (NXDOMAIN, no answer, timeout) yields an empty list, so the caller
    treats the challenge as unsatisfied.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        answers = resolver.resolve(name, "TXT")
        return [b"".join(rdata.strings).decode() for rdata in answers]
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
    ):
        return []
    except dns.exception.Timeout:
        return []
    except dns.exception.DNSException:
        return []


def _row_to_model(row: dict, created_by_name: str | None = None) -> ProtectedDomain:
    """Convert a protected_domains row to a ProtectedDomain model."""
    status = row["verification_status"]
    token = row.get("verification_token")
    # Once verified, the token is cleared; surface no record value.
    record_value = challenge_record_value(token) if token and status != "verified" else None
    return ProtectedDomain(
        id=str(row["id"]),
        domain=row["domain"],
        portal_host=row["portal_host"],
        verification_status=status,
        verification_token=token if status != "verified" else None,
        verification_record_name=challenge_record_name(row["domain"]),
        verification_record_value=record_value,
        verified_at=row.get("verified_at"),
        enabled=row["enabled"],
        created_at=row["created_at"],
        created_by_name=created_by_name,
    )


def _created_by_name(tenant_id: str, created_by: object) -> str | None:
    """Resolve a created_by user id to a display name, if available."""
    if not created_by:
        return None
    user = database.users.get_user_by_id(tenant_id, str(created_by))
    if not user:
        return None
    name = f"{user.get('first_name', '') or ''} {user.get('last_name', '') or ''}".strip()
    return name or user.get("email")


# =============================================================================
# CRUD + verification (admin-authz)
# =============================================================================


def list_protected_domains(requesting_user: RequestingUser) -> ProtectedDomainList:
    """List all protected domains for the tenant.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    rows = database.protected_domains.list_protected_domains(tenant_id)
    items = [_row_to_model(r, _created_by_name(tenant_id, r.get("created_by"))) for r in rows]
    return ProtectedDomainList(items=items, total=len(items))


def get_protected_domain(requesting_user: RequestingUser, domain_id: str) -> ProtectedDomain:
    """Get a single protected domain by ID.

    Authorization: Requires super_admin role.

    Raises:
        NotFoundError: If the domain does not exist for this tenant.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    row = database.protected_domains.get_protected_domain(tenant_id, domain_id)
    if not row:
        raise NotFoundError(
            message="Protected domain not found.",
            code="protected_domain_not_found",
            details={"domain_id": domain_id},
        )
    return _row_to_model(row, _created_by_name(tenant_id, row.get("created_by")))


def register_protected_domain(
    requesting_user: RequestingUser, data: ProtectedDomainCreate
) -> ProtectedDomain:
    """Register a domain to protect with forward auth.

    Generates a DNS-TXT challenge token. The domain starts 'pending' and must be
    verified before it can serve cookies or get TLS certificates.

    Authorization: Requires super_admin role.

    Raises:
        ValidationError: If the domain or portal host is malformed, or the portal
            host is not under the domain.
        ConflictError: If the domain is already registered for this tenant, or the
            portal host is already in use by any tenant.
    """
    require_super_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    domain = _normalize_host(data.domain)
    portal_host = _normalize_host(data.portal_host)
    _validate_host(domain, "domain")
    _validate_host(portal_host, "portal_host")

    # The portal host must be under the protected domain (the browser cookie rule
    # only lets WeftID set a Domain=<domain> cookie from a host under it).
    if portal_host != domain and not portal_host.endswith(f".{domain}"):
        raise ValidationError(
            message=(f"The portal host must be under the protected domain (e.g. auth.{domain})."),
            code="portal_host_not_under_domain",
            field="portal_host",
        )

    if database.protected_domains.get_protected_domain_by_domain(tenant_id, domain):
        raise ConflictError(
            message=f"'{domain}' is already registered as a protected domain.",
            code="protected_domain_exists",
            details={"domain": domain},
        )

    # portal_host is globally unique; check across tenants to give a clean error
    # rather than a DB integrity failure.
    existing_host = database.protected_domains.get_protected_domain_by_portal_host(
        database.UNSCOPED, portal_host
    )
    if existing_host:
        raise ConflictError(
            message=f"The portal host '{portal_host}' is already in use.",
            code="portal_host_in_use",
            details={"portal_host": portal_host},
        )

    token = secrets.token_hex(24)
    row = database.protected_domains.create_protected_domain(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        domain=domain,
        portal_host=portal_host,
        created_by=requesting_user["id"],
        verification_token=token,
        verification_status="pending",
    )
    if not row:
        raise ValidationError(
            message="Failed to register protected domain.",
            code="protected_domain_create_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        event_type="protected_domain_registered",
        artifact_type="protected_domain",
        artifact_id=str(row["id"]),
        metadata={"domain": domain, "portal_host": portal_host},
    )

    return _row_to_model(row, _created_by_name(tenant_id, row.get("created_by")))


def verify_protected_domain(
    requesting_user: RequestingUser, domain_id: str
) -> ProtectedDomainVerifyResult:
    """Re-runnable DNS-TXT verification for a protected domain.

    Resolves the challenge TXT record and, if it matches the issued token, flips
    the domain to 'verified' and clears the token. On a missing/mismatched record
    the domain is set to 'failed' so the operator knows to retry after the record
    propagates. Fails closed: any DNS error counts as not verified.

    Authorization: Requires super_admin role.

    Raises:
        NotFoundError: If the domain does not exist for this tenant.
    """
    require_super_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    row = database.protected_domains.get_protected_domain(tenant_id, domain_id)
    if not row:
        raise NotFoundError(
            message="Protected domain not found.",
            code="protected_domain_not_found",
            details={"domain_id": domain_id},
        )

    # Already verified: idempotent success, no DNS call.
    if row["verification_status"] == "verified":
        return ProtectedDomainVerifyResult(
            verified=True,
            status="verified",
            message="This domain is already verified.",
        )

    token = row.get("verification_token")
    if not token:
        raise ValidationError(
            message="This domain has no active verification challenge.",
            code="no_challenge_token",
        )

    domain = row["domain"]
    record_name = challenge_record_name(domain)
    expected = challenge_record_value(token)
    found = _resolve_txt(record_name)

    if expected in found:
        database.protected_domains.update_protected_domain(
            tenant_id,
            domain_id,
            verification_status="verified",
            verification_token=None,
            verified_at=datetime.now(UTC),
        )
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            event_type="protected_domain_verified",
            artifact_type="protected_domain",
            artifact_id=domain_id,
            metadata={"domain": domain},
        )
        return ProtectedDomainVerifyResult(
            verified=True,
            status="verified",
            message=f"Ownership of {domain} verified.",
        )

    # Not found / mismatch -> failed (re-runnable; operator can retry).
    database.protected_domains.update_protected_domain(
        tenant_id, domain_id, verification_status="failed"
    )
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        event_type="protected_domain_verification_failed",
        artifact_type="protected_domain",
        artifact_id=domain_id,
        metadata={"domain": domain},
    )
    return ProtectedDomainVerifyResult(
        verified=False,
        status="failed",
        message=(
            f"The expected TXT record was not found at {record_name}. "
            "DNS changes can take time to propagate; add the record and try again."
        ),
    )


def delete_protected_domain(requesting_user: RequestingUser, domain_id: str) -> None:
    """Delete a protected domain (cascades to its proxy apps and grants).

    Authorization: Requires super_admin role.

    Raises:
        NotFoundError: If the domain does not exist for this tenant.
    """
    require_super_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    row = database.protected_domains.get_protected_domain(tenant_id, domain_id)
    if not row:
        raise NotFoundError(
            message="Protected domain not found.",
            code="protected_domain_not_found",
            details={"domain_id": domain_id},
        )

    database.protected_domains.delete_protected_domain(tenant_id, domain_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        event_type="protected_domain_deleted",
        artifact_type="protected_domain",
        artifact_id=domain_id,
        metadata={"domain": row["domain"], "portal_host": row["portal_host"]},
    )


# =============================================================================
# Pre-auth infrastructure helpers (no authorization; fail-closed)
# =============================================================================


def resolve_verified_portal_host(portal_host: str) -> dict | None:
    """Resolve a portal host to its owning protected-domain row, fail-closed.

    Used by the (unauthenticated) Caddy ask endpoint and TenantGuardMiddleware.
    Returns the row only if the host maps to a VERIFIED, ENABLED protected domain;
    otherwise None. portal_host is globally unique, so this is a single indexed
    UNSCOPED lookup.
    """
    host = _normalize_host(portal_host)
    if not host:
        return None
    row = database.protected_domains.get_protected_domain_by_portal_host(database.UNSCOPED, host)
    if not row:
        return None
    if row["verification_status"] != "verified" or not row["enabled"]:
        return None
    return row


def is_verified_portal_host(portal_host: str) -> bool:
    """Return True if *portal_host* is a verified, enabled protected-domain host."""
    return resolve_verified_portal_host(portal_host) is not None
