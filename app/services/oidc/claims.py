"""Scope-gated OIDC claim assembly.

This is the single shared assembler for the identity claims WeftID releases as
a downstream OIDC provider. It is deliberately the one code path used by both
the ID token (this iteration) and the userinfo endpoint (Iteration 3), and it
is the place Iteration 4 adds the `groups` claim. Keeping one assembler means a
claim is gated by its scope in exactly one location, so the ID token and
userinfo can never drift.

What it does NOT do:
  * It does not emit `sub` / `iss` / `aud` / `exp` / `iat` / `auth_time` /
    `nonce`. Those are token-envelope claims added by the ID-token minter (and
    `sub` is added by the userinfo endpoint in Iteration 3). `sub` is always the
    stable WeftID user id, never derived here from a scope.
  * It does not add the `groups` claim or perform any access-control decision
    (deferred to Iteration 4).

Scope semantics (OpenID Connect Core 1.0, section 5.4):
  * ``profile`` -> name, given_name, family_name, locale, updated_at
  * ``email``   -> email, email_verified
Unknown scopes are ignored. Absent user data is simply omitted (claims are only
included when a value is present), matching the spec's "MAY" language.
"""

from __future__ import annotations

import database

# Standard OIDC scope names.
SCOPE_OPENID = "openid"
SCOPE_PROFILE = "profile"
SCOPE_EMAIL = "email"

# Scopes this provider recognises and advertises. `openid` gates ID-token
# issuance itself and carries no profile data of its own.
SUPPORTED_SCOPES = (SCOPE_OPENID, SCOPE_PROFILE, SCOPE_EMAIL)


def parse_scope(scope: str | None) -> set[str]:
    """Split an OAuth2 space-delimited scope string into a set of scope names."""
    if not scope:
        return set()
    return {s for s in scope.split() if s}


def build_claims(tenant_id: str, user_id: str, scopes: set[str]) -> dict:
    """Assemble the scope-gated identity claims for a user.

    Args:
        tenant_id: Tenant ID for RLS scoping.
        user_id: The subject user's stable WeftID id.
        scopes: The granted scope names (already parsed).

    Returns:
        A dict of released claims. Empty if no recognised profile/email scope is
        granted or the user cannot be resolved. Never includes `sub` or any
        token-envelope claim.
    """
    # Nothing to release unless a claim-bearing scope was granted.
    if not scopes & {SCOPE_PROFILE, SCOPE_EMAIL}:
        return {}

    row = database.oidc.get_user_claim_data(tenant_id, user_id)
    if row is None:
        return {}

    claims: dict = {}

    if SCOPE_PROFILE in scopes:
        _add_profile_claims(claims, row)

    if SCOPE_EMAIL in scopes:
        _add_email_claims(claims, row)

    return claims


def _add_profile_claims(claims: dict, row: dict) -> None:
    """Add `profile`-scope claims, omitting any that are absent."""
    given_name = row.get("first_name")
    family_name = row.get("last_name")

    if given_name:
        claims["given_name"] = given_name
    if family_name:
        claims["family_name"] = family_name

    full_name = " ".join(part for part in (given_name, family_name) if part).strip()
    if full_name:
        claims["name"] = full_name

    if row.get("locale"):
        claims["locale"] = row["locale"]

    updated_at = row.get("updated_at")
    if updated_at is not None:
        # OIDC `updated_at` is seconds since the epoch (NumericDate).
        claims["updated_at"] = int(updated_at.timestamp())


def _add_email_claims(claims: dict, row: dict) -> None:
    """Add `email`-scope claims when the user has a primary email."""
    email = row.get("primary_email")
    if email:
        claims["email"] = email
        claims["email_verified"] = bool(row.get("email_verified"))
