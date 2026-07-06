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
  * It does not perform the access-control decision that gates OIDC-client
    login (that lives in :mod:`services.oidc.access`, enforced at authorize).

Scope semantics (OpenID Connect Core 1.0, section 5.4):
  * ``profile`` -> name, given_name, family_name, locale, updated_at
  * ``email``   -> email, email_verified
  * ``groups``  -> groups (WeftID extension: the user's effective group names,
                   DAG-aware via the group_lineage closure table)
Unknown scopes are ignored. Absent user data is simply omitted (claims are only
included when a value is present), matching the spec's "MAY" language. The
``groups`` claim is the one exception: when the ``groups`` scope is granted it is
always released, as an empty list when the user is in no group (an empty list is
a meaningful "no groups" answer, not missing data).
"""

from __future__ import annotations

import database

# Standard OIDC scope names.
SCOPE_OPENID = "openid"
SCOPE_PROFILE = "profile"
SCOPE_EMAIL = "email"
# WeftID extension scope: releases the user's effective group memberships.
SCOPE_GROUPS = "groups"

# Scopes this provider recognises and advertises. `openid` gates ID-token
# issuance itself and carries no profile data of its own.
SUPPORTED_SCOPES = (SCOPE_OPENID, SCOPE_PROFILE, SCOPE_EMAIL, SCOPE_GROUPS)

# Human-readable descriptions shown on the authorize/consent page so the user
# can see what each requested scope grants. Keyed by scope name.
SCOPE_DESCRIPTIONS = {
    SCOPE_OPENID: "Confirm your identity",
    SCOPE_PROFILE: "Your name and profile information",
    SCOPE_EMAIL: "Your email address",
    SCOPE_GROUPS: "Your group memberships",
}


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
        A dict of released claims. Empty if no recognised claim-bearing scope is
        granted or the user cannot be resolved. Never includes `sub` or any
        token-envelope claim.
    """
    claims: dict = {}

    # profile/email claims require a single user-data read, gated by scope.
    if scopes & {SCOPE_PROFILE, SCOPE_EMAIL}:
        row = database.oidc.get_user_claim_data(tenant_id, user_id)
        if row is not None:
            if SCOPE_PROFILE in scopes:
                _add_profile_claims(claims, row)
            if SCOPE_EMAIL in scopes:
                _add_email_claims(claims, row)

    # The `groups` claim is sourced from the effective (DAG-aware) membership
    # closure so a user in a child group receives all ancestor group names.
    # Released whenever the `groups` scope is granted, even as an empty list.
    if SCOPE_GROUPS in scopes:
        claims["groups"] = database.groups.get_effective_group_names(tenant_id, user_id)

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
