"""Server-side store for upstream sign-in state.

Starting a sign-in creates ``state``, ``nonce`` and a PKCE ``code_verifier``.
They are kept here, in the cache, keyed by ``state``, rather than in the
session cookie: a provider that posts its callback from its own site (Apple's
``form_post``) arrives without the SameSite=Lax session cookie, and a future
shared callback host would have no tenant session at all.

The browser that started the sign-in is still bound to it: the login route
keeps ``state`` in the session, and the GET callback (on the tenant host,
where the cookie arrives) requires it to match before taking the entry. A
posted callback only attaches its fields (:func:`attach_callback_fields`) and
redirects to the GET callback.

Keys are a SHA-256 of ``state``, so a caller-supplied value never shapes the
cache key. Entries live for :data:`LOGIN_STATE_TTL` seconds and are removed on
first use.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field

from utils import cache

# How long a started sign-in may take at the provider.
LOGIN_STATE_TTL = 600

_KEY_PREFIX = "oidc_login_state:"

# The posted callback fields kept for the GET callback.
CALLBACK_FIELDS = ("code", "error", "user")


@dataclass(frozen=True)
class LoginState:
    """A started sign-in.

    Attributes:
        tenant_id: The tenant the sign-in was started on.
        connection_id: The connection it goes through.
        nonce: The ID-token replay nonce.
        code_verifier: The PKCE verifier.
        entry: ``login_button`` or ``routed`` (audit metadata).
        callback_fields: Fields the provider posted to the callback
            (``form_post``), or None when the callback is a plain GET.
    """

    tenant_id: str
    connection_id: str
    nonce: str
    code_verifier: str
    entry: str
    callback_fields: dict[str, str] | None = field(default=None)


def _key(state: str) -> str:
    return _KEY_PREFIX + hashlib.sha256(state.encode()).hexdigest()


def save_login_state(state: str, login_state: LoginState) -> bool:
    """Store a new sign-in. Returns False if the store is unavailable."""
    return cache.add(_key(state), json.dumps(asdict(login_state)), ttl=LOGIN_STATE_TTL)


def load_login_state(state: str) -> LoginState | None:
    """Return the sign-in stored for ``state``, or None (unknown, expired, bad)."""
    if not state:
        return None
    raw = cache.get(_key(state))
    if raw is None:
        return None
    try:
        data = json.loads(raw)
        callback_fields = data.get("callback_fields")
        if callback_fields is not None and not (
            isinstance(callback_fields, dict)
            and all(isinstance(v, str) for v in callback_fields.values())
        ):
            return None
        login_state = LoginState(
            tenant_id=data["tenant_id"],
            connection_id=data["connection_id"],
            nonce=data["nonce"],
            code_verifier=data["code_verifier"],
            entry=data["entry"],
            callback_fields=callback_fields,
        )
    except ValueError, KeyError, TypeError, AttributeError:
        return None
    if not all(
        isinstance(value, str)
        for value in (
            login_state.tenant_id,
            login_state.connection_id,
            login_state.nonce,
            login_state.code_verifier,
            login_state.entry,
        )
    ):
        return None
    return login_state


def attach_callback_fields(state: str, login_state: LoginState, fields: dict[str, str]) -> bool:
    """Record what the provider posted to the callback, for the GET callback.

    Only :data:`CALLBACK_FIELDS` are kept. A sign-in takes one posted
    callback: returns False when fields are already attached or the store
    is unavailable, or another post got there first.
    """
    if login_state.callback_fields is not None:
        return False
    # Read-then-write is not atomic: a marker that only one post can add
    # settles two concurrent posts.
    if not cache.add(_key(state) + ":posted", "1", ttl=LOGIN_STATE_TTL):
        return False
    kept = {name: value for name, value in fields.items() if name in CALLBACK_FIELDS and value}
    updated = LoginState(**{**asdict(login_state), "callback_fields": kept})
    return cache.set(_key(state), json.dumps(asdict(updated)), ttl=LOGIN_STATE_TTL)


def take_login_state(state: str) -> LoginState | None:
    """Return the sign-in stored for ``state`` and remove it (single use)."""
    login_state = load_login_state(state)
    if login_state is not None:
        cache.delete(_key(state))
    return login_state
