"""OIDC upstream provider adapters.

An adapter owns everything about a sign-in that depends on the provider: the
authorize URL, the code exchange, and turning what the provider returns into
one normalized :class:`UpstreamIdentity`. The routes in
``routers.oidc_upstream.authentication`` own the session state and what
happens after the identity is known (correlation, MFA, login completion), and
never branch on the provider.

Spec OIDC (:class:`SpecOIDCAdapter`) is the default and serves every preset
that publishes a discovery document and issues ID tokens. Providers that do
not (GitHub, Discord, Facebook) or that bend the spec (Apple) get their own
adapter, registered in ``_ADAPTERS``. Presets stay pure defaults.

Two seams exist so that platform-owned shared provider apps stay possible
later: client credentials are resolved only through
:func:`resolve_client_credentials`, and callback URLs are built only by
:func:`callback_url`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from services.oidc_upstream.errors import OIDCUpstreamError
from services.oidc_upstream.presets import token_auth_method

# The path the provider sends the browser back to. Built only by callback_url.
_CALLBACK_PATH = "/auth/oidc/{connection_id}/callback"

# Scopes requested when a connection has none stored.
_FALLBACK_SCOPES = "openid profile email"


@dataclass(frozen=True)
class ClientCredentials:
    """The credentials a connection presents to its provider."""

    client_id: str
    client_secret: str
    token_auth_method: str


@dataclass(frozen=True)
class UpstreamIdentity:
    """A provider's answer to a sign-in, normalized across providers.

    Attributes:
        subject: The value users are correlated on (the connection's
            correlation claim: ``sub``, Entra's ``oid``, ...).
        claims: Every claim known about the user, for provisioning, claim
            mapping and group sync.
        upstream_sub: The provider session's subject, for back-channel and
            RP-initiated logout. None when the provider has no sessions to
            end (no ID token).
        upstream_sid: The provider session id (``sid``), when issued.
        id_token: The raw ID token, kept for ``id_token_hint`` at logout.
    """

    subject: str
    claims: dict
    upstream_sub: str | None = None
    upstream_sid: str | None = None
    id_token: str | None = None


class ProviderLoginError(OIDCUpstreamError):
    """A sign-in step failed.

    Attributes:
        reason: The ``oidc_login_failed`` audit reason (``token_exchange``,
            ``id_token``, ...).
        detail: Optional detail for the audit event. Never shown to the user.
        public_error: The ``/login?error=`` value shown to the user.
    """

    def __init__(
        self,
        reason: str,
        detail: str | None = None,
        *,
        public_error: str = "auth_failed",
    ) -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail
        self.public_error = public_error


class ProviderCheckError(OIDCUpstreamError):
    """Test Connection found a problem. The message is safe to show an admin."""


class ProviderAdapter(Protocol):
    """What a provider adapter does for the login and callback routes."""

    def prepare(self, tenant_id: str, connection: dict) -> dict:
        """Return the connection row fit to sign in with.

        Raises:
            DiscoveryError: the provider's published configuration was refused.
        """
        ...

    def authorize_url(
        self,
        connection: dict,
        *,
        redirect_uri: str,
        state: str,
        nonce: str,
        code_challenge: str,
    ) -> str:
        """Build the provider's authorize URL.

        Raises:
            ProviderLoginError: the connection is not configured to sign in.
        """
        ...

    def complete(
        self,
        tenant_id: str,
        connection: dict,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str,
        nonce: str | None,
    ) -> UpstreamIdentity:
        """Exchange the code and return the user's normalized identity.

        Raises:
            ProviderLoginError: any step failed; carries the audit reason.
        """
        ...

    def check(self, tenant_id: str, connection: dict, *, redirect_uri: str) -> dict:
        """Check the connection against the provider (Test Connection).

        Returns the connection row, refreshed with anything the check stored.

        Raises:
            ProviderCheckError: the check failed; the message says why.
        """
        ...


def callback_url(base_url: str, connection_id: str) -> str:
    """Return a connection's callback URL (the redirect URI to register).

    The single place the callback URL is built. ``base_url`` is the tenant's
    origin without a trailing slash.
    """
    return f"{base_url}{_CALLBACK_PATH.format(connection_id=connection_id)}"


def resolve_client_credentials(connection: dict) -> ClientCredentials | None:
    """Return the credentials a connection presents to its provider.

    The single place credentials are read: today they are the connection's
    own client id and decrypted secret. Returns None when the connection has
    no client id or secret.
    """
    from services.oidc_upstream.connections import decrypt_client_secret

    client_id = connection.get("client_id")
    client_secret_enc = connection.get("client_secret_enc")
    if not client_id or not client_secret_enc:
        return None
    return ClientCredentials(
        client_id=client_id,
        client_secret=decrypt_client_secret(client_secret_enc),
        token_auth_method=token_auth_method(connection.get("provider_type") or "generic"),
    )


class SpecOIDCAdapter:
    """The default adapter: discovery, ID-token validation and userinfo."""

    def prepare(self, tenant_id: str, connection: dict) -> dict:
        # Pick up endpoint changes the IdP published since the last discovery
        # (TTL-gated).
        import services.oidc_upstream as oidc_service

        return oidc_service.refresh_for_login(tenant_id, connection)

    def authorize_url(
        self,
        connection: dict,
        *,
        redirect_uri: str,
        state: str,
        nonce: str,
        code_challenge: str,
    ) -> str:
        import services.oidc_upstream as oidc_service

        authorization_endpoint = connection.get("authorization_endpoint")
        client_id = connection.get("client_id")
        if not authorization_endpoint or not client_id:
            raise ProviderLoginError("configuration_error", public_error="configuration_error")

        return oidc_service.build_authorize_url(
            authorization_endpoint=authorization_endpoint,
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            scopes=connection.get("scopes") or _FALLBACK_SCOPES,
            hosted_domain=connection.get("hosted_domain"),
        )

    def complete(
        self,
        tenant_id: str,
        connection: dict,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str,
        nonce: str | None,
    ) -> UpstreamIdentity:
        # The helpers are looked up on the package at call time so a test
        # patch on ``services.oidc_upstream.<name>`` reaches them.
        import services.oidc_upstream as oidc_service

        connection_id = str(connection["id"])
        token_endpoint = connection.get("token_endpoint")
        if not token_endpoint:
            raise ProviderLoginError("configuration_error", public_error="configuration_error")
        credentials = resolve_client_credentials(connection)
        if credentials is None:
            raise ProviderLoginError("configuration_error", public_error="configuration_error")

        try:
            token_response = oidc_service.exchange_code(
                token_endpoint=token_endpoint,
                client_id=credentials.client_id,
                client_secret=credentials.client_secret,
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
                auth_method=credentials.token_auth_method,
            )
        except oidc_service.TokenExchangeError as exc:
            raise ProviderLoginError("token_exchange", str(exc)) from exc

        id_token = token_response.get("id_token")
        if not id_token:
            raise ProviderLoginError("missing_id_token")

        jwks_uri = connection.get("jwks_uri")
        issuer = connection.get("issuer")
        if not jwks_uri or not issuer:
            raise ProviderLoginError("configuration_error", public_error="configuration_error")

        try:
            claims = oidc_service.validate_id_token(
                token=id_token,
                tenant_id=tenant_id,
                connection_id=connection_id,
                issuer=issuer,
                client_id=credentials.client_id,
                jwks_uri=jwks_uri,
                nonce=nonce,
            )
        except oidc_service.IDTokenValidationError as exc:
            raise ProviderLoginError("id_token", str(exc)) from exc

        # The upstream session this sign-in belongs to, read from the verified
        # ID token itself (userinfo cannot speak for the session).
        upstream_sub = claims.get("sub")
        upstream_sid = claims.get("sid") if isinstance(claims.get("sid"), str) else None

        # Optionally merge userinfo claims (email may live there for some IdPs).
        userinfo_endpoint = connection.get("userinfo_endpoint")
        access_token = token_response.get("access_token")
        if userinfo_endpoint and access_token:
            try:
                userinfo = oidc_service.fetch_userinfo(
                    userinfo_endpoint=userinfo_endpoint,
                    access_token=access_token,
                    expected_sub=claims["sub"],
                )
                claims = {**userinfo, **claims}
            except oidc_service.UserinfoError:
                # Userinfo is optional; a failure here must not break login.
                pass
            except oidc_service.UserinfoSubjectMismatchError as exc:
                # A response about another subject is not optional data to
                # skip: the IdP (or something in between) is confused or lying.
                raise ProviderLoginError("userinfo_sub_mismatch", str(exc)) from exc

        correlation_claim = connection.get("correlation_claim") or "sub"
        subject = claims.get(correlation_claim)
        if not subject or not isinstance(subject, str):
            raise ProviderLoginError("missing_sub")

        return UpstreamIdentity(
            subject=subject,
            claims=claims,
            upstream_sub=upstream_sub if isinstance(upstream_sub, str) and upstream_sub else None,
            upstream_sid=upstream_sid,
            id_token=id_token,
        )

    def check(self, tenant_id: str, connection: dict, *, redirect_uri: str) -> dict:
        # Discovery runs regardless of the TTL and replaces the stored
        # endpoints; the key set it advertises is then fetched so an unusable
        # one is reported now rather than at the first sign-in.
        from services.oidc_upstream import jwks as jwks_service
        from services.oidc_upstream.discovery import run_discovery
        from services.oidc_upstream.errors import DiscoveryError, JwksError

        try:
            row = run_discovery(tenant_id, str(connection["id"]), force=True)
            jwks_service.refresh_jwks(tenant_id, str(connection["id"]), str(row["jwks_uri"]))
        except DiscoveryError as exc:
            raise ProviderCheckError(f"Discovery failed: {exc}") from exc
        except JwksError as exc:
            raise ProviderCheckError(f"Key set (JWKS) failed: {exc}") from exc
        return row


_SPEC_OIDC = SpecOIDCAdapter()


def _adapters() -> dict[str, ProviderAdapter]:
    """Provider types with their own adapter. Every other type is spec OIDC."""
    from services.oidc_upstream.github import GitHubAdapter

    return {"github": GitHubAdapter()}


_ADAPTERS: dict[str, ProviderAdapter] = _adapters()


def get_adapter(provider_type: str | None) -> ProviderAdapter:
    """Return the adapter for a provider type (spec OIDC by default)."""
    return _ADAPTERS.get(provider_type or "", _SPEC_OIDC)
