"""Typed errors for the OIDC upstream (relying-party) connector.

The connector core (discovery, JWKS, ID-token validation) is pure service
code with no HTTP/session concerns, so it raises these plain exceptions
rather than the HTTP-facing ``ServiceError`` subclasses. The auth flow
(Iteration 3) catches them and translates each into the appropriate
response (a clear rejection page, a logged ``oidc_login_failed`` event, or
a retryable discovery error).

Each failure mode has a distinct type so callers and tests can assert on
the exact cause rather than matching message strings.
"""


class OIDCUpstreamError(Exception):
    """Base class for all OIDC upstream connector errors."""


class DiscoveryError(OIDCUpstreamError):
    """Discovery document could not be fetched or parsed."""


class DiscoveryIssuerMismatchError(DiscoveryError):
    """The discovery document's ``issuer`` does not match the configured issuer."""

    def __init__(self, configured: str, discovered: str) -> None:
        self.configured = configured
        self.discovered = discovered
        super().__init__(
            f"Discovery issuer mismatch: configured {configured!r}, discovered {discovered!r}"
        )


class DiscoveryInsecureEndpointError(DiscoveryError):
    """A discovery endpoint URL is not https (rejected outside IS_DEV)."""

    def __init__(self, field: str, url: str) -> None:
        self.field = field
        self.url = url
        super().__init__(f"Discovery endpoint {field!r} is not https: {url!r}")


class DiscoveryRedirectError(DiscoveryError):
    """The discovery URL returned a redirect, which is not followed."""

    def __init__(self, url: str, status_code: int) -> None:
        self.url = url
        self.status_code = status_code
        super().__init__(
            f"Discovery URL {url!r} returned a redirect ({status_code}); "
            "redirects are not followed for SSRF safety"
        )


class JwksError(OIDCUpstreamError):
    """JWKS could not be fetched or parsed."""


class IDTokenValidationError(OIDCUpstreamError):
    """Base class for ID-token validation failures."""


class IDTokenSignatureError(IDTokenValidationError):
    """ID token signature could not be verified against the JWKS."""


class IDTokenIssuerError(IDTokenValidationError):
    """ID token ``iss`` does not match the connection issuer."""


class IDTokenAudienceError(IDTokenValidationError):
    """ID token ``aud`` does not include the connection client_id."""


class IDTokenNonceError(IDTokenValidationError):
    """ID token ``nonce`` does not match the expected nonce."""


class IDTokenExpiredError(IDTokenValidationError):
    """ID token is expired."""


class IDTokenNotYetValidError(IDTokenValidationError):
    """ID token ``iat`` is in the future beyond tolerance."""


class IDTokenMissingClaimsError(IDTokenValidationError):
    """ID token is missing a required claim."""
