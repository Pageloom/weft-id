"""GitHub sign-in adapter.

GitHub is an OAuth2 provider, not OIDC: there is no discovery document, no
ID token and no userinfo endpoint. After the code exchange the adapter reads
the user from the REST API:

- ``GET /user``: the numeric account id (the subject: a login can be
  renamed, the id cannot), login, display name and avatar.
- ``GET /user/emails``: the account's addresses. Only the primary address,
  and only when GitHub has verified it, becomes ``email`` with
  ``email_verified: true``. Any other shape leaves the identity without an
  email, so it can neither email-link nor be provisioned.
- ``GET /user/orgs`` and ``GET /user/teams``: organization and team
  membership, fetched only when the connection needs them (allowed
  organizations, or group sync through the ``groups`` claim).

Allowed organizations: when the connection lists any, a user who belongs to
none of them is refused (``github_org_not_allowed``, audited by the callback
as ``oidc_login_failed``). Group sync then only sees those organizations and
their teams, so an outside organization a user happens to be in never
becomes a group in the tenant.

The ``groups`` claim holds organization logins (``acme``) and teams as
``<org>/<team-slug>`` (``acme/platform``). It feeds the connector's normal
group sync when the admin sets the group claim to ``groups``.

Every call goes through :func:`utils.safe_http.build_safe_client`.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode

from services.oidc_upstream._http import SAFE_CLIENT_OPTIONS, read_capped
from services.oidc_upstream.adapters import (
    ProviderCheckError,
    ProviderLoginError,
    UpstreamIdentity,
    resolve_client_credentials,
)
from services.oidc_upstream.errors import OIDCUpstreamError
from services.oidc_upstream.presets import get_preset
from services.oidc_upstream.token_exchange import TokenExchangeError, exchange_code
from utils.safe_http import build_safe_client

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
API_BASE_URL = "https://api.github.com"

# The claim carrying organizations and teams for group sync.
GROUPS_CLAIM = "groups"

# GitHub pages list endpoints at 100 per page at most. Five pages bound one
# sign-in to the group sync's own cap (500 groups).
_PAGE_SIZE = 100
_MAX_PAGES = 5

_API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# A code GitHub cannot have issued, for Test Connection. GitHub checks the
# client credentials before the code, so the error tells them apart.
_CHECK_CODE = "weftid-connection-test"


class GitHubAPIError(OIDCUpstreamError):
    """A GitHub REST API call failed."""


def _api_get(access_token: str, path: str, params: dict | None = None) -> Any:
    """GET a GitHub REST API path and return the parsed JSON body."""
    headers = {**_API_HEADERS, "Authorization": f"Bearer {access_token}"}
    with build_safe_client(**SAFE_CLIENT_OPTIONS) as client:
        try:
            status, body = read_capped(
                client, "GET", f"{API_BASE_URL}{path}", headers=headers, params=params
            )
        except Exception as exc:  # noqa: BLE001
            raise GitHubAPIError(f"{path} failed: {exc}") from exc
    if status != 200:
        raise GitHubAPIError(f"{path} returned HTTP {status}")
    try:
        return json.loads(body)
    except ValueError as exc:
        raise GitHubAPIError(f"{path} returned invalid JSON") from exc


def _api_get_list(access_token: str, path: str) -> list:
    """GET every page of a GitHub list endpoint (bounded by ``_MAX_PAGES``)."""
    items: list = []
    for page in range(1, _MAX_PAGES + 1):
        batch = _api_get(access_token, path, {"per_page": _PAGE_SIZE, "page": page})
        if not isinstance(batch, list):
            raise GitHubAPIError(f"{path} did not return a list")
        items.extend(batch)
        if len(batch) < _PAGE_SIZE:
            break
    return items


def primary_verified_email(emails: Any) -> str | None:
    """Return the primary address from ``/user/emails`` if GitHub verified it."""
    if not isinstance(emails, list):
        return None
    for entry in emails:
        if not isinstance(entry, dict):
            continue
        email = entry.get("email")
        if (
            entry.get("primary") is True
            and entry.get("verified") is True
            and isinstance(email, str)
            and email
        ):
            return email
    return None


def _split_name(name: Any, login: str) -> tuple[str, str | None]:
    """Split GitHub's single display name into given and family names.

    No display name: the login stands in for the given name.
    """
    if isinstance(name, str) and name.strip():
        parts = name.strip().split(None, 1)
        return parts[0], parts[1] if len(parts) > 1 else None
    return login, None


def _org_logins(orgs: list) -> list[str]:
    return [o["login"] for o in orgs if isinstance(o, dict) and isinstance(o.get("login"), str)]


def _team_names(teams: list) -> list[str]:
    names = []
    for team in teams:
        if not isinstance(team, dict):
            continue
        org = team.get("organization")
        org_login = org.get("login") if isinstance(org, dict) else None
        slug = team.get("slug")
        if isinstance(org_login, str) and isinstance(slug, str):
            names.append(f"{org_login}/{slug}")
    return names


def build_identity(
    access_token: str,
    *,
    allowed_orgs: list[str],
    sync_groups: bool,
) -> UpstreamIdentity:
    """Read the signed-in user from the GitHub API.

    Raises:
        GitHubAPIError: an API call failed or returned an unusable shape.
        ProviderLoginError: the user is in none of ``allowed_orgs``.
    """
    user = _api_get(access_token, "/user")
    if not isinstance(user, dict):
        raise GitHubAPIError("/user did not return an object")
    user_id = user.get("id")
    login = user.get("login")
    # bool is an int subclass; an id is never true/false.
    if isinstance(user_id, bool) or not isinstance(user_id, int) or not isinstance(login, str):
        raise ProviderLoginError("missing_sub", "GitHub /user has no id or login")
    subject = str(user_id)

    email = primary_verified_email(_api_get(access_token, "/user/emails"))
    given_name, family_name = _split_name(user.get("name"), login)

    claims: dict[str, Any] = {
        "sub": subject,
        "preferred_username": login,
        "given_name": given_name,
        "email_verified": email is not None,
    }
    if isinstance(user.get("name"), str) and user["name"].strip():
        claims["name"] = user["name"].strip()
    if family_name:
        claims["family_name"] = family_name
    if email:
        claims["email"] = email
    for claim, key in (("picture", "avatar_url"), ("profile", "html_url")):
        if isinstance(user.get(key), str):
            claims[claim] = user[key]

    if allowed_orgs or sync_groups:
        allowed = {org.lower() for org in allowed_orgs}
        orgs = _org_logins(_api_get_list(access_token, "/user/orgs"))
        if allowed:
            orgs = [org for org in orgs if org.lower() in allowed]
            if not orgs:
                raise ProviderLoginError(
                    "github_org_not_allowed",
                    f"GitHub user {login} is in none of the allowed organizations",
                    public_error="github_org_not_allowed",
                )
        if sync_groups:
            teams = _team_names(_api_get_list(access_token, "/user/teams"))
            if allowed:
                teams = [team for team in teams if team.split("/", 1)[0].lower() in allowed]
            claims[GROUPS_CLAIM] = orgs + teams

    return UpstreamIdentity(subject=subject, claims=claims)


class GitHubAdapter:
    """Sign-in with GitHub (OAuth2 web application flow with PKCE)."""

    def prepare(self, tenant_id: str, connection: dict) -> dict:
        # Fixed endpoints: nothing to discover.
        return connection

    def authorize_url(
        self,
        connection: dict,
        *,
        redirect_uri: str,
        state: str,
        nonce: str,
        code_challenge: str,
    ) -> str:
        client_id = connection.get("client_id")
        if not client_id:
            raise ProviderLoginError("configuration_error", public_error="configuration_error")
        preset = get_preset("github")
        scopes = connection.get("scopes") or (preset.scopes if preset else "")
        # GitHub has no nonce: there is no ID token to bind it to. PKCE and
        # state protect the code.
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scopes,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{AUTHORIZE_URL}?{urlencode(params)}"

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
        credentials = resolve_client_credentials(connection)
        if credentials is None:
            raise ProviderLoginError("configuration_error", public_error="configuration_error")

        try:
            token_response = exchange_code(
                token_endpoint=TOKEN_URL,
                client_id=credentials.client_id,
                client_secret=credentials.client_secret,
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
                auth_method=credentials.token_auth_method,
            )
        except TokenExchangeError as exc:
            raise ProviderLoginError("token_exchange", str(exc)) from exc

        access_token = token_response.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise ProviderLoginError("token_exchange", "GitHub returned no access token")

        try:
            return build_identity(
                access_token,
                allowed_orgs=list(connection.get("github_allowed_orgs") or []),
                sync_groups=(connection.get("group_claim_source") or "").strip() == GROUPS_CLAIM,
            )
        except GitHubAPIError as exc:
            raise ProviderLoginError("github_api", str(exc)) from exc

    def check(self, tenant_id: str, connection: dict, *, redirect_uri: str) -> dict:
        """Present the client credentials to GitHub with a made-up code.

        GitHub answers ``incorrect_client_credentials`` for a wrong client id
        or secret, ``redirect_uri_mismatch`` when the callback URL is not the
        app's, and ``bad_verification_code`` once both are right.
        """
        credentials = resolve_client_credentials(connection)
        if credentials is None:
            raise ProviderCheckError("Enter the GitHub app's client ID and client secret.")
        try:
            exchange_code(
                token_endpoint=TOKEN_URL,
                client_id=credentials.client_id,
                client_secret=credentials.client_secret,
                code=_CHECK_CODE,
                redirect_uri=redirect_uri,
                code_verifier=_CHECK_CODE,
                auth_method=credentials.token_auth_method,
            )
        except TokenExchangeError as exc:
            if exc.error == "bad_verification_code":
                return connection
            if exc.error == "incorrect_client_credentials":
                raise ProviderCheckError("GitHub rejected the client ID or client secret.") from exc
            if exc.error == "redirect_uri_mismatch":
                raise ProviderCheckError(
                    "The callback URL does not match the GitHub app's callback URL."
                ) from exc
            raise ProviderCheckError(f"GitHub check failed: {exc}") from exc
        # GitHub never accepts the made-up code.
        raise ProviderCheckError("GitHub accepted an invalid code; check the app settings.")
