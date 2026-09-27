"""Tests for end_session request resolution (services/oidc/logout.py).

Real database, real tenant signing keys: hints are minted by the ID-token
service and verified the way the endpoint does.
"""

import database
import jwt
import pytest
from services.oidc import logout as logout_service
from services.oidc import tokens as tokens_service

ISSUER = "https://tenant.example.com"
BYE = "https://rp.example/bye"


@pytest.fixture
def rp_client(test_tenant, test_admin_user):
    return database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Logout RP",
        redirect_uris=["https://rp.example/cb"],
        created_by=test_admin_user["id"],
        post_logout_redirect_uris=[BYE],
    )


def _hint(test_tenant, user, client, *, issuer=ISSUER, sid=None) -> str:
    return tokens_service.issue_id_token(
        tenant_id=str(test_tenant["id"]),
        issuer=issuer,
        client_uuid=str(client["id"]),
        client_id=client["client_id"],
        user_id=str(user["id"]),
        scopes={"openid"},
        sid=sid,
    )


def _resolve(test_tenant, **kw):
    params = {"id_token_hint": None, "client_id": None, "post_logout_redirect_uri": None}
    params.update(kw)
    return logout_service.resolve_end_session_request(
        tenant_id=str(test_tenant["id"]), issuer=ISSUER, **params
    )


class TestVerifiedHint:
    def test_hint_with_registered_uri_is_fully_verified(self, test_tenant, test_user, rp_client):
        resolved = _resolve(
            test_tenant,
            id_token_hint=_hint(test_tenant, test_user, rp_client),
            post_logout_redirect_uri=BYE,
        )
        assert resolved.problem is None
        assert resolved.hint_subject == str(test_user["id"])
        assert resolved.client["client_id"] == rp_client["client_id"]
        assert resolved.post_logout_redirect_uri == BYE

    def test_hint_alone_names_the_client_by_audience(self, test_tenant, test_user, rp_client):
        resolved = _resolve(test_tenant, id_token_hint=_hint(test_tenant, test_user, rp_client))
        assert resolved.problem is None
        assert resolved.client["client_id"] == rp_client["client_id"]
        assert resolved.post_logout_redirect_uri is None

    def test_matching_client_id_is_accepted(self, test_tenant, test_user, rp_client):
        resolved = _resolve(
            test_tenant,
            id_token_hint=_hint(test_tenant, test_user, rp_client),
            client_id=rp_client["client_id"],
            post_logout_redirect_uri=BYE,
        )
        assert resolved.problem is None and resolved.post_logout_redirect_uri == BYE

    def test_expired_hint_still_verifies(self, test_tenant, test_user, rp_client, mocker):
        from datetime import timedelta

        mocker.patch.object(tokens_service, "ID_TOKEN_EXPIRY", timedelta(hours=-1))
        resolved = _resolve(test_tenant, id_token_hint=_hint(test_tenant, test_user, rp_client))
        assert resolved.problem is None and resolved.hint_subject == str(test_user["id"])


class TestHintAudiencePeek:
    """The unverified audience peek only picks which client to verify against."""

    def _unsigned(self, claims: dict) -> str:
        return jwt.encode(claims, key=None, algorithm="none")

    def test_string_audience(self):
        assert logout_service._hint_audience(self._unsigned({"aud": "rp-1"})) == "rp-1"

    def test_one_element_list(self):
        assert logout_service._hint_audience(self._unsigned({"aud": ["rp-1"]})) == "rp-1"

    def test_ambiguous_or_missing_audience(self):
        for claims in ({"aud": ["rp-1", "rp-2"]}, {"aud": ""}, {"aud": 5}, {}):
            assert logout_service._hint_audience(self._unsigned(claims)) is None

    def test_not_a_jwt(self):
        assert logout_service._hint_audience("garbage") is None


class TestRejectedHint:
    def test_garbage_hint(self, test_tenant, rp_client):
        resolved = _resolve(test_tenant, id_token_hint="not-a-jwt", post_logout_redirect_uri=BYE)
        assert resolved.problem == logout_service.PROBLEM_INVALID_ID_TOKEN_HINT
        assert resolved.post_logout_redirect_uri is None
        assert resolved.client is None

    def test_alg_none_hint(self, test_tenant, test_user, rp_client):
        token = _hint(test_tenant, test_user, rp_client)
        claims = jwt.decode(token, options={"verify_signature": False})
        unsigned = jwt.encode(claims, key=None, algorithm="none")
        resolved = _resolve(test_tenant, id_token_hint=unsigned, post_logout_redirect_uri=BYE)
        assert resolved.problem == logout_service.PROBLEM_INVALID_ID_TOKEN_HINT

    def test_hint_signed_by_another_key(self, test_tenant, test_user, rp_client):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        real = jwt.get_unverified_header(_hint(test_tenant, test_user, rp_client))
        forged = jwt.encode(
            {"iss": ISSUER, "sub": str(test_user["id"]), "aud": rp_client["client_id"]},
            pem,
            algorithm="RS256",
            headers={"kid": real["kid"]},
        )
        resolved = _resolve(test_tenant, id_token_hint=forged, post_logout_redirect_uri=BYE)
        assert resolved.problem == logout_service.PROBLEM_INVALID_ID_TOKEN_HINT

    def test_hint_for_another_issuer(self, test_tenant, test_user, rp_client):
        token = _hint(test_tenant, test_user, rp_client, issuer="https://other.example.com")
        resolved = _resolve(test_tenant, id_token_hint=token)
        assert resolved.problem == logout_service.PROBLEM_INVALID_ID_TOKEN_HINT

    def test_client_id_disagreeing_with_hint(
        self, test_tenant, test_user, rp_client, normal_oauth2_client
    ):
        resolved = _resolve(
            test_tenant,
            id_token_hint=_hint(test_tenant, test_user, rp_client),
            client_id=normal_oauth2_client["client_id"],
        )
        assert resolved.problem == logout_service.PROBLEM_INVALID_ID_TOKEN_HINT

    def test_hint_for_deactivated_client(self, test_tenant, test_user, rp_client):
        token = _hint(test_tenant, test_user, rp_client)
        database.oauth2.deactivate_client(test_tenant["id"], rp_client["client_id"])
        resolved = _resolve(test_tenant, id_token_hint=token, post_logout_redirect_uri=BYE)
        assert resolved.problem == logout_service.PROBLEM_INVALID_ID_TOKEN_HINT

    def test_hint_for_unknown_audience(self, test_tenant, test_user, rp_client):
        token = tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer=ISSUER,
            client_uuid=str(rp_client["id"]),
            client_id="no-such-client",
            user_id=str(test_user["id"]),
            scopes={"openid"},
        )
        resolved = _resolve(test_tenant, id_token_hint=token)
        assert resolved.problem == logout_service.PROBLEM_INVALID_ID_TOKEN_HINT


class TestRedirectTarget:
    def test_unregistered_uri(self, test_tenant, test_user, rp_client):
        resolved = _resolve(
            test_tenant,
            id_token_hint=_hint(test_tenant, test_user, rp_client),
            post_logout_redirect_uri="https://evil.example/bye",
        )
        assert resolved.problem == logout_service.PROBLEM_UNREGISTERED_POST_LOGOUT_REDIRECT_URI
        assert resolved.post_logout_redirect_uri is None
        assert resolved.hint_subject == str(test_user["id"])

    def test_query_added_to_registered_uri_is_unregistered(self, test_tenant, test_user, rp_client):
        resolved = _resolve(
            test_tenant,
            id_token_hint=_hint(test_tenant, test_user, rp_client),
            post_logout_redirect_uri=BYE + "?foo=bar",
        )
        assert resolved.problem == logout_service.PROBLEM_UNREGISTERED_POST_LOGOUT_REDIRECT_URI

    def test_uri_without_hint_is_never_honoured(self, test_tenant, rp_client):
        """client_id + a registered URI is not enough: anyone can build that link."""
        resolved = _resolve(
            test_tenant, client_id=rp_client["client_id"], post_logout_redirect_uri=BYE
        )
        assert resolved.problem == logout_service.PROBLEM_ID_TOKEN_HINT_REQUIRED
        assert resolved.post_logout_redirect_uri is None
        assert resolved.client["client_id"] == rp_client["client_id"]

    def test_uri_alone(self, test_tenant, rp_client):
        resolved = _resolve(test_tenant, post_logout_redirect_uri=BYE)
        assert resolved.problem == logout_service.PROBLEM_ID_TOKEN_HINT_REQUIRED
        assert resolved.client is None


class TestNoHint:
    def test_no_parameters(self, test_tenant):
        resolved = _resolve(test_tenant)
        assert resolved == logout_service.EndSessionRequest()
        assert resolved.hint_subject is None

    def test_known_client_id_alone(self, test_tenant, rp_client):
        resolved = _resolve(test_tenant, client_id=rp_client["client_id"])
        assert resolved.problem is None
        assert resolved.hint_claims is None
        assert resolved.client["client_id"] == rp_client["client_id"]

    def test_unknown_client_id(self, test_tenant):
        resolved = _resolve(test_tenant, client_id="no-such-client")
        assert resolved.problem == logout_service.PROBLEM_UNKNOWN_CLIENT

    def test_b2b_client_id_is_unknown(self, test_tenant, b2b_oauth2_client):
        resolved = _resolve(test_tenant, client_id=b2b_oauth2_client["client_id"])
        assert resolved.problem == logout_service.PROBLEM_UNKNOWN_CLIENT


def test_other_tenant_client_is_unknown(test_tenant, test_user, rp_client):
    """Resolution is tenant-scoped: another tenant never sees this client."""
    import uuid

    other = database.fetchone(
        database.UNSCOPED,
        "insert into tenants (subdomain, name) values (:s, 'Other') returning id",
        {"s": f"other-{uuid.uuid4().hex[:8]}"},
    )
    try:
        resolved = logout_service.resolve_end_session_request(
            tenant_id=str(other["id"]),
            issuer=ISSUER,
            id_token_hint=_hint(test_tenant, test_user, rp_client),
            client_id=None,
            post_logout_redirect_uri=BYE,
        )
        assert resolved.problem == logout_service.PROBLEM_INVALID_ID_TOKEN_HINT
    finally:
        database.execute(
            database.UNSCOPED, "delete from tenants where id = :id", {"id": other["id"]}
        )
