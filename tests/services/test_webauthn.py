"""Tests for services.webauthn (passkey registration / management)."""

from dataclasses import dataclass
from types import SimpleNamespace

import database
import pytest
from schemas.webauthn import CompleteAuthenticationRequest, CompleteRegistrationRequest
from services import webauthn as webauthn_service
from services.exceptions import NotFoundError, ValidationError
from services.types import RequestingUser


@dataclass
class _FakeVerified:
    credential_id: bytes = b"cred-bytes-abcdef"
    credential_public_key: bytes = b"pk-bytes"
    sign_count: int = 0
    aaguid: str = "aaguid-string"
    credential_backed_up: bool = False
    credential_device_type: str = "single_device"


def _requesting(user: dict) -> RequestingUser:
    return {
        "id": str(user["id"]),
        "tenant_id": str(user["tenant_id"]),
        "role": user.get("role", "member"),
    }


def _fake_request(session: dict | None = None) -> SimpleNamespace:
    """Return a fake FastAPI Request with a mutable session dict."""
    session = session if session is not None else {}
    headers = {"host": "t.example.com"}
    req = SimpleNamespace(
        session=session,
        headers=headers,
        url=SimpleNamespace(scheme="https"),
    )
    return req


def test_begin_registration_stashes_challenge(test_user, mocker):
    """begin_registration stores a hex challenge + timestamp in session."""
    # Patch utils wrappers so we don't actually call the webauthn library.
    mocker.patch(
        "services.webauthn.generate_registration_options_for_user",
        return_value=({"rp": {"id": "host"}, "challenge": "abc"}, b"\x01\x02\x03"),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")
    mocker.patch("services.webauthn.rp_name_for_tenant", return_value="Tenant")

    req = _fake_request()
    result = webauthn_service.begin_registration(_requesting(test_user), req)

    assert result.public_key == {"rp": {"id": "host"}, "challenge": "abc"}
    assert req.session["webauthn_reg_challenge"] == b"\x01\x02\x03".hex()
    assert isinstance(req.session["webauthn_reg_challenge_at"], int)


def test_complete_registration_missing_challenge(test_user):
    req = _fake_request({})
    with pytest.raises(ValidationError) as exc:
        webauthn_service.complete_registration(
            _requesting(test_user),
            req,
            CompleteRegistrationRequest(name="Key", response={"response": {}}),
        )
    assert exc.value.code == "no_registration_in_progress"


def test_complete_registration_expired_challenge(test_user):
    req = _fake_request(
        {
            "webauthn_reg_challenge": b"\x00\x01".hex(),
            "webauthn_reg_challenge_at": 1,  # unix epoch start
        }
    )
    with pytest.raises(ValidationError) as exc:
        webauthn_service.complete_registration(
            _requesting(test_user),
            req,
            CompleteRegistrationRequest(name="Key", response={"response": {}}),
        )
    assert exc.value.code == "registration_session_expired"
    # Session was consumed even on expiry
    assert "webauthn_reg_challenge" not in req.session


def test_complete_registration_happy_path_issues_backup_codes(test_user, mocker):
    """First registration: backup codes are issued once; event emitted."""
    # Mock verify_registration to return a fake verified result
    mocker.patch(
        "services.webauthn.verify_registration",
        return_value=_FakeVerified(),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")
    mocker.patch("services.webauthn.origin_for_request", return_value="https://host")
    log_event = mocker.patch("services.webauthn.log_event")

    import time as _time

    req = _fake_request(
        {
            "webauthn_reg_challenge": b"chal".hex(),
            "webauthn_reg_challenge_at": int(_time.time()),
        }
    )

    payload = CompleteRegistrationRequest(
        name="Laptop",
        response={
            "id": "abc",
            "rawId": "abc",
            "type": "public-key",
            "response": {
                "clientDataJSON": "x",
                "attestationObject": "y",
                "transports": ["internal"],
            },
        },
    )

    result = webauthn_service.complete_registration(_requesting(test_user), req, payload)

    assert result.credential.name == "Laptop"
    assert result.backup_codes is not None
    assert len(result.backup_codes) > 0

    # Event was emitted
    assert log_event.called
    kwargs = log_event.call_args.kwargs
    assert kwargs["event_type"] == "passkey_registered"
    assert kwargs["artifact_type"] == "webauthn_credential"
    assert kwargs["metadata"]["credential_name"] == "Laptop"


def test_complete_registration_second_does_not_reissue_backup_codes(test_user, mocker):
    """Second registration must not return new backup codes."""
    # Pre-seed a passkey and backup codes
    database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=b"existing-cred",
        public_key=b"pk",
        name="First",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )
    database.mfa.create_backup_code(
        test_user["tenant_id"], test_user["id"], "hashvalue", str(test_user["tenant_id"])
    )

    mocker.patch(
        "services.webauthn.verify_registration",
        return_value=_FakeVerified(credential_id=b"new-cred-bytes"),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")
    mocker.patch("services.webauthn.origin_for_request", return_value="https://host")
    mocker.patch("services.webauthn.log_event")

    import time as _time

    req = _fake_request(
        {
            "webauthn_reg_challenge": b"chal".hex(),
            "webauthn_reg_challenge_at": int(_time.time()),
        }
    )

    payload = CompleteRegistrationRequest(
        name="Second",
        response={"id": "x", "rawId": "x", "type": "public-key", "response": {}},
    )
    result = webauthn_service.complete_registration(_requesting(test_user), req, payload)

    assert result.credential.name == "Second"
    assert result.backup_codes is None


def test_complete_registration_verification_failure(test_user, mocker):
    from utils.webauthn import WebAuthnError

    mocker.patch(
        "services.webauthn.verify_registration",
        side_effect=WebAuthnError("bad signature"),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")
    mocker.patch("services.webauthn.origin_for_request", return_value="https://host")

    import time as _time

    req = _fake_request(
        {
            "webauthn_reg_challenge": b"chal".hex(),
            "webauthn_reg_challenge_at": int(_time.time()),
        }
    )

    with pytest.raises(ValidationError) as exc:
        webauthn_service.complete_registration(
            _requesting(test_user),
            req,
            CompleteRegistrationRequest(name="X", response={"response": {}}),
        )
    assert exc.value.code == "registration_verification_failed"


def test_list_credentials_tracks_activity(test_user, mocker):
    track = mocker.patch("services.webauthn.track_activity")
    webauthn_service.list_credentials(_requesting(test_user))
    track.assert_called_once_with(str(test_user["tenant_id"]), str(test_user["id"]))


def test_rename_credential_not_found(test_user):
    with pytest.raises(NotFoundError):
        webauthn_service.rename_credential(
            _requesting(test_user),
            "00000000-0000-0000-0000-000000000000",
            "NewName",
        )


def test_rename_credential_other_user_not_found(test_user, test_admin_user):
    row = database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=b"user-cred",
        public_key=b"pk",
        name="User key",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )

    with pytest.raises(NotFoundError):
        webauthn_service.rename_credential(
            _requesting(test_admin_user),
            str(row["id"]),
            "Hacked",
        )


def test_rename_credential_emits_event(test_user, mocker):
    row = database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=b"rename-cred",
        public_key=b"pk",
        name="Original",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )
    log_event = mocker.patch("services.webauthn.log_event")

    result = webauthn_service.rename_credential(
        _requesting(test_user),
        str(row["id"]),
        "Updated",
    )

    assert result.name == "Updated"
    assert log_event.called
    kwargs = log_event.call_args.kwargs
    assert kwargs["event_type"] == "passkey_renamed"
    assert kwargs["metadata"] == {"old_name": "Original", "new_name": "Updated"}


def test_delete_credential_not_found(test_user):
    with pytest.raises(NotFoundError):
        webauthn_service.delete_credential(
            _requesting(test_user),
            "00000000-0000-0000-0000-000000000000",
        )


def test_delete_credential_other_user_not_found(test_user, test_admin_user):
    row = database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=b"delete-cred",
        public_key=b"pk",
        name="User key",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )
    with pytest.raises(NotFoundError):
        webauthn_service.delete_credential(
            _requesting(test_admin_user),
            str(row["id"]),
        )


def test_delete_credential_emits_event(test_user, mocker):
    row = database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=b"delete-cred-2",
        public_key=b"pk",
        name="ToDelete",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=True,
        backup_state=True,
    )
    log_event = mocker.patch("services.webauthn.log_event")

    webauthn_service.delete_credential(_requesting(test_user), str(row["id"]))

    assert log_event.called
    kwargs = log_event.call_args.kwargs
    assert kwargs["event_type"] == "passkey_deleted"
    assert kwargs["metadata"]["credential_name"] == "ToDelete"
    assert kwargs["metadata"]["backup_eligible"] is True

    # Gone from the database
    assert (
        database.webauthn_credentials.get_credential(test_user["tenant_id"], str(row["id"])) is None
    )


def test_complete_registration_preexisting_backup_codes_not_reissued(test_user, mocker):
    """A user with existing backup codes (e.g., from a prior TOTP flow) and
    zero passkeys must NOT get a fresh set issued on first passkey registration.
    """
    # User has zero passkeys but already has backup codes (shared with TOTP).
    database.mfa.create_backup_code(
        test_user["tenant_id"], test_user["id"], "hashvalue", str(test_user["tenant_id"])
    )

    mocker.patch(
        "services.webauthn.verify_registration",
        return_value=_FakeVerified(credential_id=b"first-passkey"),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")
    mocker.patch("services.webauthn.origin_for_request", return_value="https://host")
    mocker.patch("services.webauthn.log_event")
    # Spy to prove generator is NOT called
    gen_spy = mocker.patch("services.webauthn.mfa_service.generate_initial_backup_codes")

    import time as _time

    req = _fake_request(
        {
            "webauthn_reg_challenge": b"chal".hex(),
            "webauthn_reg_challenge_at": int(_time.time()),
        }
    )

    payload = CompleteRegistrationRequest(
        name="First passkey",
        response={"id": "x", "rawId": "x", "type": "public-key", "response": {}},
    )
    result = webauthn_service.complete_registration(_requesting(test_user), req, payload)

    assert result.backup_codes is None
    gen_spy.assert_not_called()


def test_complete_registration_malformed_transports_does_not_crash(test_user, mocker):
    """If the browser sends a non-list or list of non-strings under transports,
    the service must not crash and must normalise to None or a clean str list.
    """
    mocker.patch(
        "services.webauthn.verify_registration",
        return_value=_FakeVerified(credential_id=b"malformed-cred"),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")
    mocker.patch("services.webauthn.origin_for_request", return_value="https://host")
    mocker.patch("services.webauthn.log_event")

    import time as _time

    # Case 1: transports is a string, not a list -> must become None
    req = _fake_request(
        {
            "webauthn_reg_challenge": b"chal1".hex(),
            "webauthn_reg_challenge_at": int(_time.time()),
        }
    )
    payload = CompleteRegistrationRequest(
        name="Weird-1",
        response={
            "id": "x",
            "rawId": "x",
            "type": "public-key",
            "response": {"transports": "usb"},
        },
    )
    result = webauthn_service.complete_registration(_requesting(test_user), req, payload)
    assert result.credential.transports is None

    # Case 2: mixed-type list -> non-strings dropped, strings survive
    mocker.patch(
        "services.webauthn.verify_registration",
        return_value=_FakeVerified(credential_id=b"malformed-cred-2"),
    )
    req2 = _fake_request(
        {
            "webauthn_reg_challenge": b"chal2".hex(),
            "webauthn_reg_challenge_at": int(_time.time()),
        }
    )
    payload2 = CompleteRegistrationRequest(
        name="Weird-2",
        response={
            "id": "y",
            "rawId": "y",
            "type": "public-key",
            "response": {"transports": [123, "internal", None, "usb"]},
        },
    )
    result2 = webauthn_service.complete_registration(_requesting(test_user), req2, payload2)
    assert result2.credential.transports == ["internal", "usb"]

    # Case 3: empty list -> None
    mocker.patch(
        "services.webauthn.verify_registration",
        return_value=_FakeVerified(credential_id=b"malformed-cred-3"),
    )
    req3 = _fake_request(
        {
            "webauthn_reg_challenge": b"chal3".hex(),
            "webauthn_reg_challenge_at": int(_time.time()),
        }
    )
    payload3 = CompleteRegistrationRequest(
        name="Weird-3",
        response={
            "id": "z",
            "rawId": "z",
            "type": "public-key",
            "response": {"transports": []},
        },
    )
    result3 = webauthn_service.complete_registration(_requesting(test_user), req3, payload3)
    assert result3.credential.transports is None


def test_rename_credential_other_tenant_not_found(test_user, mocker):
    """A user in tenant B cannot rename a credential registered in tenant A.

    Even if they pass the exact credential UUID, the tenant-scoped lookup
    returns None and NotFoundError fires (no existence leak).
    """
    row = database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=b"tenant-iso-cred",
        public_key=b"pk",
        name="A-tenant key",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )

    # Fabricate a requesting user with a different tenant_id, same-shape user_id.
    other_tenant_requesting: RequestingUser = {
        "id": str(test_user["id"]),
        "tenant_id": "00000000-0000-0000-0000-000000000099",
        "role": "member",
    }
    with pytest.raises(NotFoundError):
        webauthn_service.rename_credential(other_tenant_requesting, str(row["id"]), "Hacked")
    with pytest.raises(NotFoundError):
        webauthn_service.delete_credential(other_tenant_requesting, str(row["id"]))


def test_list_credentials_ordering(test_user):
    """List returns newest first and exposes schema fields properly."""
    database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=b"order-1",
        public_key=b"pk",
        name="First",
        sign_count=0,
        aaguid=None,
        transports=["internal"],
        backup_eligible=True,
        backup_state=False,
    )
    database.webauthn_credentials.create_credential(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        credential_id=b"order-2",
        public_key=b"pk",
        name="Second",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
    )

    passkeys = webauthn_service.list_credentials(_requesting(test_user))
    assert passkeys[0].name == "Second"
    assert passkeys[1].name == "First"
    assert passkeys[1].transports == ["internal"]
    assert passkeys[1].backup_eligible is True


# =============================================================================
# Passkey login (iteration 3)
# =============================================================================


def _seed_passkey(
    test_user_dict,
    *,
    credential_id: bytes,
    sign_count: int = 0,
    backup_eligible: bool = False,
    backup_state: bool = False,
    name: str = "Key",
) -> dict:
    return database.webauthn_credentials.create_credential(
        tenant_id=test_user_dict["tenant_id"],
        tenant_id_value=str(test_user_dict["tenant_id"]),
        user_id=test_user_dict["id"],
        credential_id=credential_id,
        public_key=b"pk-login",
        name=name,
        sign_count=sign_count,
        aaguid=None,
        transports=None,
        backup_eligible=backup_eligible,
        backup_state=backup_state,
    )


def test_begin_authentication_eligible_user(test_user, mocker):
    _seed_passkey(test_user, credential_id=b"login-cred-1")

    mocker.patch(
        "services.webauthn.generate_authentication_options_for_user",
        return_value=(
            {"rpId": "host", "allowCredentials": [{"id": "abc"}]},
            b"\xaa\xbb\xcc",
        ),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")

    req = _fake_request()
    result = webauthn_service.begin_authentication(
        req, str(test_user["tenant_id"]), test_user["email"]
    )

    assert result is not None
    assert result.public_key["rpId"] == "host"
    assert req.session["pending_passkey_user_id"] == str(test_user["id"])
    assert req.session["webauthn_login_challenge"] == b"\xaa\xbb\xcc".hex()
    assert isinstance(req.session["webauthn_login_challenge_at"], int)


def test_begin_authentication_nonexistent_email_returns_none(test_user):
    req = _fake_request()
    result = webauthn_service.begin_authentication(
        req, str(test_user["tenant_id"]), "nobody-here@example.com"
    )
    assert result is None
    assert "pending_passkey_user_id" not in req.session


def test_begin_authentication_idp_user_returns_none(test_user, mocker):
    _seed_passkey(test_user, credential_id=b"login-cred-idp")
    # Simulate an IdP-linked user
    mocker.patch(
        "services.webauthn.database.users.get_user_auth_info",
        return_value={
            "id": test_user["id"],
            "email": test_user["email"],
            "has_password": True,
            "saml_idp_id": "11111111-1111-1111-1111-111111111111",
            "is_inactivated": False,
        },
    )
    req = _fake_request()
    result = webauthn_service.begin_authentication(
        req, str(test_user["tenant_id"]), test_user["email"]
    )
    assert result is None


def test_begin_authentication_inactivated_user_returns_none(test_user, mocker):
    _seed_passkey(test_user, credential_id=b"login-cred-inactive")
    mocker.patch(
        "services.webauthn.database.users.get_user_auth_info",
        return_value={
            "id": test_user["id"],
            "email": test_user["email"],
            "has_password": True,
            "saml_idp_id": None,
            "is_inactivated": True,
        },
    )
    req = _fake_request()
    result = webauthn_service.begin_authentication(
        req, str(test_user["tenant_id"]), test_user["email"]
    )
    assert result is None


def test_begin_authentication_zero_passkeys_returns_none(test_user):
    # No passkeys seeded
    req = _fake_request()
    result = webauthn_service.begin_authentication(
        req, str(test_user["tenant_id"]), test_user["email"]
    )
    assert result is None


class _FakeVerifiedAuth:
    def __init__(self, new_sign_count=1, credential_backed_up=False):
        self.new_sign_count = new_sign_count
        self.credential_backed_up = credential_backed_up
        self.credential_id = b"returned-id"
        self.user_verified = True


def _seed_login_session(cred_raw_id_bytes: bytes, user_id: str) -> dict:
    import base64
    import time as _time

    raw_b64 = base64.urlsafe_b64encode(cred_raw_id_bytes).rstrip(b"=").decode()
    session = {
        "pending_passkey_user_id": user_id,
        "webauthn_login_challenge": b"chal".hex(),
        "webauthn_login_challenge_at": int(_time.time()),
    }
    return {"session": session, "raw_b64": raw_b64}


def test_complete_authentication_happy_path(test_user, mocker):
    row = _seed_passkey(
        test_user,
        credential_id=b"happy-cred",
        sign_count=3,
        backup_eligible=True,
        backup_state=False,
    )
    state = _seed_login_session(b"happy-cred", str(test_user["id"]))

    mocker.patch(
        "services.webauthn.verify_authentication",
        return_value=_FakeVerifiedAuth(new_sign_count=42, credential_backed_up=True),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")
    mocker.patch("services.webauthn.origin_for_request", return_value="https://host")
    log_event = mocker.patch("services.webauthn.log_event")

    # Mock the shared login completion helper to return a canonical redirect
    from fastapi.responses import RedirectResponse

    fake_redirect = RedirectResponse(url="/dashboard", status_code=303)
    mocker.patch(
        "routers.auth._login_completion.complete_authenticated_login",
        return_value=fake_redirect,
    )

    req = _fake_request(state["session"])
    payload = CompleteAuthenticationRequest(
        response={
            "id": state["raw_b64"],
            "rawId": state["raw_b64"],
            "type": "public-key",
            "response": {
                "clientDataJSON": "x",
                "authenticatorData": "y",
                "signature": "z",
                "userHandle": None,
            },
        }
    )

    url = webauthn_service.complete_authentication(req, str(test_user["tenant_id"]), payload)

    assert url == "/dashboard"

    # DB state updated
    fresh = database.webauthn_credentials.get_credential(test_user["tenant_id"], str(row["id"]))
    assert fresh is not None
    assert fresh["sign_count"] == 42
    assert fresh["backup_state"] is True
    assert fresh["last_used_at"] is not None

    # Success event emitted
    success_calls = [
        c for c in log_event.call_args_list if c.kwargs.get("event_type") == "passkey_auth_success"
    ]
    assert len(success_calls) == 1
    meta = success_calls[0].kwargs["metadata"]
    assert meta["credential_id"] == str(row["id"])
    assert meta["credential_name"] == "Key"

    # Session keys cleared
    assert "pending_passkey_user_id" not in req.session
    assert "webauthn_login_challenge" not in req.session


def test_complete_authentication_no_session(test_user, mocker):
    log_event = mocker.patch("services.webauthn.log_event")
    req = _fake_request({})
    payload = CompleteAuthenticationRequest(response={"id": "x", "rawId": "x"})

    with pytest.raises(ValidationError) as excinfo:
        webauthn_service.complete_authentication(req, str(test_user["tenant_id"]), payload)
    assert excinfo.value.code == "no_challenge"

    # A failure event was emitted
    assert any(
        c.kwargs.get("event_type") == "passkey_auth_failure"
        and c.kwargs["metadata"]["reason"] == "no_challenge"
        for c in log_event.call_args_list
    )


def test_complete_authentication_expired_challenge(test_user, mocker):
    _seed_passkey(test_user, credential_id=b"exp-cred")
    session = {
        "pending_passkey_user_id": str(test_user["id"]),
        "webauthn_login_challenge": b"old".hex(),
        "webauthn_login_challenge_at": 1,  # epoch start
    }
    log_event = mocker.patch("services.webauthn.log_event")

    req = _fake_request(session)
    import base64 as _b64

    raw = _b64.urlsafe_b64encode(b"exp-cred").rstrip(b"=").decode()
    payload = CompleteAuthenticationRequest(response={"id": raw, "rawId": raw})

    with pytest.raises(ValidationError) as excinfo:
        webauthn_service.complete_authentication(req, str(test_user["tenant_id"]), payload)
    assert excinfo.value.code == "expired_challenge"

    # Session cleared
    assert "pending_passkey_user_id" not in req.session
    # Failure event recorded with reason
    assert any(
        c.kwargs.get("event_type") == "passkey_auth_failure"
        and c.kwargs["metadata"]["reason"] == "expired_challenge"
        for c in log_event.call_args_list
    )


def test_complete_authentication_unknown_credential(test_user, mocker):
    _seed_passkey(test_user, credential_id=b"stored-cred")
    state = _seed_login_session(b"stored-cred", str(test_user["id"]))
    log_event = mocker.patch("services.webauthn.log_event")

    import base64 as _b64

    # Return a different id than any stored credential
    other_id = _b64.urlsafe_b64encode(b"other-bytes").rstrip(b"=").decode()

    req = _fake_request(state["session"])
    payload = CompleteAuthenticationRequest(response={"id": other_id, "rawId": other_id})

    with pytest.raises(ValidationError) as excinfo:
        webauthn_service.complete_authentication(req, str(test_user["tenant_id"]), payload)
    assert excinfo.value.code == "unknown_credential"
    assert any(
        c.kwargs.get("event_type") == "passkey_auth_failure"
        and c.kwargs["metadata"]["reason"] == "unknown_credential"
        for c in log_event.call_args_list
    )


def test_complete_authentication_bad_signature(test_user, mocker):
    row = _seed_passkey(
        test_user,
        credential_id=b"badsig-cred",
        sign_count=5,
        backup_eligible=False,
    )
    state = _seed_login_session(b"badsig-cred", str(test_user["id"]))
    log_event = mocker.patch("services.webauthn.log_event")
    from utils.webauthn import WebAuthnError

    mocker.patch(
        "services.webauthn.verify_authentication",
        side_effect=WebAuthnError("invalid signature"),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")
    mocker.patch("services.webauthn.origin_for_request", return_value="https://host")

    req = _fake_request(state["session"])
    payload = CompleteAuthenticationRequest(
        response={"id": state["raw_b64"], "rawId": state["raw_b64"]}
    )

    with pytest.raises(ValidationError) as excinfo:
        webauthn_service.complete_authentication(req, str(test_user["tenant_id"]), payload)
    assert excinfo.value.code == "bad_signature"

    # Credential must NOT be deleted on bad_signature
    fresh = database.webauthn_credentials.get_credential(test_user["tenant_id"], str(row["id"]))
    assert fresh is not None
    # Failure event emitted with reason
    assert any(
        c.kwargs.get("event_type") == "passkey_auth_failure"
        and c.kwargs["metadata"]["reason"] == "bad_signature"
        for c in log_event.call_args_list
    )


def test_complete_authentication_clone_suspected_be_false(test_user, mocker):
    row = _seed_passkey(
        test_user,
        credential_id=b"clone-cred",
        sign_count=10,
        backup_eligible=False,
    )
    state = _seed_login_session(b"clone-cred", str(test_user["id"]))
    log_event = mocker.patch("services.webauthn.log_event")
    from utils.webauthn import SignCountRegressionError

    mocker.patch(
        "services.webauthn.verify_authentication",
        side_effect=SignCountRegressionError("Counter has not increased"),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")
    mocker.patch("services.webauthn.origin_for_request", return_value="https://host")

    req = _fake_request(state["session"])
    payload = CompleteAuthenticationRequest(
        response={"id": state["raw_b64"], "rawId": state["raw_b64"]}
    )

    with pytest.raises(ValidationError) as excinfo:
        webauthn_service.complete_authentication(req, str(test_user["tenant_id"]), payload)
    assert excinfo.value.code == "clone_suspected"

    # Credential deleted
    fresh = database.webauthn_credentials.get_credential(test_user["tenant_id"], str(row["id"]))
    assert fresh is None

    # Both passkey_deleted and passkey_auth_failure events emitted
    event_types = [c.kwargs.get("event_type") for c in log_event.call_args_list]
    assert "passkey_deleted" in event_types
    assert "passkey_auth_failure" in event_types
    # Deletion carries clone_suspected reason
    deleted_call = next(
        c for c in log_event.call_args_list if c.kwargs.get("event_type") == "passkey_deleted"
    )
    assert deleted_call.kwargs["metadata"]["reason"] == "clone_suspected"
    # Failure event has clone_suspected reason and credential_uuid
    failure_call = next(
        c for c in log_event.call_args_list if c.kwargs.get("event_type") == "passkey_auth_failure"
    )
    assert failure_call.kwargs["metadata"]["reason"] == "clone_suspected"
    assert failure_call.kwargs["artifact_type"] == "webauthn_credential"
    assert failure_call.kwargs["artifact_id"] == str(row["id"])


def test_complete_authentication_sign_count_regression_be_true_allowed(test_user, mocker):
    """Synced platform authenticators (BE=true) may reset sign_count; we must allow it."""
    row = _seed_passkey(
        test_user,
        credential_id=b"synced-cred",
        sign_count=5,
        backup_eligible=True,
        backup_state=True,
    )
    state = _seed_login_session(b"synced-cred", str(test_user["id"]))

    # Library returns success with new_sign_count=0 (reset)
    mocker.patch(
        "services.webauthn.verify_authentication",
        return_value=_FakeVerifiedAuth(new_sign_count=0, credential_backed_up=True),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")
    mocker.patch("services.webauthn.origin_for_request", return_value="https://host")
    mocker.patch("services.webauthn.log_event")

    from fastapi.responses import RedirectResponse

    mocker.patch(
        "routers.auth._login_completion.complete_authenticated_login",
        return_value=RedirectResponse(url="/dashboard", status_code=303),
    )

    req = _fake_request(state["session"])
    payload = CompleteAuthenticationRequest(
        response={"id": state["raw_b64"], "rawId": state["raw_b64"]}
    )
    url = webauthn_service.complete_authentication(req, str(test_user["tenant_id"]), payload)
    assert url == "/dashboard"

    fresh = database.webauthn_credentials.get_credential(test_user["tenant_id"], str(row["id"]))
    assert fresh is not None
    assert fresh["sign_count"] == 0


def test_complete_authentication_backup_state_refreshed(test_user, mocker):
    """backup_state is written from the verified assertion (not static)."""
    row = _seed_passkey(
        test_user,
        credential_id=b"bs-cred",
        sign_count=1,
        backup_eligible=True,
        backup_state=False,
    )
    state = _seed_login_session(b"bs-cred", str(test_user["id"]))

    mocker.patch(
        "services.webauthn.verify_authentication",
        return_value=_FakeVerifiedAuth(new_sign_count=2, credential_backed_up=True),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")
    mocker.patch("services.webauthn.origin_for_request", return_value="https://host")
    mocker.patch("services.webauthn.log_event")

    from fastapi.responses import RedirectResponse

    mocker.patch(
        "routers.auth._login_completion.complete_authenticated_login",
        return_value=RedirectResponse(url="/dashboard", status_code=303),
    )

    req = _fake_request(state["session"])
    payload = CompleteAuthenticationRequest(
        response={"id": state["raw_b64"], "rawId": state["raw_b64"]}
    )
    webauthn_service.complete_authentication(req, str(test_user["tenant_id"]), payload)

    fresh = database.webauthn_credentials.get_credential(test_user["tenant_id"], str(row["id"]))
    assert fresh["backup_state"] is True


def test_user_has_passkey_for_email_true(test_user):
    _seed_passkey(test_user, credential_id=b"flag-cred")
    assert webauthn_service.user_has_passkey_for_email(
        str(test_user["tenant_id"]), test_user["email"]
    )


def test_user_has_passkey_for_email_false_without_passkey(test_user):
    assert not webauthn_service.user_has_passkey_for_email(
        str(test_user["tenant_id"]), test_user["email"]
    )


def test_user_has_passkey_for_email_false_unknown_email(test_user):
    assert not webauthn_service.user_has_passkey_for_email(
        str(test_user["tenant_id"]), "nobody@example.com"
    )


def test_complete_authentication_corrupt_challenge_clears_session(test_user, mocker):
    """A non-hex challenge string clears ceremony state and emits a failure event."""
    _seed_passkey(test_user, credential_id=b"corrupt-cred")
    session = {
        "pending_passkey_user_id": str(test_user["id"]),
        "webauthn_login_challenge": "not-valid-hex-ZZZ",
        "webauthn_login_challenge_at": int(__import__("time").time()),
    }
    log_event = mocker.patch("services.webauthn.log_event")

    req = _fake_request(session)
    import base64 as _b64

    raw = _b64.urlsafe_b64encode(b"corrupt-cred").rstrip(b"=").decode()
    payload = CompleteAuthenticationRequest(response={"id": raw, "rawId": raw})

    with pytest.raises(ValidationError) as excinfo:
        webauthn_service.complete_authentication(req, str(test_user["tenant_id"]), payload)
    assert excinfo.value.code == "corrupt_challenge"

    # Session must be fully cleared on every error exit
    assert "pending_passkey_user_id" not in req.session
    assert "webauthn_login_challenge" not in req.session
    assert "webauthn_login_challenge_at" not in req.session

    assert any(
        c.kwargs.get("event_type") == "passkey_auth_failure"
        and c.kwargs["metadata"]["reason"] == "corrupt_challenge"
        for c in log_event.call_args_list
    )


def test_complete_authentication_clone_detection_clears_session(test_user, mocker):
    """Clone-detected path must also clear the ceremony session keys."""
    _seed_passkey(
        test_user,
        credential_id=b"clone-session-cred",
        sign_count=10,
        backup_eligible=False,
    )
    state = _seed_login_session(b"clone-session-cred", str(test_user["id"]))
    mocker.patch("services.webauthn.log_event")
    from utils.webauthn import SignCountRegressionError

    mocker.patch(
        "services.webauthn.verify_authentication",
        side_effect=SignCountRegressionError("Response sign count of 5 was not greater than current count"),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")
    mocker.patch("services.webauthn.origin_for_request", return_value="https://host")

    req = _fake_request(state["session"])
    payload = CompleteAuthenticationRequest(
        response={"id": state["raw_b64"], "rawId": state["raw_b64"]}
    )

    with pytest.raises(ValidationError) as excinfo:
        webauthn_service.complete_authentication(req, str(test_user["tenant_id"]), payload)
    assert excinfo.value.code == "clone_suspected"

    # All three ceremony keys cleared
    assert "pending_passkey_user_id" not in req.session
    assert "webauthn_login_challenge" not in req.session
    assert "webauthn_login_challenge_at" not in req.session


def test_complete_authentication_clone_detection_via_typed_exception(test_user, mocker):
    """complete_authentication must detect clones via SignCountRegressionError, not by
    inspecting the error message string.

    The service layer catches SignCountRegressionError first (before the generic
    WebAuthnError handler). This test patches verify_authentication to raise the
    typed exception directly, verifying the service routes it to clone_suspected
    regardless of the message text.
    """
    from utils.webauthn import SignCountRegressionError

    row = _seed_passkey(
        test_user,
        credential_id=b"typed-clone-cred",
        sign_count=10,
        backup_eligible=False,
    )
    state = _seed_login_session(b"typed-clone-cred", str(test_user["id"]))
    log_event = mocker.patch("services.webauthn.log_event")

    mocker.patch(
        "services.webauthn.verify_authentication",
        side_effect=SignCountRegressionError("sign count regression"),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")
    mocker.patch("services.webauthn.origin_for_request", return_value="https://host")

    req = _fake_request(state["session"])
    payload = CompleteAuthenticationRequest(
        response={"id": state["raw_b64"], "rawId": state["raw_b64"]}
    )

    with pytest.raises(ValidationError) as excinfo:
        webauthn_service.complete_authentication(req, str(test_user["tenant_id"]), payload)
    assert excinfo.value.code == "clone_suspected"

    # Credential must be deleted.
    gone = database.webauthn_credentials.get_credential(test_user["tenant_id"], str(row["id"]))
    assert gone is None

    # Both deletion and failure events emitted with clone_suspected reason.
    event_types = [c.kwargs.get("event_type") for c in log_event.call_args_list]
    assert "passkey_deleted" in event_types
    assert "passkey_auth_failure" in event_types
    deleted_call = next(
        c for c in log_event.call_args_list if c.kwargs.get("event_type") == "passkey_deleted"
    )
    assert deleted_call.kwargs["metadata"]["reason"] == "clone_suspected"


# =============================================================================
# Eligibility recheck (TOCTOU guard in complete_authentication)
# =============================================================================


def test_complete_authentication_rejects_inactivated_user(test_user, mocker):
    """User inactivated between begin and complete is rejected."""
    _seed_passkey(test_user, credential_id=b"toctou-inactive", sign_count=0, backup_eligible=True)
    state = _seed_login_session(b"toctou-inactive", str(test_user["id"]))

    mocker.patch(
        "services.webauthn.verify_authentication",
        return_value=_FakeVerifiedAuth(new_sign_count=1),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")
    mocker.patch("services.webauthn.origin_for_request", return_value="https://host")
    log_event = mocker.patch("services.webauthn.log_event")

    mocker.patch(
        "services.webauthn.database.users.get_user_by_id",
        return_value={
            "id": test_user["id"],
            "is_inactivated": True,
            "saml_idp_id": None,
        },
    )

    req = _fake_request(state["session"])
    payload = CompleteAuthenticationRequest(
        response={
            "id": state["raw_b64"],
            "rawId": state["raw_b64"],
            "type": "public-key",
            "response": {
                "clientDataJSON": "x",
                "authenticatorData": "y",
                "signature": "z",
                "userHandle": None,
            },
        }
    )

    with pytest.raises(ValidationError) as excinfo:
        webauthn_service.complete_authentication(req, str(test_user["tenant_id"]), payload)
    assert excinfo.value.code == "eligibility_revoked"

    assert "pending_passkey_user_id" not in req.session

    assert any(
        c.kwargs.get("event_type") == "passkey_auth_failure"
        and c.kwargs["metadata"]["reason"] == "eligibility_revoked"
        for c in log_event.call_args_list
    )

    assert not any(
        c.kwargs.get("event_type") == "passkey_auth_success" for c in log_event.call_args_list
    )


def test_complete_authentication_rejects_idp_linked_user(test_user, mocker):
    """User linked to SAML IdP between begin and complete is rejected."""
    _seed_passkey(test_user, credential_id=b"toctou-idp", sign_count=0, backup_eligible=True)
    state = _seed_login_session(b"toctou-idp", str(test_user["id"]))

    mocker.patch(
        "services.webauthn.verify_authentication",
        return_value=_FakeVerifiedAuth(new_sign_count=1),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")
    mocker.patch("services.webauthn.origin_for_request", return_value="https://host")
    mocker.patch("services.webauthn.log_event")

    mocker.patch(
        "services.webauthn.database.users.get_user_by_id",
        return_value={
            "id": test_user["id"],
            "is_inactivated": False,
            "saml_idp_id": "11111111-1111-1111-1111-111111111111",
        },
    )

    req = _fake_request(state["session"])
    payload = CompleteAuthenticationRequest(
        response={
            "id": state["raw_b64"],
            "rawId": state["raw_b64"],
            "type": "public-key",
            "response": {
                "clientDataJSON": "x",
                "authenticatorData": "y",
                "signature": "z",
                "userHandle": None,
            },
        }
    )

    with pytest.raises(ValidationError) as excinfo:
        webauthn_service.complete_authentication(req, str(test_user["tenant_id"]), payload)
    assert excinfo.value.code == "eligibility_revoked"


def test_complete_authentication_rejects_deleted_user(test_user, mocker):
    """User deleted between begin and complete is rejected."""
    _seed_passkey(test_user, credential_id=b"toctou-deleted", sign_count=0, backup_eligible=True)
    state = _seed_login_session(b"toctou-deleted", str(test_user["id"]))

    mocker.patch(
        "services.webauthn.verify_authentication",
        return_value=_FakeVerifiedAuth(new_sign_count=1),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")
    mocker.patch("services.webauthn.origin_for_request", return_value="https://host")
    log_event = mocker.patch("services.webauthn.log_event")

    mocker.patch(
        "services.webauthn.database.users.get_user_by_id",
        return_value=None,
    )

    req = _fake_request(state["session"])
    payload = CompleteAuthenticationRequest(
        response={
            "id": state["raw_b64"],
            "rawId": state["raw_b64"],
            "type": "public-key",
            "response": {
                "clientDataJSON": "x",
                "authenticatorData": "y",
                "signature": "z",
                "userHandle": None,
            },
        }
    )

    with pytest.raises(ValidationError) as excinfo:
        webauthn_service.complete_authentication(req, str(test_user["tenant_id"]), payload)
    assert excinfo.value.code == "eligibility_revoked"

    assert any(
        c.kwargs.get("event_type") == "passkey_auth_failure"
        and c.kwargs["metadata"]["reason"] == "eligibility_revoked"
        for c in log_event.call_args_list
    )


# =============================================================================
# Admin operations (iteration 5)
# =============================================================================


def _requesting_admin(user: dict) -> RequestingUser:
    return {
        "id": str(user["id"]),
        "tenant_id": str(user["tenant_id"]),
        "role": user.get("role", "admin"),
    }


def test_admin_list_credentials_happy_path(test_user, test_admin_user):
    _seed_passkey(test_user, credential_id=b"admin-list-1", name="Laptop")
    _seed_passkey(test_user, credential_id=b"admin-list-2", name="Phone")

    result = webauthn_service.admin_list_credentials(
        _requesting_admin(test_admin_user), str(test_user["id"])
    )

    names = sorted(p.name for p in result)
    assert names == ["Laptop", "Phone"]


def test_admin_list_credentials_forbidden_for_member(test_user):
    from services.exceptions import ForbiddenError

    with pytest.raises(ForbiddenError):
        webauthn_service.admin_list_credentials(_requesting(test_user), str(test_user["id"]))


def test_admin_list_credentials_cross_tenant_empty(test_user, test_admin_user):
    # Passkey lives in test_user's tenant. An admin in a different tenant sees none.
    _seed_passkey(test_user, credential_id=b"admin-iso-1", name="Key")

    other_admin: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": "00000000-0000-0000-0000-000000000099",
        "role": "admin",
    }
    result = webauthn_service.admin_list_credentials(other_admin, str(test_user["id"]))
    assert result == []


def test_admin_revoke_credential_happy_path(test_user, test_admin_user, mocker):
    row = _seed_passkey(test_user, credential_id=b"admin-revoke-1", name="Target key")
    log_event = mocker.patch("services.webauthn.log_event")

    webauthn_service.admin_revoke_credential(
        _requesting_admin(test_admin_user),
        str(test_user["id"]),
        str(row["id"]),
    )

    # Row gone
    fresh = database.webauthn_credentials.get_credential(test_user["tenant_id"], str(row["id"]))
    assert fresh is None

    # Event emitted with revoked_by_admin + target_user_id metadata
    assert log_event.called
    kwargs = log_event.call_args.kwargs
    assert kwargs["event_type"] == "passkey_deleted"
    assert kwargs["actor_user_id"] == str(test_admin_user["id"])
    assert kwargs["metadata"]["revoked_by_admin"] is True
    assert kwargs["metadata"]["target_user_id"] == str(test_user["id"])
    assert kwargs["metadata"]["credential_name"] == "Target key"
    # target_user_name survives anonymization in the audit trail
    assert "target_user_name" in kwargs["metadata"]
    assert kwargs["metadata"]["target_user_name"].strip() != ""


def test_admin_revoke_credential_revokes_oauth2_tokens(test_user, test_admin_user, mocker):
    """An admin revoke on a compromised credential must also revoke the target
    user's OAuth2 tokens so an attacker with an active access/refresh token is
    ejected alongside the passkey."""
    row = _seed_passkey(test_user, credential_id=b"admin-revoke-oauth", name="Target key")
    revoke_tokens = mocker.patch(
        "services.webauthn.database.oauth2.revoke_all_user_tokens", return_value=2
    )
    log_event = mocker.patch("services.webauthn.log_event")

    webauthn_service.admin_revoke_credential(
        _requesting_admin(test_admin_user),
        str(test_user["id"]),
        str(row["id"]),
    )

    revoke_tokens.assert_called_once_with(str(test_user["tenant_id"]), str(test_user["id"]))

    # Two log_event calls: oauth2_user_tokens_revoked + passkey_deleted.
    event_types = [c.kwargs["event_type"] for c in log_event.call_args_list]
    assert "oauth2_user_tokens_revoked" in event_types
    assert "passkey_deleted" in event_types
    oauth_call = next(
        c
        for c in log_event.call_args_list
        if c.kwargs["event_type"] == "oauth2_user_tokens_revoked"
    )
    assert oauth_call.kwargs["metadata"]["reason"] == "admin_revoked_passkey"
    assert oauth_call.kwargs["metadata"]["tokens_revoked"] == 2


def test_admin_revoke_credential_skips_token_event_when_no_tokens(
    test_user, test_admin_user, mocker
):
    """No OAuth2 tokens in play -> don't emit the revoke event. Keeps the audit
    log free of no-op entries."""
    row = _seed_passkey(test_user, credential_id=b"admin-revoke-no-tok", name="Target key")
    mocker.patch("services.webauthn.database.oauth2.revoke_all_user_tokens", return_value=0)
    log_event = mocker.patch("services.webauthn.log_event")

    webauthn_service.admin_revoke_credential(
        _requesting_admin(test_admin_user),
        str(test_user["id"]),
        str(row["id"]),
    )

    event_types = [c.kwargs["event_type"] for c in log_event.call_args_list]
    assert event_types == ["passkey_deleted"]


def test_admin_revoke_credential_unknown_user(test_admin_user):
    """Admin passes a well-formed user_id UUID that doesn't resolve to a user."""
    fake_user = "00000000-0000-0000-0000-0000000000ff"
    fake_cred = "00000000-0000-0000-0000-0000000000ee"
    with pytest.raises(NotFoundError) as exc_info:
        webauthn_service.admin_revoke_credential(
            _requesting_admin(test_admin_user),
            fake_user,
            fake_cred,
        )
    assert exc_info.value.code == "user_not_found"


def test_admin_revoke_credential_wrong_user(test_user, test_admin_user):
    """user_id in args does not match the credential's owner -> NotFoundError."""
    row = _seed_passkey(test_user, credential_id=b"admin-revoke-wrong", name="k")

    other_user_id = "00000000-0000-0000-0000-000000000042"
    with pytest.raises(NotFoundError):
        webauthn_service.admin_revoke_credential(
            _requesting_admin(test_admin_user),
            other_user_id,
            str(row["id"]),
        )


def test_admin_revoke_credential_cross_tenant(test_user, test_admin_user):
    row = _seed_passkey(test_user, credential_id=b"admin-revoke-iso", name="k")

    other_tenant_admin: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": "00000000-0000-0000-0000-000000000099",
        "role": "admin",
    }
    with pytest.raises(NotFoundError):
        webauthn_service.admin_revoke_credential(
            other_tenant_admin,
            str(test_user["id"]),
            str(row["id"]),
        )


def test_admin_revoke_credential_forbidden_for_member(test_user):
    from services.exceptions import ForbiddenError

    row = _seed_passkey(test_user, credential_id=b"admin-revoke-forbid", name="k")
    with pytest.raises(ForbiddenError):
        webauthn_service.admin_revoke_credential(
            _requesting(test_user),
            str(test_user["id"]),
            str(row["id"]),
        )


def test_admin_list_credentials_tracks_activity(test_user, test_admin_user, mocker):
    """admin_list_credentials is a read, so it must call track_activity."""
    track = mocker.patch("services.webauthn.track_activity")
    webauthn_service.admin_list_credentials(
        _requesting_admin(test_admin_user), str(test_user["id"])
    )
    # Activity is tracked for the requesting admin, not the target user.
    track.assert_called_once_with(str(test_admin_user["tenant_id"]), str(test_admin_user["id"]))


def test_admin_revoke_nonexistent_credential_raises_not_found(test_user, test_admin_user):
    """Passing a well-formed UUID that doesn't exist must return NotFoundError,
    not leak existence via a different error code or status."""
    fake_cred = "00000000-0000-0000-0000-0000000000aa"
    with pytest.raises(NotFoundError):
        webauthn_service.admin_revoke_credential(
            _requesting_admin(test_admin_user),
            str(test_user["id"]),
            fake_cred,
        )


def test_admin_revoke_credential_matches_target_user_only(test_user, test_admin_user):
    """If two users in the same tenant each own a passkey, revoking the wrong
    user's credential_uuid paired with the right user_id must NotFoundError
    (defence against mistaken-UI revocations that would otherwise bypass the
    ownership check purely at the DB DELETE step)."""
    row_a = _seed_passkey(test_user, credential_id=b"admin-pair-a", name="UserA")

    # Create a second user in the same tenant via the users table directly
    # (matching the conftest pattern).
    import uuid as _uuid

    other_user_id = database.fetchone(
        test_user["tenant_id"],
        """
        insert into users (tenant_id, first_name, last_name, role)
        values (:tenant_id, 'Other', 'User', 'member') returning id
        """,
        {"tenant_id": test_user["tenant_id"]},
    )["id"]

    # Revoke with user_id=other_user_id but credential_uuid=row_a (owned by test_user)
    with pytest.raises(NotFoundError):
        webauthn_service.admin_revoke_credential(
            _requesting_admin(test_admin_user),
            str(other_user_id),
            str(row_a["id"]),
        )
    # Suppress unused-variable lint if type checker complains.
    _ = _uuid

    # Row must still exist (no partial deletion happened).
    still_there = database.webauthn_credentials.get_credential(
        test_user["tenant_id"], str(row_a["id"])
    )
    assert still_there is not None


def test_admin_revoke_self_is_rejected(test_admin_user):
    """An admin cannot revoke their own passkey via the admin endpoint.

    Self-revoke via the admin path would (1) pollute the audit trail with
    revoked_by_admin events where actor == target, and (2) risk locking the
    admin out if the passkey was their only remaining factor. Admins must use
    the account passkeys page instead.
    """
    row = _seed_passkey(test_admin_user, credential_id=b"self-revoke", name="My key")

    with pytest.raises(ValidationError) as exc_info:
        webauthn_service.admin_revoke_credential(
            _requesting_admin(test_admin_user),
            str(test_admin_user["id"]),
            str(row["id"]),
        )
    assert exc_info.value.code == "cannot_revoke_own_passkey"

    # Credential must still exist (no partial side effect).
    still_there = database.webauthn_credentials.get_credential(
        test_admin_user["tenant_id"], str(row["id"])
    )
    assert still_there is not None


def test_admin_cannot_revoke_super_admin_passkey(test_user, test_admin_user, test_super_admin_user, mocker):
    """A plain admin must not be able to revoke a super_admin's passkey.

    Protects super admins from having their credentials revoked by lower-privilege
    admins. The service must raise ForbiddenError with code super_admin_required.
    """
    from services.exceptions import ForbiddenError

    row = _seed_passkey(test_super_admin_user, credential_id=b"sa-revoke-guard", name="SA key")

    with pytest.raises(ForbiddenError) as exc_info:
        webauthn_service.admin_revoke_credential(
            _requesting_admin(test_admin_user),
            str(test_super_admin_user["id"]),
            str(row["id"]),
        )
    assert exc_info.value.code == "super_admin_required"

    # Credential must still exist (no partial deletion).
    still_there = database.webauthn_credentials.get_credential(
        test_super_admin_user["tenant_id"], str(row["id"])
    )
    assert still_there is not None


def test_super_admin_can_revoke_another_super_admin_passkey(
    test_user, test_super_admin_user, mocker
):
    """A super_admin can revoke another super_admin's passkey."""
    import database as _db

    # Create a second super_admin in the same tenant to act as the requester.
    from uuid import uuid4

    unique = str(uuid4())[:8]
    other_sa = _db.fetchone(
        test_super_admin_user["tenant_id"],
        """
        INSERT INTO users (tenant_id, first_name, last_name, role)
        VALUES (:tenant_id, 'Other', 'SuperAdmin', 'super_admin')
        RETURNING id, first_name, last_name, role
        """,
        {"tenant_id": test_super_admin_user["tenant_id"]},
    )
    other_sa_requesting: RequestingUser = {
        "id": str(other_sa["id"]),
        "tenant_id": str(test_super_admin_user["tenant_id"]),
        "role": "super_admin",
    }

    row = _seed_passkey(test_super_admin_user, credential_id=b"sa-revoke-by-sa", name="SA key 2")
    mocker.patch("services.webauthn.log_event")
    mocker.patch("services.webauthn.database.oauth2.revoke_all_user_tokens", return_value=0)

    # Should not raise.
    webauthn_service.admin_revoke_credential(
        other_sa_requesting,
        str(test_super_admin_user["id"]),
        str(row["id"]),
    )

    # Credential is gone.
    gone = database.webauthn_credentials.get_credential(
        test_super_admin_user["tenant_id"], str(row["id"])
    )
    assert gone is None


def test_complete_authentication_preserves_backup_eligible(test_user, mocker):
    """A successful assertion must never change backup_eligible (immutable)."""
    row = _seed_passkey(
        test_user,
        credential_id=b"be-immutable-cred",
        sign_count=1,
        backup_eligible=False,  # Start as non-backup-eligible
        backup_state=False,
    )
    state = _seed_login_session(b"be-immutable-cred", str(test_user["id"]))

    # Library reports backup_eligible-looking state in the assertion, but we
    # must NOT echo that back into backup_eligible.
    mocker.patch(
        "services.webauthn.verify_authentication",
        return_value=_FakeVerifiedAuth(new_sign_count=2, credential_backed_up=True),
    )
    mocker.patch("services.webauthn.rp_id_for_request", return_value="host")
    mocker.patch("services.webauthn.origin_for_request", return_value="https://host")
    mocker.patch("services.webauthn.log_event")

    from fastapi.responses import RedirectResponse

    mocker.patch(
        "routers.auth._login_completion.complete_authenticated_login",
        return_value=RedirectResponse(url="/dashboard", status_code=303),
    )

    req = _fake_request(state["session"])
    payload = CompleteAuthenticationRequest(
        response={"id": state["raw_b64"], "rawId": state["raw_b64"]}
    )
    webauthn_service.complete_authentication(req, str(test_user["tenant_id"]), payload)

    fresh = database.webauthn_credentials.get_credential(test_user["tenant_id"], str(row["id"]))
    # backup_eligible stays what it was at registration time
    assert fresh["backup_eligible"] is False
    # backup_state reflects the refreshed value from the assertion
    assert fresh["backup_state"] is True
