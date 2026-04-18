"""Tests for services.webauthn (passkey registration / management)."""

from dataclasses import dataclass
from types import SimpleNamespace

import database
import pytest
from schemas.webauthn import CompleteRegistrationRequest
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
