"""Tests for utils.webauthn."""

from types import SimpleNamespace

import pytest
from utils import webauthn as wa


def _fake_request(headers: dict, scheme: str = "http") -> SimpleNamespace:
    return SimpleNamespace(headers=headers, url=SimpleNamespace(scheme=scheme))


def test_rp_id_for_request_uses_forwarded_host():
    req = _fake_request({"x-forwarded-host": "meridian.weftid.localhost:8443"})
    assert wa.rp_id_for_request(req) == "meridian.weftid.localhost"


def test_rp_id_for_request_falls_back_to_host():
    req = _fake_request({"host": "Test.Example.COM:8080"})
    assert wa.rp_id_for_request(req) == "test.example.com"


def test_origin_for_request_honors_forwarded_proto():
    req = _fake_request(
        {"x-forwarded-proto": "https", "x-forwarded-host": "meridian.weftid.localhost:4443"},
        scheme="http",
    )
    assert wa.origin_for_request(req) == "https://meridian.weftid.localhost:4443"


def test_origin_for_request_uses_request_scheme_when_no_forward():
    req = _fake_request({"host": "meridian.weftid.localhost:4443"}, scheme="http")
    assert wa.origin_for_request(req) == "http://meridian.weftid.localhost:4443"


def test_generate_registration_options_includes_exclude_credentials(mocker):
    captured: dict = {}

    def fake_generate(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(challenge=b"\x01\x02\x03")

    mocker.patch("utils.webauthn.generate_registration_options", side_effect=fake_generate)
    mocker.patch(
        "utils.webauthn.options_to_json",
        return_value='{"rp": {"id": "host"}, "challenge": "AQID"}',
    )

    options_dict, challenge = wa.generate_registration_options_for_user(
        rp_id="host",
        rp_name="Tenant",
        user_id_bytes=b"\x00" * 16,
        user_name="u@example.com",
        user_display_name="User",
        existing_credential_ids=[b"cred-a", b"cred-b"],
    )

    # Challenge is returned raw
    assert challenge == b"\x01\x02\x03"
    # Options dict is JSON-parsed
    assert options_dict["rp"]["id"] == "host"
    # exclude_credentials forwarded with the existing IDs
    excluded = captured["exclude_credentials"]
    assert len(excluded) == 2
    assert bytes(excluded[0].id) == b"cred-a"


def test_verify_registration_translates_library_errors(mocker):
    from webauthn.helpers import exceptions as webauthn_exc

    mocker.patch(
        "utils.webauthn.verify_registration_response",
        side_effect=webauthn_exc.InvalidRegistrationResponse("bad challenge"),
    )
    with pytest.raises(wa.WebAuthnError):
        wa.verify_registration(
            response={"id": "x"},
            expected_challenge=b"\x00",
            expected_rp_id="host",
            expected_origin="https://host",
        )


def test_rp_name_for_tenant_reads_tenant_name(mocker):
    import database

    mocker.patch.object(
        database.tenants,
        "get_tenant_by_id",
        return_value={"name": "Acme", "subdomain": "acme"},
    )
    assert wa.rp_name_for_tenant("tenant-id") == "Acme"


def test_rp_name_for_tenant_fallback_when_missing(mocker):
    import database

    mocker.patch.object(database.tenants, "get_tenant_by_id", return_value=None)
    assert wa.rp_name_for_tenant("tenant-id") == "WeftID"


def test_generate_authentication_options_includes_allow_credentials(mocker):
    captured: dict = {}

    def fake_generate(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(challenge=b"\x01\x02\x03")

    mocker.patch("utils.webauthn.generate_authentication_options", side_effect=fake_generate)
    mocker.patch(
        "utils.webauthn.options_to_json",
        return_value='{"rpId": "host", "challenge": "AQID", '
        '"allowCredentials": [{"id": "Y3JlZC1h"}, {"id": "Y3JlZC1i"}]}',
    )

    options_dict, challenge = wa.generate_authentication_options_for_user(
        rp_id="host",
        allowed_credential_ids=[b"cred-a", b"cred-b"],
    )

    assert challenge == b"\x01\x02\x03"
    assert options_dict["rpId"] == "host"
    # allow_credentials is forwarded with the credential ids we passed
    allow = captured["allow_credentials"]
    assert len(allow) == 2
    assert bytes(allow[0].id) == b"cred-a"
    assert bytes(allow[1].id) == b"cred-b"


def test_verify_authentication_wraps_library_errors(mocker):
    from webauthn.helpers import exceptions as webauthn_exc

    mocker.patch(
        "utils.webauthn.verify_authentication_response",
        side_effect=webauthn_exc.InvalidAuthenticationResponse("bad sig"),
    )
    with pytest.raises(wa.WebAuthnError) as excinfo:
        wa.verify_authentication(
            response={"id": "x"},
            expected_challenge=b"\x00",
            expected_rp_id="host",
            expected_origin="https://host",
            credential_public_key=b"pk",
            credential_current_sign_count=0,
        )
    assert "bad sig" in str(excinfo.value)


def test_verify_authentication_passes_through_when_ok(mocker):
    sentinel = object()
    mocker.patch(
        "utils.webauthn.verify_authentication_response",
        return_value=sentinel,
    )
    result = wa.verify_authentication(
        response={"id": "x"},
        expected_challenge=b"\x00",
        expected_rp_id="host",
        expected_origin="https://host",
        credential_public_key=b"pk",
        credential_current_sign_count=3,
    )
    assert result is sentinel


def test_verify_authentication_raises_sign_count_regression_error_on_sign_count_message(mocker):
    """Pin test: verify_authentication must raise SignCountRegressionError (not plain
    WebAuthnError) when the library error message contains 'sign count'.

    If a future library update changes the error wording so this keyword is no
    longer present, this test will fail and alert us to re-check clone detection.
    """
    from webauthn.helpers import exceptions as webauthn_exc

    mocker.patch(
        "utils.webauthn.verify_authentication_response",
        side_effect=webauthn_exc.InvalidAuthenticationResponse(
            "Response sign count of 5 was not greater than current sign count of 10"
        ),
    )
    with pytest.raises(wa.SignCountRegressionError):
        wa.verify_authentication(
            response={"id": "x"},
            expected_challenge=b"\x00",
            expected_rp_id="host",
            expected_origin="https://host",
            credential_public_key=b"pk",
            credential_current_sign_count=10,
        )


def test_verify_authentication_raises_sign_count_regression_error_on_counter_message(mocker):
    """Pin test: 'counter' keyword in the error message also triggers SignCountRegressionError."""
    from webauthn.helpers import exceptions as webauthn_exc

    mocker.patch(
        "utils.webauthn.verify_authentication_response",
        side_effect=webauthn_exc.InvalidAuthenticationResponse("Counter has not increased"),
    )
    with pytest.raises(wa.SignCountRegressionError):
        wa.verify_authentication(
            response={"id": "x"},
            expected_challenge=b"\x00",
            expected_rp_id="host",
            expected_origin="https://host",
            credential_public_key=b"pk",
            credential_current_sign_count=10,
        )


def test_verify_authentication_raises_plain_webauthn_error_for_other_messages(mocker):
    """Non-sign-count library errors must raise WebAuthnError, not SignCountRegressionError."""
    from webauthn.helpers import exceptions as webauthn_exc

    mocker.patch(
        "utils.webauthn.verify_authentication_response",
        side_effect=webauthn_exc.InvalidAuthenticationResponse("bad challenge"),
    )
    with pytest.raises(wa.WebAuthnError) as excinfo:
        wa.verify_authentication(
            response={"id": "x"},
            expected_challenge=b"\x00",
            expected_rp_id="host",
            expected_origin="https://host",
            credential_public_key=b"pk",
            credential_current_sign_count=0,
        )
    # Must be a plain WebAuthnError, not the more specific subclass.
    assert type(excinfo.value) is wa.WebAuthnError
