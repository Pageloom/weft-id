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
