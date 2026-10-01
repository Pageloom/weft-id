"""Database tests: the initiate_login_uri client column."""

import database

LOGIN_URI = "https://rp.example/login"


def _create(tid, uid, **kwargs):
    return database.oauth2.create_normal_client(
        tenant_id=tid,
        tenant_id_value=tid,
        name="Launchable",
        redirect_uris=["https://rp.example/cb"],
        created_by=uid,
        **kwargs,
    )


def test_defaults_to_none(test_tenant, normal_oauth2_client):
    row = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert row["initiate_login_uri"] is None


def test_create_read_update_clear(test_tenant, test_admin_user):
    tid = test_tenant["id"]
    created = _create(tid, test_admin_user["id"], initiate_login_uri=LOGIN_URI)
    assert created["initiate_login_uri"] == LOGIN_URI

    by_client_id = database.oauth2.get_client_by_client_id(tid, created["client_id"])
    by_id = database.oauth2.get_client_by_id(tid, str(created["id"]))
    listed = [
        c
        for c in database.oauth2.get_all_clients(tid, client_type="normal")
        if c["client_id"] == created["client_id"]
    ]
    assert by_client_id["initiate_login_uri"] == LOGIN_URI
    assert by_id["initiate_login_uri"] == LOGIN_URI
    assert listed[0]["initiate_login_uri"] == LOGIN_URI

    updated = database.oauth2.update_client(
        tid, created["client_id"], initiate_login_uri="https://rp.example/other"
    )
    assert updated["initiate_login_uri"] == "https://rp.example/other"

    # Omitted leaves it alone; an empty string clears it.
    untouched = database.oauth2.update_client(tid, created["client_id"], name="Renamed")
    assert untouched["initiate_login_uri"] == "https://rp.example/other"
    cleared = database.oauth2.update_client(tid, created["client_id"], initiate_login_uri="")
    assert cleared["initiate_login_uri"] is None
