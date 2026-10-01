"""Database tests: oauth2_clients subject_type / sector_identifier_uri
(migration 0076) and the queries that read them."""

import database
import psycopg
import pytest

SECTOR = "https://sector.example/redirect_uris.json"


def test_new_client_is_public(test_tenant, normal_oauth2_client):
    row = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert row["subject_type"] == "public"
    assert row["sector_identifier_uri"] is None


def test_set_subject_type_round_trip(test_tenant, normal_oauth2_client):
    updated = database.oauth2.set_client_subject_type(
        test_tenant["id"],
        normal_oauth2_client["client_id"],
        subject_type="pairwise",
        sector_identifier_uri=SECTOR,
    )
    assert updated["subject_type"] == "pairwise"
    assert updated["sector_identifier_uri"] == SECTOR
    by_id = database.oauth2.get_client_by_id(test_tenant["id"], str(normal_oauth2_client["id"]))
    assert by_id["sector_identifier_uri"] == SECTOR
    (listed,) = [
        c
        for c in database.oauth2.get_all_clients(test_tenant["id"], client_type="normal")
        if c["client_id"] == normal_oauth2_client["client_id"]
    ]
    assert listed["subject_type"] == "pairwise"


def test_set_subject_type_skips_b2b(test_tenant, b2b_oauth2_client):
    assert (
        database.oauth2.set_client_subject_type(
            test_tenant["id"],
            b2b_oauth2_client["client_id"],
            subject_type="pairwise",
            sector_identifier_uri=None,
        )
        is None
    )


@pytest.mark.parametrize(
    ("subject_type", "sector"),
    [("pseudonymous", None), ("public", SECTOR), ("pairwise", "https://s.example/" + "x" * 2048)],
)
def test_constraints(test_tenant, normal_oauth2_client, subject_type, sector):
    with pytest.raises(psycopg.errors.CheckViolation):
        database.oauth2.set_client_subject_type(
            test_tenant["id"],
            normal_oauth2_client["client_id"],
            subject_type=subject_type,
            sector_identifier_uri=sector,
        )


def test_find_token_carries_subject_settings(test_tenant, normal_oauth2_client, test_user):
    database.oauth2.set_client_subject_type(
        test_tenant["id"],
        normal_oauth2_client["client_id"],
        subject_type="pairwise",
        sector_identifier_uri=None,
    )
    _, refresh_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        scope="openid",
    )
    access = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        parent_token_id=refresh_id,
        scope="openid",
    )
    found = database.oauth2.find_token(test_tenant["id"], access)
    assert found["subject_type"] == "pairwise"
    assert found["sector_identifier_uri"] is None
    assert found["redirect_uris"] == normal_oauth2_client["redirect_uris"]
