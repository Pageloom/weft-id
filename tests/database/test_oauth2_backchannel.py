"""Database tests: back-channel logout client columns and the delivery queue."""

import database
import psycopg
import pytest

ISSUER = "https://tenant.example.com"
BC_URI = "https://rp.example/bc"


@pytest.fixture
def bc_client(test_tenant, test_admin_user):
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="BC client",
        redirect_uris=["https://rp.example/cb"],
        created_by=test_admin_user["id"],
        backchannel_logout_uri=BC_URI,
    )
    database.oauth2.update_client_oidc_settings(
        test_tenant["id"], client["client_id"], oidc_enabled=True
    )
    return client


def _queue(tid, client, user, sid="s-1", **kw) -> list[dict]:
    database.oauth2.upsert_session_client(
        tid, tid, sid=sid, client_id=str(client["id"]), user_id=str(user["id"])
    )
    return database.oauth2.consume_session_clients(tid, tid, sid, issuer=ISSUER, **kw)


def _rows(tid) -> list[dict]:
    return database.fetchall(
        tid, "select * from oidc_backchannel_logout_deliveries order by created_at"
    )


# ---------------------------------------------------------------------------
# Client columns
# ---------------------------------------------------------------------------


def test_client_columns_default(test_tenant, normal_oauth2_client):
    row = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert row["backchannel_logout_uri"] is None
    assert row["backchannel_logout_session_required"] is True


def test_client_columns_create_read_update_clear(test_tenant, test_admin_user):
    tid = test_tenant["id"]
    created = database.oauth2.create_normal_client(
        tenant_id=tid,
        tenant_id_value=tid,
        name="BC",
        redirect_uris=["https://rp.example/cb"],
        created_by=test_admin_user["id"],
        backchannel_logout_uri=BC_URI,
        backchannel_logout_session_required=False,
    )
    assert created["backchannel_logout_uri"] == BC_URI
    assert created["backchannel_logout_session_required"] is False
    by_id = database.oauth2.get_client_by_id(tid, str(created["id"]))
    assert by_id["backchannel_logout_uri"] == BC_URI

    cid = created["client_id"]
    updated = database.oauth2.update_client(
        tid,
        cid,
        backchannel_logout_uri="https://rp.example/bc2",
        backchannel_logout_session_required=True,
    )
    assert updated["backchannel_logout_uri"] == "https://rp.example/bc2"
    assert updated["backchannel_logout_session_required"] is True

    kept = database.oauth2.update_client(tid, cid, name="Renamed")
    assert kept["backchannel_logout_uri"] == "https://rp.example/bc2"

    cleared = database.oauth2.update_client(tid, cid, backchannel_logout_uri="")
    assert cleared["backchannel_logout_uri"] is None


def test_client_listing_includes_backchannel_logout(test_tenant, normal_oauth2_client):
    for client_type in (None, "normal"):
        rows = database.oauth2.get_all_clients(test_tenant["id"], client_type=client_type)
        assert all("backchannel_logout_uri" in row for row in rows)


# ---------------------------------------------------------------------------
# Queueing (consume_session_clients)
# ---------------------------------------------------------------------------


def test_consume_queues_a_delivery(test_tenant, bc_client, test_user):
    tid = test_tenant["id"]
    (row,) = _queue(tid, bc_client, test_user)
    assert row["backchannel_queued"] is True

    (delivery,) = _rows(tid)
    assert str(delivery["client_id"]) == str(bc_client["id"])
    assert delivery["sub"] == str(test_user["id"])
    assert delivery["sid"] == "s-1"
    assert delivery["issuer"] == ISSUER
    assert delivery["status"] == "pending"
    assert delivery["attempts"] == 0
    assert delivery["completed_at"] is None


def test_consume_skips_excluded_client(test_tenant, bc_client, test_user):
    tid = test_tenant["id"]
    (row,) = _queue(tid, bc_client, test_user, exclude_client_id=str(bc_client["id"]))
    assert row["backchannel_queued"] is False
    assert _rows(tid) == []


def test_consume_skips_client_without_uri(test_tenant, normal_oauth2_client, test_user):
    tid = test_tenant["id"]
    database.oauth2.update_client_oidc_settings(
        tid, normal_oauth2_client["client_id"], oidc_enabled=True
    )
    (row,) = _queue(tid, normal_oauth2_client, test_user)
    assert row["backchannel_queued"] is False
    assert _rows(tid) == []


def test_deliveries_cascade_with_the_client(test_tenant, bc_client, test_user):
    tid = test_tenant["id"]
    _queue(tid, bc_client, test_user)
    database.oauth2.delete_client(tid, bc_client["client_id"])
    assert _rows(tid) == []


def test_delivery_outlives_the_user(test_tenant, bc_client, test_admin_user, test_user):
    """``sub`` is not a foreign key: a deleted user's logout still goes out."""
    tid = test_tenant["id"]
    _queue(tid, bc_client, test_user)
    database.execute(tid, "delete from users where id = :id", {"id": test_user["id"]})
    assert len(_rows(tid)) == 1


def test_deliveries_are_tenant_isolated(test_tenant, bc_client, test_user):
    """Strict RLS: an UNSCOPED read sees nothing and an UNSCOPED write fails."""
    tid = test_tenant["id"]
    _queue(tid, bc_client, test_user)
    assert (
        database.fetchall(database.UNSCOPED, "select * from oidc_backchannel_logout_deliveries")
        == []
    )
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        database.execute(
            database.UNSCOPED,
            """
            insert into oidc_backchannel_logout_deliveries (tenant_id, client_id, sub, issuer)
            values (:t, :c, 'x', 'y')
            """,
            {"t": tid, "c": bc_client["id"]},
        )


# ---------------------------------------------------------------------------
# Claiming and outcomes
# ---------------------------------------------------------------------------


def test_due_tenant_is_listed(test_tenant, bc_client, test_user):
    tid = test_tenant["id"]
    _queue(tid, bc_client, test_user)
    assert str(tid) in database.oauth2.list_tenants_with_due_deliveries()


def test_claim_returns_delivery_with_client_and_leases_it(test_tenant, bc_client, test_user):
    tid = test_tenant["id"]
    _queue(tid, bc_client, test_user)

    (claimed,) = database.oauth2.claim_due_deliveries(tid, limit=10, lease_seconds=60)
    assert str(claimed["client_uuid"]) == str(bc_client["id"])
    assert claimed["client_id"] == bc_client["client_id"]
    assert claimed["backchannel_logout_uri"] == BC_URI
    assert claimed["backchannel_logout_session_required"] is True
    assert claimed["oidc_enabled"] is True
    assert claimed["attempts"] == 0

    # Leased: not claimable again, and the tenant is no longer due.
    assert database.oauth2.claim_due_deliveries(tid, limit=10, lease_seconds=60) == []
    assert str(tid) not in database.oauth2.list_tenants_with_due_deliveries()


def test_claim_respects_limit(test_tenant, bc_client, test_user):
    tid = test_tenant["id"]
    for sid in ("s-1", "s-2", "s-3"):
        _queue(tid, bc_client, test_user, sid=sid)
    assert len(database.oauth2.claim_due_deliveries(tid, limit=2, lease_seconds=60)) == 2
    assert len(database.oauth2.claim_due_deliveries(tid, limit=2, lease_seconds=60)) == 1


def test_mark_delivered(test_tenant, bc_client, test_user):
    tid = test_tenant["id"]
    _queue(tid, bc_client, test_user)
    (claimed,) = database.oauth2.claim_due_deliveries(tid, limit=10, lease_seconds=60)

    assert database.oauth2.mark_delivered(tid, str(claimed["id"]), http_status=200) == 1
    (row,) = _rows(tid)
    assert row["status"] == "delivered"
    assert row["attempts"] == 1
    assert row["last_http_status"] == 200
    assert row["completed_at"] is not None and row["last_attempt_at"] is not None
    # Finished rows are never updated again.
    assert database.oauth2.mark_delivered(tid, str(claimed["id"]), http_status=200) == 0


def test_mark_retry_reschedules(test_tenant, bc_client, test_user):
    tid = test_tenant["id"]
    _queue(tid, bc_client, test_user)
    (claimed,) = database.oauth2.claim_due_deliveries(tid, limit=10, lease_seconds=60)

    database.oauth2.mark_retry(
        tid, str(claimed["id"]), retry_in_seconds=30, error="http_503", http_status=503
    )
    (row,) = _rows(tid)
    assert row["status"] == "pending"
    assert row["attempts"] == 1
    assert row["last_error"] == "http_503"
    assert row["last_http_status"] == 503
    assert row["next_attempt_at"] > row["last_attempt_at"]
    assert database.oauth2.claim_due_deliveries(tid, limit=10, lease_seconds=60) == []

    # Once due again it is claimable, with the attempt count carried.
    database.execute(tid, "update oidc_backchannel_logout_deliveries set next_attempt_at = now()")
    (again,) = database.oauth2.claim_due_deliveries(tid, limit=10, lease_seconds=60)
    assert again["attempts"] == 1


def test_mark_failed_counts_the_attempt(test_tenant, bc_client, test_user):
    tid = test_tenant["id"]
    _queue(tid, bc_client, test_user)
    (claimed,) = database.oauth2.claim_due_deliveries(tid, limit=10, lease_seconds=60)

    database.oauth2.mark_failed(tid, str(claimed["id"]), error="http_400", http_status=400)
    (row,) = _rows(tid)
    assert row["status"] == "failed"
    assert row["attempts"] == 1
    assert row["last_http_status"] == 400
    assert row["completed_at"] is not None


def test_mark_failed_without_attempt(test_tenant, bc_client, test_user):
    tid = test_tenant["id"]
    _queue(tid, bc_client, test_user)
    (claimed,) = database.oauth2.claim_due_deliveries(tid, limit=10, lease_seconds=60)

    database.oauth2.mark_failed(
        tid,
        str(claimed["id"]),
        error="client_no_longer_eligible",
        http_status=None,
        count_attempt=False,
    )
    (row,) = _rows(tid)
    assert row["status"] == "failed"
    assert row["attempts"] == 0
    assert row["last_attempt_at"] is None
    assert row["last_error"] == "client_no_longer_eligible"


def test_last_error_is_truncated(test_tenant, bc_client, test_user):
    tid = test_tenant["id"]
    _queue(tid, bc_client, test_user)
    (claimed,) = database.oauth2.claim_due_deliveries(tid, limit=10, lease_seconds=60)
    database.oauth2.mark_retry(
        tid, str(claimed["id"]), retry_in_seconds=30, error="x" * 5000, http_status=None
    )
    assert len(_rows(tid)[0]["last_error"]) == 1000


# ---------------------------------------------------------------------------
# Retention and the stale session sweep (cross-tenant functions)
# ---------------------------------------------------------------------------


def test_purge_removes_only_old_finished_rows(test_tenant, bc_client, test_user):
    tid = test_tenant["id"]
    for sid in ("old-done", "new-done", "old-pending"):
        _queue(tid, bc_client, test_user, sid=sid)
    database.execute(
        tid,
        """
        update oidc_backchannel_logout_deliveries
        set status = 'delivered', completed_at = now() - interval '40 days'
        where sid = 'old-done'
        """,
    )
    database.execute(
        tid,
        """
        update oidc_backchannel_logout_deliveries
        set status = 'failed', completed_at = now() - interval '1 day'
        where sid = 'new-done'
        """,
    )
    database.execute(
        tid,
        """
        update oidc_backchannel_logout_deliveries
        set created_at = now() - interval '40 days' where sid = 'old-pending'
        """,
    )

    assert database.oauth2.purge_finished_deliveries(older_than_days=30) >= 1
    assert {row["sid"] for row in _rows(tid)} == {"new-done", "old-pending"}


def test_sweep_removes_only_stale_session_records(test_tenant, bc_client, test_user):
    tid = test_tenant["id"]
    for sid in ("stale", "fresh"):
        database.oauth2.upsert_session_client(
            tid, tid, sid=sid, client_id=str(bc_client["id"]), user_id=str(test_user["id"])
        )
    database.execute(
        tid,
        """
        update oidc_session_clients set last_issued_at = now() - interval '100 days'
        where sid = 'stale'
        """,
    )

    assert database.oauth2.sweep_stale_session_clients(older_than_days=90) >= 1
    rows = database.fetchall(tid, "select sid from oidc_session_clients")
    assert [row["sid"] for row in rows] == ["fresh"]


# ---------------------------------------------------------------------------
# Recorded issuer and per-user consumption
# ---------------------------------------------------------------------------

RECORDED = "https://recorded.example.com"


def _record(tid, client, user, sid, issuer=RECORDED):
    database.oauth2.upsert_session_client(
        tid, tid, sid=sid, client_id=str(client["id"]), user_id=str(user["id"]), issuer=issuer
    )


def _session_rows(tid) -> list[dict]:
    return database.fetchall(tid, "select * from oidc_session_clients order by sid")


def test_upsert_records_issuer_and_keeps_it(test_tenant, bc_client, test_user):
    tid = test_tenant["id"]
    _record(tid, bc_client, test_user, "s-1")
    assert _session_rows(tid)[0]["issuer"] == RECORDED
    # A repeat issuance without an issuer does not erase the recorded one.
    _record(tid, bc_client, test_user, "s-1", issuer=None)
    assert _session_rows(tid)[0]["issuer"] == RECORDED


def test_consume_prefers_recorded_issuer(test_tenant, bc_client, test_user):
    tid = test_tenant["id"]
    _record(tid, bc_client, test_user, "s-1")
    (row,) = database.oauth2.consume_session_clients(tid, tid, "s-1", issuer=ISSUER)
    assert row["issuer"] == RECORDED
    assert _rows(tid)[0]["issuer"] == RECORDED


def test_consume_user_takes_every_session(test_tenant, bc_client, test_user, test_admin_user):
    tid = test_tenant["id"]
    _record(tid, bc_client, test_user, "s-1")
    _record(tid, bc_client, test_user, "s-2", issuer=None)
    _record(tid, bc_client, test_admin_user, "s-3")

    rows = database.oauth2.consume_user_session_clients(
        tid, tid, str(test_user["id"]), issuer=ISSUER
    )

    assert sorted(row["sid"] for row in rows) == ["s-1", "s-2"]
    assert all(row["backchannel_queued"] for row in rows)
    deliveries = {d["sid"]: d for d in _rows(tid)}
    assert set(deliveries) == {"s-1", "s-2"}
    assert deliveries["s-1"]["issuer"] == RECORDED
    assert deliveries["s-2"]["issuer"] == ISSUER  # recorded before issuers were kept
    assert {d["sub"] for d in deliveries.values()} == {str(test_user["id"])}
    # The other user's session is untouched.
    assert [r["sid"] for r in _session_rows(tid)] == ["s-3"]


def test_consume_user_queued_flag_is_per_session(
    test_tenant, bc_client, normal_oauth2_client, test_user
):
    """A client without a back-channel URI is consumed but not queued."""
    tid = test_tenant["id"]
    _record(tid, bc_client, test_user, "s-1")
    _record(tid, normal_oauth2_client, test_user, "s-1")
    rows = database.oauth2.consume_user_session_clients(
        tid, tid, str(test_user["id"]), issuer=ISSUER
    )
    queued = {str(row["id"]): row["backchannel_queued"] for row in rows}
    assert queued == {str(bc_client["id"]): True, str(normal_oauth2_client["id"]): False}
    assert _session_rows(tid) == []


def test_consume_user_client_takes_only_that_pair(
    test_tenant, bc_client, normal_oauth2_client, test_user, test_admin_user
):
    """Consent revocation signs one user out of one client, every session."""
    tid = test_tenant["id"]
    _record(tid, bc_client, test_user, "s-1")
    _record(tid, bc_client, test_user, "s-2", issuer=None)
    _record(tid, normal_oauth2_client, test_user, "s-1")
    _record(tid, bc_client, test_admin_user, "s-3")

    rows = database.oauth2.consume_user_client_session_clients(
        tid, tid, str(test_user["id"]), str(bc_client["id"]), issuer=ISSUER
    )

    assert sorted(row["sid"] for row in rows) == ["s-1", "s-2"]
    assert all(row["backchannel_queued"] for row in rows)
    deliveries = {d["sid"]: d for d in _rows(tid)}
    assert set(deliveries) == {"s-1", "s-2"}
    assert deliveries["s-2"]["issuer"] == ISSUER
    assert {str(d["client_id"]) for d in deliveries.values()} == {str(bc_client["id"])}
    remaining = {(r["sid"], str(r["client_id"])) for r in _session_rows(tid)}
    assert remaining == {("s-1", str(normal_oauth2_client["id"])), ("s-3", str(bc_client["id"]))}


def test_consume_user_client_with_no_sessions(test_tenant, bc_client, test_user):
    tid = test_tenant["id"]
    rows = database.oauth2.consume_user_client_session_clients(
        tid, tid, str(test_user["id"]), str(bc_client["id"]), issuer=ISSUER
    )
    assert rows == []
    assert _rows(tid) == []


def test_consume_user_with_no_sessions(test_tenant, test_user):
    tid = test_tenant["id"]
    assert (
        database.oauth2.consume_user_session_clients(tid, tid, str(test_user["id"]), issuer=ISSUER)
        == []
    )


# ---------------------------------------------------------------------------
# Delivery log reads (status view)
# ---------------------------------------------------------------------------


def _set_status(tid, sid, status, created_offset_s=0):
    database.execute(
        tid,
        """
        update oidc_backchannel_logout_deliveries
        set status = :status, created_at = now() - make_interval(secs => :off)
        where sid = :sid
        """,
        {"status": status, "sid": sid, "off": created_offset_s},
    )


def test_list_client_deliveries_newest_first_with_user(
    test_tenant, bc_client, test_user, test_admin_user
):
    tid = test_tenant["id"]
    _queue(tid, bc_client, test_user, sid="old")
    _queue(tid, bc_client, test_admin_user, sid="new")
    _set_status(tid, "old", "delivered", created_offset_s=60)

    rows = database.oauth2.list_client_deliveries(tid, str(bc_client["id"]), limit=10)

    assert [r["sub"] for r in rows] == [str(test_admin_user["id"]), str(test_user["id"])]
    assert rows[0]["user_email"] == test_admin_user["email"]
    assert rows[0]["user_first_name"] == test_admin_user["first_name"]
    assert rows[1]["status"] == "delivered"


def test_list_client_deliveries_filters_and_pages(
    test_tenant, bc_client, test_user, test_admin_user
):
    tid = test_tenant["id"]
    cid = str(bc_client["id"])
    for i in range(3):
        _queue(tid, bc_client, test_user, sid=f"s-{i}")
        _set_status(tid, f"s-{i}", "failed" if i == 0 else "pending", created_offset_s=i)

    failed = database.oauth2.list_client_deliveries(tid, cid, status="failed", limit=10)
    assert [r["status"] for r in failed] == ["failed"]
    first = database.oauth2.list_client_deliveries(tid, cid, limit=2)
    second = database.oauth2.list_client_deliveries(tid, cid, limit=2, offset=2)
    assert len(first) == 2 and len(second) == 1
    assert {r["id"] for r in first}.isdisjoint({r["id"] for r in second})
    assert database.oauth2.count_client_deliveries_by_status(tid, cid) == {
        "pending": 2,
        "delivered": 0,
        "failed": 1,
    }


def test_list_client_deliveries_deleted_user_has_no_name(test_tenant, bc_client, test_user):
    tid = test_tenant["id"]
    _queue(tid, bc_client, test_user)
    database.execute(tid, "delete from users where id = :id", {"id": test_user["id"]})
    (row,) = database.oauth2.list_client_deliveries(tid, str(bc_client["id"]), limit=10)
    assert row["sub"] == str(test_user["id"])
    assert row["user_first_name"] is None and row["user_email"] is None


def test_list_client_deliveries_only_that_client(
    test_tenant, test_admin_user, bc_client, test_user
):
    tid = test_tenant["id"]
    other = database.oauth2.create_normal_client(
        tenant_id=tid,
        tenant_id_value=tid,
        name="Other",
        redirect_uris=["https://rp2.example/cb"],
        created_by=test_admin_user["id"],
        backchannel_logout_uri=BC_URI,
    )
    database.oauth2.update_client_oidc_settings(tid, other["client_id"], oidc_enabled=True)
    _queue(tid, other, test_user)
    assert database.oauth2.list_client_deliveries(tid, str(bc_client["id"]), limit=10) == []
    assert database.oauth2.count_client_deliveries_by_status(tid, str(bc_client["id"])) == {
        "pending": 0,
        "delivered": 0,
        "failed": 0,
    }


def test_list_client_deliveries_is_tenant_scoped(test_tenant, bc_client, test_user):
    import uuid

    _queue(test_tenant["id"], bc_client, test_user)
    assert (
        database.oauth2.list_client_deliveries(str(uuid.uuid4()), str(bc_client["id"]), limit=10)
        == []
    )
