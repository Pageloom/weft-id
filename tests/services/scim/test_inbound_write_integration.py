"""End-to-end integration tests for the inbound SCIM write service.

Unlike the unit tests in `test_inbound_write.py`, these talk to the real
database. They exercise the full merge / create / replace / patch /
delete flow and verify the resulting DB state (users row, primary
email, user_idp_attributes external-id row, soft-delete state).

These tests pin the contract that:
1. Create-or-merge is idempotent on externalId AND on canonical email.
2. PATCH-driven attribute writes flow through the existing IdP
   mirror pipeline (so downstream SP outbound replay catches them).
3. Soft-delete preserves MFA + email rows.
4. Status transitions emit the expected event types.
"""

from __future__ import annotations

import time
from uuid import uuid4

import database
import pytest
from services.scim.inbound_write import (
    create_or_merge_user,
    patch_user,
    replace_user,
    soft_delete_user,
)


def _location_builder(uid: str) -> str:
    return f"https://t.test/scim/v2/inbound/i/Users/{uid}"


@pytest.fixture
def idp(test_tenant, test_user):
    return database.saml.create_identity_provider(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="SCIM IdP",
        provider_type="generic",
        sp_entity_id=f"urn:test:{uuid4().hex}",
        created_by=str(test_user["id"]),
    )


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


def test_create_writes_user_email_externalid_and_idp_binding(test_tenant, idp):
    payload, created = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {
            "userName": "alice.new@example.test",
            "name": {"givenName": "Alice", "familyName": "New"},
            "externalId": "okta-001",
            "active": True,
        },
        location_builder=_location_builder,
    )
    assert created is True
    user_id = payload["id"]

    row = database.users.get_user_by_id(str(test_tenant["id"]), user_id)
    assert row is not None
    assert row["saml_idp_id"] is not None and str(row["saml_idp_id"]) == str(idp["id"])
    assert row["first_name"] == "Alice"

    primary = database.user_emails.get_primary_email(str(test_tenant["id"]), user_id)
    assert primary is not None
    assert primary["email"] == "alice.new@example.test"

    ext = database.user_idp_attributes.get_external_id(
        str(test_tenant["id"]), user_id, str(idp["id"])
    )
    assert ext == "okta-001"


def test_create_then_merge_on_external_id_does_not_duplicate(test_tenant, idp):
    """Second POST with same externalId returns the same user (no dup)."""
    payload_1, c1 = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "merge-x@example.test", "externalId": "okta-merge-1"},
        location_builder=_location_builder,
    )
    payload_2, c2 = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {
            "userName": "different@example.test",  # different email
            "externalId": "okta-merge-1",  # same externalId
        },
        location_builder=_location_builder,
    )
    assert c1 is True and c2 is False
    assert payload_1["id"] == payload_2["id"]


def test_create_then_merge_on_email_does_not_duplicate(test_tenant, idp):
    """Second POST with same email (different / no externalId) merges."""
    payload_1, c1 = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "shared@example.test"},
        location_builder=_location_builder,
    )
    payload_2, c2 = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "shared@example.test", "externalId": "okta-late"},
        location_builder=_location_builder,
    )
    assert c1 is True and c2 is False
    assert payload_1["id"] == payload_2["id"]


def test_create_canonicalises_email_for_merge_lookup(test_tenant, idp):
    """Case-different repeats of the same email merge."""
    payload_1, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "Mixed.Case@Example.Test"},
        location_builder=_location_builder,
    )
    payload_2, c2 = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "mixed.case@example.test"},
        location_builder=_location_builder,
    )
    assert c2 is False
    assert payload_1["id"] == payload_2["id"]


# ---------------------------------------------------------------------------
# Replace (PUT)
# ---------------------------------------------------------------------------


def test_replace_user_changes_name_and_attribute(test_tenant, idp):
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {
            "userName": "put-target@example.test",
            "name": {"givenName": "Old", "familyName": "Name"},
        },
        location_builder=_location_builder,
    )
    user_id = payload["id"]

    replace_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        user_id,
        {
            "userName": "put-target@example.test",
            "name": {"givenName": "New", "familyName": "Name"},
            "active": True,
        },
        location_builder=_location_builder,
    )

    row = database.users.get_user_by_id(str(test_tenant["id"]), user_id)
    assert row["first_name"] == "New"


def test_replace_user_with_active_false_deactivates(test_tenant, idp):
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "to-deactivate@example.test"},
        location_builder=_location_builder,
    )
    user_id = payload["id"]
    replace_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        user_id,
        {"userName": "to-deactivate@example.test", "active": False},
        location_builder=_location_builder,
    )
    row = database.users.get_user_by_id(str(test_tenant["id"]), user_id)
    assert row["is_inactivated"] is True


def test_replace_user_reactivates_on_active_true(test_tenant, idp):
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "to-reactivate@example.test"},
        location_builder=_location_builder,
    )
    user_id = payload["id"]
    # Soft-delete first.
    soft_delete_user(str(test_tenant["id"]), str(idp["id"]), user_id)
    assert database.users.get_user_by_id(str(test_tenant["id"]), user_id)["is_inactivated"] is True

    replace_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        user_id,
        {"userName": "to-reactivate@example.test", "active": True},
        location_builder=_location_builder,
    )
    row = database.users.get_user_by_id(str(test_tenant["id"]), user_id)
    assert row["is_inactivated"] is False


# ---------------------------------------------------------------------------
# PATCH
# ---------------------------------------------------------------------------


def test_patch_user_disable_marks_inactivated(test_tenant, idp):
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "patch-disable@example.test"},
        location_builder=_location_builder,
    )
    user_id = payload["id"]
    patch_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        user_id,
        {"Operations": [{"op": "replace", "path": "active", "value": False}]},
        location_builder=_location_builder,
    )
    assert database.users.get_user_by_id(str(test_tenant["id"]), user_id)["is_inactivated"] is True


def test_patch_user_bumps_updated_at(test_tenant, idp):
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "patch-bump@example.test"},
        location_builder=_location_builder,
    )
    user_id = payload["id"]
    before = database.fetchone(
        str(test_tenant["id"]),
        "select updated_at from users where id = :id",
        {"id": user_id},
    )["updated_at"]
    time.sleep(0.05)
    patch_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        user_id,
        {"Operations": [{"op": "replace", "path": "displayName", "value": "Patched"}]},
        location_builder=_location_builder,
    )
    after = database.fetchone(
        str(test_tenant["id"]),
        "select updated_at from users where id = :id",
        {"id": user_id},
    )["updated_at"]
    assert after > before


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------


def test_soft_delete_inactivates_but_preserves_email(test_tenant, idp):
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "delete-me@example.test"},
        location_builder=_location_builder,
    )
    user_id = payload["id"]
    soft_delete_user(str(test_tenant["id"]), str(idp["id"]), user_id)

    row = database.users.get_user_by_id(str(test_tenant["id"]), user_id)
    assert row["is_inactivated"] is True
    # Email is preserved (admin can reactivate later without re-importing).
    primary = database.user_emails.get_primary_email(str(test_tenant["id"]), user_id)
    assert primary is not None


def test_soft_delete_then_create_with_same_email_reactivates_via_merge(test_tenant, idp):
    """The classic IdP "user came back" flow: soft-delete + re-create.

    Recreating via SCIM POST with the same email finds the inactivated
    user via the canonical-email lookup. The merge doesn't automatically
    reactivate -- the IdP must send `active=true` -- so we verify the
    merge case explicitly.
    """
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "comeback@example.test"},
        location_builder=_location_builder,
    )
    user_id = payload["id"]
    soft_delete_user(str(test_tenant["id"]), str(idp["id"]), user_id)

    payload_2, created = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "comeback@example.test", "active": True},
        location_builder=_location_builder,
    )
    assert created is False
    assert payload_2["id"] == user_id
    row = database.users.get_user_by_id(str(test_tenant["id"]), user_id)
    assert row["is_inactivated"] is False


def test_create_then_event_log_records_scim_user_received(test_tenant, idp):
    """Verify the event row exists so the outbound SCIM dispatch can fan out."""
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "evlog@example.test", "externalId": "okta-evlog"},
        location_builder=_location_builder,
    )
    user_id = payload["id"]
    events = database.fetchall(
        str(test_tenant["id"]),
        """
        select event_type
        from event_logs
        where artifact_id = :id and event_type = 'scim_user_received'
        """,
        {"id": user_id},
    )
    assert len(events) >= 1


def test_soft_delete_records_scim_user_deactivated_event(test_tenant, idp):
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "dx@example.test"},
        location_builder=_location_builder,
    )
    user_id = payload["id"]
    soft_delete_user(str(test_tenant["id"]), str(idp["id"]), user_id)
    events = database.fetchall(
        str(test_tenant["id"]),
        """
        select event_type
        from event_logs
        where artifact_id = :id and event_type = 'scim_user_deactivated'
        """,
        {"id": user_id},
    )
    assert len(events) >= 1


def test_reactivate_records_scim_user_reactivated_event(test_tenant, idp):
    """An active=true transition that re-enables a disabled account emits a
    dedicated security-tier event, mirroring the deactivate branch."""
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "rx@example.test"},
        location_builder=_location_builder,
    )
    user_id = payload["id"]
    soft_delete_user(str(test_tenant["id"]), str(idp["id"]), user_id)
    replace_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        user_id,
        {"userName": "rx@example.test", "active": True},
        location_builder=_location_builder,
    )
    events = database.fetchall(
        str(test_tenant["id"]),
        """
        select event_type
        from event_logs
        where artifact_id = :id and event_type = 'scim_user_reactivated'
        """,
        {"id": user_id},
    )
    assert len(events) >= 1


# ---------------------------------------------------------------------------
# Event log: PUT / PATCH emit `scim_user_updated`
# (needed for outbound SCIM dispatch to fan changes out to downstream SPs).
# ---------------------------------------------------------------------------


def test_replace_user_records_scim_user_updated_event(test_tenant, idp):
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "put-evlog@example.test"},
        location_builder=_location_builder,
    )
    user_id = payload["id"]
    replace_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        user_id,
        {"userName": "put-evlog@example.test", "name": {"givenName": "X", "familyName": "Y"}},
        location_builder=_location_builder,
    )
    events = database.fetchall(
        str(test_tenant["id"]),
        """
        select m.metadata
        from event_logs e
        join event_log_metadata m on m.metadata_hash = e.metadata_hash
        where e.artifact_id = :id and e.event_type = 'scim_user_updated'
        """,
        {"id": user_id},
    )
    assert len(events) >= 1
    # Metadata shape required by outbound SCIM dispatch: includes verb + idp_id.
    md = events[-1]["metadata"]
    assert md["verb"] == "PUT"
    assert md["idp_id"] == str(idp["id"])


def test_patch_user_records_scim_user_updated_event_with_op_count(test_tenant, idp):
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "patch-evlog@example.test"},
        location_builder=_location_builder,
    )
    user_id = payload["id"]
    patch_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        user_id,
        {
            "Operations": [
                {"op": "replace", "path": "displayName", "value": "Patched"},
                {"op": "replace", "path": "name.givenName", "value": "Patched"},
            ]
        },
        location_builder=_location_builder,
    )
    events = database.fetchall(
        str(test_tenant["id"]),
        """
        select m.metadata
        from event_logs e
        join event_log_metadata m on m.metadata_hash = e.metadata_hash
        where e.artifact_id = :id and e.event_type = 'scim_user_updated'
        """,
        {"id": user_id},
    )
    assert len(events) >= 1
    md = events[-1]["metadata"]
    assert md["verb"] == "PATCH"
    assert md["ops"] == 2


# ---------------------------------------------------------------------------
# MFA preservation across SCIM soft-delete + reactivate.
#
# Acceptance criterion: "DELETE /Users soft-delete via existing inactivate
# flow; preserves MFA + history". Verify TOTP rows survive a soft-delete
# and remain usable after reactivate.
# ---------------------------------------------------------------------------


def test_soft_delete_preserves_mfa_totp_and_survives_reactivation(test_tenant, idp):
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "mfa-keeper@example.test"},
        location_builder=_location_builder,
    )
    user_id = payload["id"]

    # Enrol TOTP for this user (mirrors the user-self-service enrolment path).
    database.mfa.create_totp_secret(
        tenant_id=test_tenant["id"],
        user_id=user_id,
        secret_encrypted="fake-encrypted-secret",
        tenant_id_value=str(test_tenant["id"]),
    )
    database.mfa.verify_totp_secret(test_tenant["id"], user_id, "totp")
    assert database.mfa.get_verified_totp_secret(test_tenant["id"], user_id, "totp") is not None

    soft_delete_user(str(test_tenant["id"]), str(idp["id"]), user_id)
    # TOTP row still present after soft-delete.
    assert database.mfa.get_verified_totp_secret(test_tenant["id"], user_id, "totp") is not None

    # Reactivate via SCIM POST + active=true.
    replace_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        user_id,
        {"userName": "mfa-keeper@example.test", "active": True},
        location_builder=_location_builder,
    )
    row = database.users.get_user_by_id(str(test_tenant["id"]), user_id)
    assert row["is_inactivated"] is False
    # And the TOTP record is still there + verified.
    assert database.mfa.get_verified_totp_secret(test_tenant["id"], user_id, "totp") is not None


# ---------------------------------------------------------------------------
# externalId concurrency: a duplicate POST with the same externalId (and
# different email) must not create a second user. The lookup/write split
# means this depends on application-level idempotence rather than a DB
# constraint -- this test pins the happy-path serial case; the concurrent
# race is logged separately in `.claude/ISSUES.md`.
# ---------------------------------------------------------------------------


def test_repeated_create_with_same_external_id_different_email_merges(test_tenant, idp):
    p1, c1 = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "first-alias@example.test", "externalId": "shared-ext-99"},
        location_builder=_location_builder,
    )
    p2, c2 = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "second-alias@example.test", "externalId": "shared-ext-99"},
        location_builder=_location_builder,
    )
    assert c1 is True and c2 is False
    assert p1["id"] == p2["id"]


def test_partial_unique_index_blocks_duplicate_external_id_per_idp(test_tenant, idp):
    """The 0044 partial unique index prevents two users sharing one externalId.

    This is the database-level defence that lets `create_or_merge_user`'s
    retry-on-UniqueViolation handler converge on a single user even when
    concurrent POSTs miss the lookup. Without this index, the lookups in
    `_create_or_merge_user_attempt` and the writes that follow would be
    free to interleave and produce two WeftID users sharing one upstream
    externalId.
    """
    import psycopg.errors

    user_a = database.users.create_user(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        first_name="A",
        last_name="One",
        email=f"race-a-{uuid4().hex}@example.test",
    )
    user_b = database.users.create_user(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        first_name="B",
        last_name="Two",
        email=f"race-b-{uuid4().hex}@example.test",
    )
    database.user_idp_attributes.set_external_id(
        test_tenant["id"],
        str(test_tenant["id"]),
        str(user_a["user_id"]),
        str(idp["id"]),
        "racy-ext-id",
    )
    with pytest.raises(psycopg.errors.UniqueViolation):
        database.user_idp_attributes.set_external_id(
            test_tenant["id"],
            str(test_tenant["id"]),
            str(user_b["user_id"]),
            str(idp["id"]),
            "racy-ext-id",
        )


def test_create_or_merge_retries_on_unique_violation(test_tenant, idp, monkeypatch):
    """If a concurrent POST wins the race, the merge retries and converges.

    Simulates the race: the first `_create_or_merge_user_attempt` lookups
    miss, the create path raises UniqueViolation (because a concurrent
    POST landed between lookup and insert), and the wrapper retries. The
    second attempt's lookup now sees the row and goes through the merge
    branch.
    """
    import psycopg.errors
    from services.scim import inbound_write

    winner_payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "winner@example.test", "externalId": "race-winner"},
        location_builder=_location_builder,
    )
    winner_id = winner_payload["id"]

    real_attempt = inbound_write._create_or_merge_user_attempt
    calls = {"n": 0}

    def fake_attempt(tenant_id, idp_id_arg, payload, *, location_builder):
        calls["n"] += 1
        if calls["n"] == 1:
            # Race loser: act as if our lookups missed and the partial
            # unique index fired on insert.
            raise psycopg.errors.UniqueViolation("simulated race")
        return real_attempt(tenant_id, idp_id_arg, payload, location_builder=location_builder)

    monkeypatch.setattr(inbound_write, "_create_or_merge_user_attempt", fake_attempt)

    payload, created = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"userName": "loser-alias@example.test", "externalId": "race-winner"},
        location_builder=_location_builder,
    )
    assert calls["n"] == 2
    assert created is False
    assert payload["id"] == winner_id


# ---------------------------------------------------------------------------
# PUT name-field semantics (RFC 7644 §3.5.1 full-replace).
#
# Distinguishes three states:
# 1. Field absent       -> preserve existing.
# 2. Field present+set  -> use the supplied value.
# 3. Field present+""   -> honour as explicit SCIM clear.
#
# Regression guard against the bug where an absent givenName/familyName
# silently wrote the literal placeholder "SCIM" / "User" into the user
# record, clobbering real data on every partial-name PUT.
# ---------------------------------------------------------------------------


def test_replace_user_preserves_last_name_when_only_given_name_in_payload(test_tenant, idp):
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {
            "userName": "partial-given@example.test",
            "name": {"givenName": "Alice", "familyName": "Smith"},
        },
        location_builder=_location_builder,
    )
    user_id = payload["id"]

    replace_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        user_id,
        {
            "userName": "partial-given@example.test",
            "name": {"givenName": "Alicia"},
        },
        location_builder=_location_builder,
    )

    row = database.users.get_user_by_id(str(test_tenant["id"]), user_id)
    assert row["first_name"] == "Alicia"
    # familyName was absent from the payload -- the existing value must be
    # preserved. NEVER the literal placeholder "User".
    assert row["last_name"] == "Smith"


def test_replace_user_preserves_first_name_when_only_family_name_in_payload(test_tenant, idp):
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {
            "userName": "partial-family@example.test",
            "name": {"givenName": "Bob", "familyName": "Jones"},
        },
        location_builder=_location_builder,
    )
    user_id = payload["id"]

    replace_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        user_id,
        {
            "userName": "partial-family@example.test",
            "name": {"familyName": "Jonesy"},
        },
        location_builder=_location_builder,
    )

    row = database.users.get_user_by_id(str(test_tenant["id"]), user_id)
    assert row["last_name"] == "Jonesy"
    # givenName was absent from the payload -- preserve. NEVER "SCIM".
    assert row["first_name"] == "Bob"


def test_replace_user_with_no_name_block_preserves_both_fields(test_tenant, idp):
    """An absent `name` block (and no displayName) is "not specified", not "clear"."""
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {
            "userName": "no-name-block@example.test",
            "name": {"givenName": "Carol", "familyName": "Wong"},
        },
        location_builder=_location_builder,
    )
    user_id = payload["id"]

    # PUT with no `name` block at all.
    replace_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        user_id,
        {"userName": "no-name-block@example.test", "active": True},
        location_builder=_location_builder,
    )

    row = database.users.get_user_by_id(str(test_tenant["id"]), user_id)
    assert row["first_name"] == "Carol"
    assert row["last_name"] == "Wong"


def test_replace_user_with_empty_name_dict_preserves_both_fields(test_tenant, idp):
    """An empty `name={}` provides neither field -> preserve both (same as omitted)."""
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {
            "userName": "empty-name@example.test",
            "name": {"givenName": "Dana", "familyName": "Yu"},
        },
        location_builder=_location_builder,
    )
    user_id = payload["id"]

    replace_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        user_id,
        {"userName": "empty-name@example.test", "name": {}},
        location_builder=_location_builder,
    )

    row = database.users.get_user_by_id(str(test_tenant["id"]), user_id)
    assert row["first_name"] == "Dana"
    assert row["last_name"] == "Yu"


def test_replace_user_with_explicit_empty_family_name_clears_it(test_tenant, idp):
    """`familyName: ""` is an explicit SCIM clear per RFC 7644 §3.5.1.

    Distinguishes "present-but-empty" (clear) from "absent" (preserve).
    """
    payload, _ = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        {
            "userName": "clear-family@example.test",
            "name": {"givenName": "Eve", "familyName": "Adams"},
        },
        location_builder=_location_builder,
    )
    user_id = payload["id"]

    replace_user(
        str(test_tenant["id"]),
        str(idp["id"]),
        user_id,
        {
            "userName": "clear-family@example.test",
            "name": {"givenName": "Eve", "familyName": ""},
        },
        location_builder=_location_builder,
    )

    row = database.users.get_user_by_id(str(test_tenant["id"]), user_id)
    assert row["first_name"] == "Eve"
    # Explicit empty -> cleared. NOT the placeholder "User".
    assert row["last_name"] == ""


# ---------------------------------------------------------------------------
# Cross-IdP email-match merge (rebind).
#
# Iteration 3 decisions log: a POST to IdP-B with a userName whose
# canonical email already exists under IdP-A *rebinds* the existing user
# to IdP-B and merges the payload. This is the documented behaviour; we
# pin it here so a future refactor can't silently break it. The rebind
# now also emits a dedicated `scim_user_rebound` audit event carrying
# the previous binding (closes the audit-trail gap from the final review).
# ---------------------------------------------------------------------------


def test_cross_idp_email_match_rebinds_user_to_new_idp(test_tenant, test_user):
    idp_a = database.saml.create_identity_provider(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="IdP A",
        provider_type="generic",
        sp_entity_id=f"urn:test:{uuid4().hex}",
        created_by=str(test_user["id"]),
    )
    idp_b = database.saml.create_identity_provider(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="IdP B",
        provider_type="generic",
        sp_entity_id=f"urn:test:{uuid4().hex}",
        created_by=str(test_user["id"]),
    )

    # First POST: created under IdP A.
    payload_a, created_a = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp_a["id"]),
        {"userName": "alice@x.test"},
        location_builder=_location_builder,
    )
    assert created_a is True
    user_id = payload_a["id"]
    row_a = database.users.get_user_by_id(str(test_tenant["id"]), user_id)
    assert str(row_a["saml_idp_id"]) == str(idp_a["id"])

    # Second POST against IdP B, same canonical email, no externalId.
    # The email-match path drives the merge and rebinds to IdP B.
    payload_b, created_b = create_or_merge_user(
        str(test_tenant["id"]),
        str(idp_b["id"]),
        {"userName": "alice@x.test"},
        location_builder=_location_builder,
    )
    assert created_b is False
    assert payload_b["id"] == user_id

    row_b = database.users.get_user_by_id(str(test_tenant["id"]), user_id)
    # Rebound to IdP B per the iteration-3 cross-IdP rebind behaviour.
    assert str(row_b["saml_idp_id"]) == str(idp_b["id"])

    # The second POST's audit event records the merge against IdP B.
    events = database.fetchall(
        str(test_tenant["id"]),
        """
        select m.metadata
        from event_logs e
        join event_log_metadata m on m.metadata_hash = e.metadata_hash
        where e.artifact_id = :id and e.event_type = 'scim_user_received'
        order by e.created_at desc
        limit 1
        """,
        {"id": user_id},
    )
    assert len(events) == 1
    md = events[0]["metadata"]
    assert md["merged"] is True
    assert md["idp_id"] == str(idp_b["id"])

    # A dedicated rebind event records the move from IdP-A to IdP-B so
    # operators can filter for cross-IdP rebinds in the audit log.
    rebound = database.fetchall(
        str(test_tenant["id"]),
        """
        select m.metadata
        from event_logs e
        join event_log_metadata m on m.metadata_hash = e.metadata_hash
        where e.artifact_id = :id and e.event_type = 'scim_user_rebound'
        order by e.created_at desc
        limit 1
        """,
        {"id": user_id},
    )
    assert len(rebound) == 1
    assert rebound[0]["metadata"]["previous_idp_id"] == str(idp_a["id"])
    assert rebound[0]["metadata"]["idp_id"] == str(idp_b["id"])
