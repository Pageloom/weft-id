"""Database integration tests for password lifecycle hardening columns and functions."""

import database


def test_hibp_columns_initially_null(test_tenant, test_user):
    """HIBP monitoring columns are null for new users."""
    tid = test_tenant["id"]
    uid = str(test_user["id"])

    users = database.users.get_users_with_hibp_prefix(tid)
    user_ids = [str(u["id"]) for u in users]
    assert uid not in user_ids


def test_update_password_stores_hibp_data(test_tenant, test_user):
    """update_password stores HIBP prefix and HMAC."""
    tid = test_tenant["id"]
    uid = str(test_user["id"])

    valid_hash = "$argon2id$v=19$m=65536,t=3,p=4$" + "a" * 40
    database.users.update_password(
        tid,
        uid,
        valid_hash,
        hibp_prefix="ABCDE",
        hibp_check_hmac="f" * 64,
        policy_length_at_set=14,
        policy_score_at_set=3,
    )

    users = database.users.get_users_with_hibp_prefix(tid)
    user_ids = [str(u["id"]) for u in users]
    assert uid in user_ids

    user_data = next(u for u in users if str(u["id"]) == uid)
    assert user_data["hibp_prefix"] == "ABCDE"
    assert user_data["hibp_check_hmac"] == "f" * 64


def test_clear_hibp_data(test_tenant, test_user):
    """clear_hibp_data removes HIBP monitoring data."""
    tid = test_tenant["id"]
    uid = str(test_user["id"])

    valid_hash = "$argon2id$v=19$m=65536,t=3,p=4$" + "a" * 40
    database.users.update_password(
        tid,
        uid,
        valid_hash,
        hibp_prefix="ABCDE",
        hibp_check_hmac="f" * 64,
    )

    database.users.clear_hibp_data(tid, uid)

    users = database.users.get_users_with_hibp_prefix(tid)
    user_ids = [str(u["id"]) for u in users]
    assert uid not in user_ids


def test_update_password_stores_policy_at_set(test_tenant, test_user):
    """update_password stores the policy values in effect at set time."""
    tid = test_tenant["id"]
    uid = str(test_user["id"])

    valid_hash = "$argon2id$v=19$m=65536,t=3,p=4$" + "a" * 40
    database.users.update_password(
        tid,
        uid,
        valid_hash,
        policy_length_at_set=16,
        policy_score_at_set=4,
    )

    # Check via the weak policy query (this user should NOT appear if
    # the new policy is <= what they were set under)
    weak = database.users.get_users_with_weak_policy(tid, 16, 4)
    weak_ids = [str(u["id"]) for u in weak]
    assert uid not in weak_ids

    # But should appear if policy is tightened beyond their set values
    weak = database.users.get_users_with_weak_policy(tid, 18, 4)
    weak_ids = [str(u["id"]) for u in weak]
    assert uid in weak_ids


def test_get_users_with_weak_policy_length(test_tenant, test_user):
    """Detects users whose password_policy_length_at_set is below new minimum."""
    tid = test_tenant["id"]
    uid = str(test_user["id"])

    valid_hash = "$argon2id$v=19$m=65536,t=3,p=4$" + "a" * 40
    database.users.update_password(
        tid,
        uid,
        valid_hash,
        policy_length_at_set=14,
        policy_score_at_set=3,
    )

    # Policy tightened: length goes from 14 to 16
    weak = database.users.get_users_with_weak_policy(tid, 16, 3)
    weak_ids = [str(u["id"]) for u in weak]
    assert uid in weak_ids


def test_get_users_with_weak_policy_score(test_tenant, test_user):
    """Detects users whose password_policy_score_at_set is below new minimum."""
    tid = test_tenant["id"]
    uid = str(test_user["id"])

    valid_hash = "$argon2id$v=19$m=65536,t=3,p=4$" + "a" * 40
    database.users.update_password(
        tid,
        uid,
        valid_hash,
        policy_length_at_set=14,
        policy_score_at_set=3,
    )

    # Policy tightened: score goes from 3 to 4
    weak = database.users.get_users_with_weak_policy(tid, 14, 4)
    weak_ids = [str(u["id"]) for u in weak]
    assert uid in weak_ids


def test_get_users_with_weak_policy_excludes_already_flagged(test_tenant, test_user):
    """Users already flagged for reset are excluded from weak policy results."""
    tid = test_tenant["id"]
    uid = str(test_user["id"])

    valid_hash = "$argon2id$v=19$m=65536,t=3,p=4$" + "a" * 40
    database.users.update_password(
        tid,
        uid,
        valid_hash,
        policy_length_at_set=14,
        policy_score_at_set=3,
    )

    # Flag user for reset
    database.users.set_password_reset_required(tid, uid, True)

    # Should not appear since already flagged
    weak = database.users.get_users_with_weak_policy(tid, 20, 4)
    weak_ids = [str(u["id"]) for u in weak]
    assert uid not in weak_ids


def test_bulk_set_password_reset_required(test_tenant, test_user, test_admin_user):
    """Bulk flagging sets password_reset_required on multiple users."""
    tid = test_tenant["id"]
    uid1 = str(test_user["id"])
    uid2 = str(test_admin_user["id"])

    rows = database.users.bulk_set_password_reset_required(tid, [uid1, uid2])
    assert rows == 2

    user1 = database.users.get_user_by_id(tid, uid1)
    user2 = database.users.get_user_by_id(tid, uid2)
    assert user1["password_reset_required"] is True
    assert user2["password_reset_required"] is True


def test_bulk_set_empty_list(test_tenant):
    """Bulk flagging with empty list does nothing."""
    tid = test_tenant["id"]
    rows = database.users.bulk_set_password_reset_required(tid, [])
    assert rows == 0


def test_get_all_tenant_ids(test_tenant):
    """get_all_tenant_ids returns at least the test tenant."""
    tenants = database.security.get_all_tenant_ids()
    tenant_ids = [str(t["tenant_id"]) for t in tenants]
    assert str(test_tenant["id"]) in tenant_ids
