"""Database tests: ``erase_user_identity_data`` (part of anonymization).

Runs against the real schema, so a table the app user cannot delete from,
or a column that moved, fails here.
"""

import database

from tests.fixtures.identity_data import (
    ERASED_TABLES,
    count_rows,
    hibp_values,
    seed_identity_data,
)


def test_erases_every_identifying_row(test_tenant, test_user, test_admin_user):
    tid = str(test_tenant["id"])
    seed_identity_data(tid, test_user["id"], test_admin_user["id"])
    assert all(count_rows(tid, test_user["id"]).values())

    deleted = database.users.erase_user_identity_data(tid, str(test_user["id"]))

    assert set(deleted) == set(ERASED_TABLES)
    assert all(deleted.values())
    assert count_rows(tid, test_user["id"]) == dict.fromkeys(ERASED_TABLES, 0)
    assert hibp_values(tid, test_user["id"]) == (None, None)


def test_leaves_other_users_alone(test_tenant, test_user, test_admin_user):
    tid = str(test_tenant["id"])
    seed_identity_data(tid, test_admin_user["id"], test_admin_user["id"])

    database.users.erase_user_identity_data(tid, str(test_user["id"]))

    assert all(count_rows(tid, test_admin_user["id"]).values())
    assert hibp_values(tid, test_admin_user["id"]) == ("ABCDE", "hmac")


def test_nothing_to_erase(test_tenant, test_user):
    tid = str(test_tenant["id"])
    deleted = database.users.erase_user_identity_data(tid, str(test_user["id"]))
    assert deleted == dict.fromkeys(ERASED_TABLES, 0)
