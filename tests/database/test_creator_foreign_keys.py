"""Foreign keys from a row to the user who created or last updated it.

Each spans (creator, tenant_id). A bare ON DELETE SET NULL would null
tenant_id too and fail, so deleting the user must null only the creator.
"""

import database


def test_no_composite_user_fk_nulls_tenant_id(test_tenant):
    """Every composite SET NULL foreign key to users names the column it nulls."""
    rows = database.fetchall(
        database.UNSCOPED,
        """
        select c.conname
        from pg_constraint c
        where c.contype = 'f'
          and c.confrelid = to_regclass('public.users')
          and c.confdeltype = 'n'
          and array_length(c.conkey, 1) > 1
          and (c.confdelsetcols is null
               or array_length(c.confdelsetcols, 1) <> array_length(c.conkey, 1) - 1)
        """,
        {},
    )
    assert rows == []


def test_deleting_a_service_provider_creator_keeps_the_sp(test_tenant, test_super_admin_user):
    """The user service's delete used to fail on the creator FK (regression)."""
    from services import users as users_service

    creator = database.fetchone(
        test_tenant["id"],
        """
        insert into users (tenant_id, first_name, last_name, role)
        values (:t, 'Former', 'Admin', 'admin') returning id
        """,
        {"t": test_tenant["id"]},
    )
    sp = database.service_providers.create_service_provider(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Kept SP",
        created_by=str(creator["id"]),
    )

    users_service.delete_user(
        {
            "id": str(test_super_admin_user["id"]),
            "tenant_id": str(test_tenant["id"]),
            "role": "super_admin",
        },
        str(creator["id"]),
    )

    row = database.fetchone(
        test_tenant["id"],
        "select created_by, tenant_id from service_providers where id = :id",
        {"id": str(sp["id"])},
    )
    assert row["created_by"] is None
    assert str(row["tenant_id"]) == str(test_tenant["id"])
