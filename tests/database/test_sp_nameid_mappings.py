"""Integration tests for database.sp_nameid_mappings module.

These are integration tests that use a real database connection.
"""

import database


def _create_sp(tenant, user, name="Test SP"):
    """Create a service provider for testing."""
    return database.service_providers.create_service_provider(
        tenant_id=tenant["id"],
        tenant_id_value=str(tenant["id"]),
        name=name,
        created_by=str(user["id"]),
    )


# -- get_or_create_nameid_mapping ----------------------------------------------


def test_get_or_create_nameid_mapping_creates_new(test_tenant, test_user):
    """Test that get_or_create creates a mapping when none exists."""
    sp = _create_sp(test_tenant, test_user, name="NameID Create SP")

    result = database.sp_nameid_mappings.get_or_create_nameid_mapping(
        test_tenant["id"],
        str(test_tenant["id"]),
        str(test_user["id"]),
        str(sp["id"]),
    )

    assert result is not None
    assert str(result["user_id"]) == str(test_user["id"])
    assert str(result["sp_id"]) == str(sp["id"])
    assert result["nameid_value"] is not None
    # nameid_value should be a UUID-formatted string
    assert len(str(result["nameid_value"])) == 36
    assert result["id"] is not None
    assert result["created_at"] is not None


def test_get_or_create_nameid_mapping_idempotent(test_tenant, test_user):
    """Test that calling get_or_create twice returns the same mapping."""
    sp = _create_sp(test_tenant, test_user, name="NameID Idempotent SP")

    first = database.sp_nameid_mappings.get_or_create_nameid_mapping(
        test_tenant["id"],
        str(test_tenant["id"]),
        str(test_user["id"]),
        str(sp["id"]),
    )
    second = database.sp_nameid_mappings.get_or_create_nameid_mapping(
        test_tenant["id"],
        str(test_tenant["id"]),
        str(test_user["id"]),
        str(sp["id"]),
    )

    assert first["id"] == second["id"]
    assert first["nameid_value"] == second["nameid_value"]


def test_get_or_create_nameid_mapping_different_sps_get_different_mappings(test_tenant, test_user):
    """Test that the same user gets distinct mappings per SP."""
    sp_a = _create_sp(test_tenant, test_user, name="NameID SP A")
    sp_b = _create_sp(test_tenant, test_user, name="NameID SP B")

    mapping_a = database.sp_nameid_mappings.get_or_create_nameid_mapping(
        test_tenant["id"],
        str(test_tenant["id"]),
        str(test_user["id"]),
        str(sp_a["id"]),
    )
    mapping_b = database.sp_nameid_mappings.get_or_create_nameid_mapping(
        test_tenant["id"],
        str(test_tenant["id"]),
        str(test_user["id"]),
        str(sp_b["id"]),
    )

    # Different SPs get different mappings
    assert mapping_a["id"] != mapping_b["id"]
    assert mapping_a["nameid_value"] != mapping_b["nameid_value"]
