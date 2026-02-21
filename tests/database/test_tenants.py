"""Tests for database.tenants module."""


def test_get_tenant_by_subdomain(test_tenant):
    """Test retrieving a tenant by subdomain."""
    import database

    tenant = database.tenants.get_tenant_by_subdomain(test_tenant["subdomain"])

    assert tenant is not None
    assert tenant["id"] == test_tenant["id"]


def test_get_tenant_by_subdomain_not_found():
    """Test retrieving a non-existent tenant returns None."""
    import database

    tenant = database.tenants.get_tenant_by_subdomain("nonexistent-subdomain")

    assert tenant is None


def test_get_tenant_by_id(test_tenant):
    """Test retrieving a tenant by ID."""
    import database

    tenant = database.tenants.get_tenant_by_id(test_tenant["id"])

    assert tenant is not None
    assert tenant["id"] == test_tenant["id"]
    assert tenant["subdomain"] == test_tenant["subdomain"]


def test_get_tenant_by_id_not_found():
    """Test retrieving a non-existent tenant by ID returns None."""
    from uuid import uuid4

    import database

    tenant = database.tenants.get_tenant_by_id(uuid4())

    assert tenant is None
