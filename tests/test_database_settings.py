"""Tests for database.settings module."""

import pytest


def test_list_privileged_domains_empty(test_tenant):
    """Test listing privileged domains when none exist."""
    import database

    domains = database.settings.list_privileged_domains(test_tenant["id"])

    assert isinstance(domains, list)
    # Initially empty for new test tenant
    assert len(domains) == 0


def test_add_privileged_domain(test_tenant, test_user):
    """Test adding a privileged domain."""
    import database

    domain = "example.com"

    # Add the domain
    database.settings.add_privileged_domain(
        test_tenant["id"],
        domain,
        test_user["id"],
        test_tenant["id"]
    )

    # Verify it was added
    domains = database.settings.list_privileged_domains(test_tenant["id"])
    assert len(domains) == 1
    assert domains[0]["domain"] == domain


def test_privileged_domain_exists(test_tenant, test_user):
    """Test checking if a privileged domain exists."""
    import database

    domain = "test.com"

    # Initially doesn't exist
    exists = database.settings.privileged_domain_exists(test_tenant["id"], domain)
    assert exists is False

    # Add it
    database.settings.add_privileged_domain(
        test_tenant["id"],
        domain,
        test_user["id"],
        test_tenant["id"]
    )

    # Now it exists
    exists = database.settings.privileged_domain_exists(test_tenant["id"], domain)
    assert exists is True


def test_delete_privileged_domain(test_tenant, test_user):
    """Test deleting a privileged domain."""
    import database

    domain = "delete-me.com"

    # Add the domain
    database.settings.add_privileged_domain(
        test_tenant["id"],
        domain,
        test_user["id"],
        test_tenant["id"]
    )

    # Verify it exists
    exists = database.settings.privileged_domain_exists(test_tenant["id"], domain)
    assert exists is True

    # Get the domain ID
    domains = database.settings.list_privileged_domains(test_tenant["id"])
    domain_record = next(d for d in domains if d["domain"] == domain)
    domain_id = domain_record["id"]

    # Delete it
    database.settings.delete_privileged_domain(test_tenant["id"], domain_id)

    # Verify it's gone
    exists = database.settings.privileged_domain_exists(test_tenant["id"], domain)
    assert exists is False


def test_add_duplicate_privileged_domain(test_tenant, test_user):
    """Test that adding a duplicate domain raises constraint violation."""
    import database
    import psycopg

    domain = "duplicate.com"

    # Add the domain once
    database.settings.add_privileged_domain(
        test_tenant["id"],
        domain,
        test_user["id"],
        test_tenant["id"]
    )

    # Adding it again should raise unique constraint violation
    with pytest.raises(psycopg.errors.UniqueViolation):
        database.settings.add_privileged_domain(
            test_tenant["id"],
            domain,
            test_user["id"],
            test_tenant["id"]
        )
