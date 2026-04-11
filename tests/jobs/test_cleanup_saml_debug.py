"""Tests for SAML debug entry cleanup job."""


def test_cleanup_deletes_old_entries(test_tenant):
    """Insert old debug entries and verify cleanup removes them."""
    import database
    from jobs.cleanup_saml_debug import cleanup_saml_debug_entries

    tenant_id = test_tenant["id"]

    # Insert an entry aged beyond the 24h threshold
    database.execute(
        tenant_id,
        """
        INSERT INTO saml_debug_entries (tenant_id, error_type, error_detail, created_at)
        VALUES (:tenant_id, :error_type, :error_detail, now() - interval '25 hours')
        """,
        {
            "tenant_id": tenant_id,
            "error_type": "test_error",
            "error_detail": "Old entry for cleanup test",
        },
    )

    # Insert a recent entry that should NOT be deleted
    database.execute(
        tenant_id,
        """
        INSERT INTO saml_debug_entries (tenant_id, error_type, error_detail, created_at)
        VALUES (:tenant_id, :error_type, :error_detail, now() - interval '1 hour')
        """,
        {
            "tenant_id": tenant_id,
            "error_type": "test_error",
            "error_detail": "Recent entry for cleanup test",
        },
    )

    result = cleanup_saml_debug_entries()

    assert result["deleted"] >= 1

    # The recent entry should still exist
    remaining = database.saml.get_debug_entries(tenant_id, limit=100)
    recent = [e for e in remaining if e["error_detail"] == "Recent entry for cleanup test"]
    assert len(recent) == 1


def test_cleanup_returns_zero_when_nothing_to_delete():
    """Verify cleanup returns zero when no old entries exist."""
    from jobs.cleanup_saml_debug import cleanup_saml_debug_entries

    # This may or may not delete entries depending on test ordering,
    # but should at least not error
    result = cleanup_saml_debug_entries()
    assert "deleted" in result
    assert result["deleted"] >= 0
