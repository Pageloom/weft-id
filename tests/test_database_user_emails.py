"""Tests for database.user_emails module."""

import pytest


def test_get_primary_email(test_user):
    """Test retrieving a user's primary email."""
    import database

    email = database.user_emails.get_primary_email(
        test_user["tenant_id"],
        test_user["id"]
    )

    assert email is not None
    assert email["email"] == test_user["email"]


def test_list_user_emails(test_user):
    """Test listing all emails for a user."""
    import database

    emails = database.user_emails.list_user_emails(
        test_user["tenant_id"],
        test_user["id"]
    )

    assert len(emails) == 1
    assert emails[0]["email"] == test_user["email"]


def test_email_exists(test_user):
    """Test checking if an email exists."""
    import database

    exists = database.user_emails.email_exists(
        test_user["tenant_id"],
        test_user["email"]
    )

    assert exists is True


def test_email_not_exists(test_tenant):
    """Test checking if a non-existent email exists."""
    import database

    exists = database.user_emails.email_exists(
        test_tenant["id"],
        "nonexistent@example.com"
    )

    assert exists is False


def test_add_email(test_user):
    """Test adding a new email to a user."""
    import database

    new_email = f"secondary-{test_user['id']}@example.com"

    # Add the email
    result = database.user_emails.add_email(
        test_user["tenant_id"],
        test_user["id"],
        new_email,
        test_user["tenant_id"]
    )

    assert result is not None
    assert "id" in result
    assert "verify_nonce" in result

    # Verify it was added
    emails = database.user_emails.list_user_emails(
        test_user["tenant_id"],
        test_user["id"]
    )

    assert len(emails) == 2
    assert any(e["email"] == new_email for e in emails)

    # Verify new email is not primary and not verified
    new_email_record = next(e for e in emails if e["email"] == new_email)
    assert new_email_record["is_primary"] is False
    assert new_email_record["verified_at"] is None


def test_verify_email(test_user):
    """Test verifying an email."""
    import database

    new_email = f"verify-{test_user['id']}@example.com"

    # Add unverified email
    result = database.user_emails.add_email(
        test_user["tenant_id"],
        test_user["id"],
        new_email,
        test_user["tenant_id"]
    )

    email_id = result["id"]

    # Verify the email
    database.user_emails.verify_email(
        test_user["tenant_id"],
        email_id
    )

    # Check it's verified
    emails = database.user_emails.list_user_emails(
        test_user["tenant_id"],
        test_user["id"]
    )

    verified_email = next(e for e in emails if e["email"] == new_email)
    assert verified_email["verified_at"] is not None


def test_set_primary_email(test_user):
    """Test setting a different email as primary."""
    import database

    new_email = f"newprimary-{test_user['id']}@example.com"

    # Add and verify new email
    result = database.user_emails.add_email(
        test_user["tenant_id"],
        test_user["id"],
        new_email,
        test_user["tenant_id"]
    )

    email_id = result["id"]

    database.user_emails.verify_email(
        test_user["tenant_id"],
        email_id
    )

    # Set as primary (need to unset current primary first to avoid constraint violation)
    # Get current emails to find and unset the current primary
    current_emails = database.user_emails.list_user_emails(
        test_user["tenant_id"],
        test_user["id"]
    )
    current_primary = next((e for e in current_emails if e["is_primary"]), None)
    if current_primary:
        # Unset current primary by updating directly
        database.execute(
            test_user["tenant_id"],
            "UPDATE user_emails SET is_primary = false WHERE id = :email_id",
            {"email_id": current_primary["id"]}
        )

    # Now set the new one as primary
    database.user_emails.set_primary_email(
        test_user["tenant_id"],
        email_id
    )

    # Verify it's now primary
    primary = database.user_emails.get_primary_email(
        test_user["tenant_id"],
        test_user["id"]
    )

    assert primary["email"] == new_email


def test_delete_email(test_user):
    """Test deleting a non-primary email."""
    import database

    email_to_delete = f"delete-{test_user['id']}@example.com"

    # Add email
    result = database.user_emails.add_email(
        test_user["tenant_id"],
        test_user["id"],
        email_to_delete,
        test_user["tenant_id"]
    )

    email_id = result["id"]

    # Verify it exists
    emails_before = database.user_emails.list_user_emails(
        test_user["tenant_id"],
        test_user["id"]
    )
    assert any(e["email"] == email_to_delete for e in emails_before)

    # Delete it
    database.user_emails.delete_email(
        test_user["tenant_id"],
        email_id
    )

    # Verify it's gone
    emails_after = database.user_emails.list_user_emails(
        test_user["tenant_id"],
        test_user["id"]
    )
    assert not any(e["email"] == email_to_delete for e in emails_after)
