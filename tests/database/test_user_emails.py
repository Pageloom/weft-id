"""Tests for database.user_emails module."""


def test_get_primary_email(test_user):
    """Test retrieving a user's primary email."""
    import database

    email = database.user_emails.get_primary_email(test_user["tenant_id"], test_user["id"])

    assert email is not None
    assert email["email"] == test_user["email"]


def test_list_user_emails(test_user):
    """Test listing all emails for a user."""
    import database

    emails = database.user_emails.list_user_emails(test_user["tenant_id"], test_user["id"])

    assert len(emails) == 1
    assert emails[0]["email"] == test_user["email"]


def test_email_exists(test_user):
    """Test checking if an email exists."""
    import database

    exists = database.user_emails.email_exists(test_user["tenant_id"], test_user["email"])

    assert exists is True


def test_email_not_exists(test_tenant):
    """Test checking if a non-existent email exists."""
    import database

    exists = database.user_emails.email_exists(test_tenant["id"], "nonexistent@example.com")

    assert exists is False


def test_add_email(test_user):
    """Test adding a new email to a user."""
    import database

    new_email = f"secondary-{test_user['id']}@example.com"

    # Add the email
    result = database.user_emails.add_email(
        test_user["tenant_id"], test_user["id"], new_email, test_user["tenant_id"]
    )

    assert result is not None
    assert "id" in result
    assert "verify_nonce" in result

    # Verify it was added
    emails = database.user_emails.list_user_emails(test_user["tenant_id"], test_user["id"])

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
        test_user["tenant_id"], test_user["id"], new_email, test_user["tenant_id"]
    )

    email_id = result["id"]

    # Verify the email
    database.user_emails.verify_email(test_user["tenant_id"], email_id)

    # Check it's verified
    emails = database.user_emails.list_user_emails(test_user["tenant_id"], test_user["id"])

    verified_email = next(e for e in emails if e["email"] == new_email)
    assert verified_email["verified_at"] is not None


def test_set_primary_email(test_user):
    """Test setting a different email as primary."""
    import database

    new_email = f"newprimary-{test_user['id']}@example.com"

    # Add and verify new email
    result = database.user_emails.add_email(
        test_user["tenant_id"], test_user["id"], new_email, test_user["tenant_id"]
    )

    email_id = result["id"]

    database.user_emails.verify_email(test_user["tenant_id"], email_id)

    # Set as primary (need to unset current primary first to avoid constraint violation)
    # Get current emails to find and unset the current primary
    current_emails = database.user_emails.list_user_emails(test_user["tenant_id"], test_user["id"])
    current_primary = next((e for e in current_emails if e["is_primary"]), None)
    if current_primary:
        # Unset current primary by updating directly
        database.execute(
            test_user["tenant_id"],
            "UPDATE user_emails SET is_primary = false WHERE id = :email_id",
            {"email_id": current_primary["id"]},
        )

    # Now set the new one as primary
    database.user_emails.set_primary_email(test_user["tenant_id"], email_id)

    # Verify it's now primary
    primary = database.user_emails.get_primary_email(test_user["tenant_id"], test_user["id"])

    assert primary["email"] == new_email


def test_delete_email(test_user):
    """Test deleting a non-primary email."""
    import database

    email_to_delete = f"delete-{test_user['id']}@example.com"

    # Add email
    result = database.user_emails.add_email(
        test_user["tenant_id"], test_user["id"], email_to_delete, test_user["tenant_id"]
    )

    email_id = result["id"]

    # Verify it exists
    emails_before = database.user_emails.list_user_emails(test_user["tenant_id"], test_user["id"])
    assert any(e["email"] == email_to_delete for e in emails_before)

    # Delete it
    database.user_emails.delete_email(test_user["tenant_id"], email_id)

    # Verify it's gone
    emails_after = database.user_emails.list_user_emails(test_user["tenant_id"], test_user["id"])
    assert not any(e["email"] == email_to_delete for e in emails_after)


def test_get_user_with_primary_email(test_user):
    """Test getting user info with their primary email."""
    import database

    result = database.user_emails.get_user_with_primary_email(
        test_user["tenant_id"], test_user["id"]
    )

    assert result is not None
    assert result["id"] == test_user["id"]
    assert result["email"] == test_user["email"]


def test_get_email_by_id(test_user):
    """Test getting an email record by ID."""
    import database

    # Add a secondary email
    new_email = f"byid-{test_user['id']}@example.com"
    result = database.user_emails.add_email(
        test_user["tenant_id"], test_user["id"], new_email, test_user["tenant_id"]
    )
    email_id = result["id"]

    # Get the email by ID
    email_record = database.user_emails.get_email_by_id(
        test_user["tenant_id"], email_id, test_user["id"]
    )

    assert email_record is not None
    assert email_record["id"] == email_id
    assert email_record["is_primary"] is False
    assert email_record["verified_at"] is None


def test_get_email_for_verification(test_user):
    """Test getting email info for verification."""
    import database

    # Add an unverified email
    new_email = f"forverify-{test_user['id']}@example.com"
    result = database.user_emails.add_email(
        test_user["tenant_id"], test_user["id"], new_email, test_user["tenant_id"]
    )
    email_id = result["id"]

    # Get email for verification
    email_info = database.user_emails.get_email_for_verification(test_user["tenant_id"], email_id)

    assert email_info is not None
    assert email_info["id"] == email_id
    assert email_info["user_id"] == test_user["id"]
    assert email_info["email"] == new_email
    assert email_info["verified_at"] is None
    assert "verify_nonce" in email_info
    assert "set_password_nonce" in email_info
    assert email_info["set_password_nonce"] == 1


def test_increment_set_password_nonce(test_user):
    """Test incrementing the set_password_nonce to invalidate a set-password link."""
    import database

    # Add an email to get its ID
    new_email = f"spnonce-{test_user['id']}@example.com"
    result = database.user_emails.add_email(
        test_user["tenant_id"], test_user["id"], new_email, test_user["tenant_id"]
    )
    email_id = result["id"]

    # Confirm starting nonce is 1
    email_info = database.user_emails.get_email_for_verification(test_user["tenant_id"], email_id)
    assert email_info["set_password_nonce"] == 1

    # Increment the nonce
    rows = database.user_emails.increment_set_password_nonce(test_user["tenant_id"], email_id)
    assert rows == 1

    # Confirm it was incremented
    email_info = database.user_emails.get_email_for_verification(test_user["tenant_id"], email_id)
    assert email_info["set_password_nonce"] == 2


def test_add_verified_email_returns_set_password_nonce(test_user):
    """Test that add_verified_email returns set_password_nonce in its result."""
    import database

    new_email = f"verified-sp-{test_user['id']}@example.com"
    result = database.user_emails.add_verified_email(
        tenant_id=test_user["tenant_id"],
        user_id=str(test_user["id"]),
        email=new_email,
        tenant_id_value=str(test_user["tenant_id"]),
    )

    assert result is not None
    assert "set_password_nonce" in result
    assert result["set_password_nonce"] == 1


def test_get_email_with_nonce(test_user):
    """Test getting email with verification nonce."""
    import database

    # Add a new email
    new_email = f"withnonce-{test_user['id']}@example.com"
    result = database.user_emails.add_email(
        test_user["tenant_id"], test_user["id"], new_email, test_user["tenant_id"]
    )
    email_id = result["id"]
    original_nonce = result["verify_nonce"]

    # Get email with nonce
    email_info = database.user_emails.get_email_with_nonce(
        test_user["tenant_id"], email_id, test_user["id"]
    )

    assert email_info is not None
    assert email_info["id"] == email_id
    assert email_info["email"] == new_email
    assert email_info["verify_nonce"] == original_nonce


def test_unset_primary_emails(test_user):
    """Test unsetting all primary email flags for a user."""
    import database

    # Verify user has a primary email
    primary_before = database.user_emails.get_primary_email(test_user["tenant_id"], test_user["id"])
    assert primary_before is not None

    # Unset all primary emails
    database.user_emails.unset_primary_emails(test_user["tenant_id"], test_user["id"])

    # Verify no primary email exists
    emails = database.user_emails.list_user_emails(test_user["tenant_id"], test_user["id"])
    assert not any(e["is_primary"] for e in emails)


# =============================================================================
# Email Anonymization Tests
# =============================================================================


def test_anonymize_user_emails(test_user):
    """Test anonymizing user email addresses."""
    import database

    # Add a secondary email
    new_email = f"secondary-anon-{test_user['id']}@example.com"
    database.user_emails.add_email(
        test_user["tenant_id"], test_user["id"], new_email, test_user["tenant_id"]
    )

    # Get emails before
    emails_before = database.user_emails.list_user_emails(test_user["tenant_id"], test_user["id"])
    assert len(emails_before) == 2

    # Anonymize emails
    rows_affected = database.user_emails.anonymize_user_emails(
        test_user["tenant_id"], test_user["id"]
    )
    assert rows_affected == 2

    # Check emails after
    emails_after = database.user_emails.list_user_emails(test_user["tenant_id"], test_user["id"])
    assert len(emails_after) == 2

    for email in emails_after:
        # Check email format
        assert email["email"].startswith("anon-")
        assert email["email"].endswith("@anonymized.example.com")
        # Check verified_at is cleared
        assert email["verified_at"] is None
