"""Tests for the bulk change primary email job handlers."""

from unittest.mock import patch
from uuid import uuid4

# =============================================================================
# Handler Registration
# =============================================================================


def test_preview_handler_registered():
    """Preview handler is registered with the correct job type."""
    import jobs.bulk_change_primary_email  # noqa: F401
    from jobs.registry import get_handler

    handler = get_handler("bulk_primary_email_preview")
    assert handler is not None


def test_apply_handler_registered():
    """Apply handler is registered with the correct job type."""
    import jobs.bulk_change_primary_email  # noqa: F401
    from jobs.registry import get_handler

    handler = get_handler("bulk_primary_email_apply")
    assert handler is not None


# =============================================================================
# Preview Handler
# =============================================================================


def test_preview_computes_impact_for_each_user():
    """Preview handler computes impact and returns per-user results."""
    from jobs.bulk_change_primary_email import handle_bulk_primary_email_preview

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    email_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": str(uuid4()),
        "payload": {
            "items": [{"user_id": user_id, "new_primary_email": "new@example.com"}],
        },
    }

    impact = {
        "sp_impacts": [
            {"sp_id": "sp-1", "sp_name": "Slack", "impact": "will_change"},
        ],
        "routing_change": None,
        "summary": {"affected_sp_count": 1, "unaffected_sp_count": 0, "total_sp_count": 1},
    }

    with (
        patch("jobs.bulk_change_primary_email.database") as mock_db,
        patch("jobs.bulk_change_primary_email.compute_email_change_impact", return_value=impact),
    ):
        mock_db.users.get_user_by_id.return_value = {
            "id": user_id,
            "first_name": "Alice",
            "last_name": "Smith",
            "email": "old@example.com",
        }
        mock_db.user_emails.list_user_emails.return_value = [
            {
                "id": "primary-id",
                "email": "old@example.com",
                "is_primary": True,
                "verified_at": "2025-01-01",
            },
            {
                "id": email_id,
                "email": "new@example.com",
                "is_primary": False,
                "verified_at": "2025-01-01",
            },
        ]

        result = handle_bulk_primary_email_preview(task)

    assert result["totals"]["users_previewed"] == 1
    assert result["totals"]["users_with_sp_impact"] == 1
    assert len(result["user_results"]) == 1
    assert result["user_results"][0]["status"] == "ok"
    assert result["user_results"][0]["user_name"] == "Alice Smith"
    assert result["user_results"][0]["current_email"] == "old@example.com"


def test_preview_errors_on_missing_user():
    """Preview reports error when user not found."""
    from jobs.bulk_change_primary_email import handle_bulk_primary_email_preview

    task = {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "created_by": str(uuid4()),
        "payload": {
            "items": [{"user_id": "missing-id", "new_primary_email": "new@example.com"}],
        },
    }

    with patch("jobs.bulk_change_primary_email.database") as mock_db:
        mock_db.users.get_user_by_id.return_value = None

        result = handle_bulk_primary_email_preview(task)

    assert result["totals"]["errors"] == 1
    assert result["user_results"][0]["status"] == "error"
    assert result["user_results"][0]["error_reason"] == "User not found"


def test_preview_errors_on_unverified_email():
    """Preview reports error when target email is not a verified secondary."""
    from jobs.bulk_change_primary_email import handle_bulk_primary_email_preview

    user_id = str(uuid4())
    task = {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "created_by": str(uuid4()),
        "payload": {
            "items": [{"user_id": user_id, "new_primary_email": "unverified@example.com"}],
        },
    }

    with patch("jobs.bulk_change_primary_email.database") as mock_db:
        mock_db.users.get_user_by_id.return_value = {
            "id": user_id,
            "first_name": "Bob",
            "last_name": "Jones",
            "email": "old@example.com",
        }
        mock_db.user_emails.list_user_emails.return_value = [
            {
                "id": str(uuid4()),
                "email": "old@example.com",
                "is_primary": True,
                "verified_at": "2025-01-01",
            },
            {
                "id": str(uuid4()),
                "email": "unverified@example.com",
                "is_primary": False,
                "verified_at": None,
            },
        ]

        result = handle_bulk_primary_email_preview(task)

    assert result["totals"]["errors"] == 1
    assert "not a verified secondary" in result["user_results"][0]["error_reason"]


def test_preview_tracks_routing_changes():
    """Preview counts users with routing changes separately."""
    from jobs.bulk_change_primary_email import handle_bulk_primary_email_preview

    user_id = str(uuid4())
    task = {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "created_by": str(uuid4()),
        "payload": {
            "items": [{"user_id": user_id, "new_primary_email": "new@other.com"}],
        },
    }

    impact = {
        "sp_impacts": [],
        "routing_change": {"current_idp_name": "Okta", "new_idp_name": "Google"},
        "summary": {"affected_sp_count": 0, "unaffected_sp_count": 0, "total_sp_count": 0},
    }

    with (
        patch("jobs.bulk_change_primary_email.database") as mock_db,
        patch("jobs.bulk_change_primary_email.compute_email_change_impact", return_value=impact),
    ):
        mock_db.users.get_user_by_id.return_value = {
            "id": user_id,
            "first_name": "Carol",
            "last_name": "Lee",
            "email": "old@example.com",
        }
        mock_db.user_emails.list_user_emails.return_value = [
            {
                "id": str(uuid4()),
                "email": "new@other.com",
                "is_primary": False,
                "verified_at": "2025-01-01",
            },
        ]

        result = handle_bulk_primary_email_preview(task)

    assert result["totals"]["users_with_routing_change"] == 1


# =============================================================================
# Apply Handler
# =============================================================================


def test_apply_promotes_emails():
    """Apply handler promotes emails and logs events."""
    from jobs.bulk_change_primary_email import handle_bulk_primary_email_apply

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user_id = str(uuid4())
    email_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "payload": {
            "items": [
                {
                    "user_id": user_id,
                    "new_primary_email": "new@example.com",
                    "idp_disposition": "keep",
                }
            ],
        },
    }

    with (
        patch("jobs.bulk_change_primary_email.database") as mock_db,
        patch("jobs.bulk_change_primary_email.log_event") as mock_log,
        patch("jobs.bulk_change_primary_email.send_primary_email_changed_notification"),
    ):
        mock_db.users.get_user_by_id.return_value = {
            "id": user_id,
            "email": "old@example.com",
            "saml_idp_id": None,
        }
        mock_db.user_emails.list_user_emails.return_value = [
            {
                "id": email_id,
                "email": "new@example.com",
                "is_primary": False,
                "verified_at": "2025-01-01",
            },
        ]

        result = handle_bulk_primary_email_apply(task)

    assert result["promoted"] == 1
    assert result["errors"] == 0
    mock_db.user_emails.unset_primary_emails.assert_called_once_with(tenant_id, user_id)
    mock_db.user_emails.set_primary_email.assert_called_once_with(tenant_id, email_id)
    mock_log.assert_called_once()
    assert mock_log.call_args.kwargs["event_type"] == "primary_email_changed"


def test_apply_errors_on_missing_user():
    """Apply reports error when user not found."""
    from jobs.bulk_change_primary_email import handle_bulk_primary_email_apply

    task = {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "created_by": str(uuid4()),
        "payload": {
            "items": [
                {
                    "user_id": "missing-id",
                    "new_primary_email": "new@example.com",
                    "idp_disposition": "keep",
                }
            ],
        },
    }

    with (
        patch("jobs.bulk_change_primary_email.database") as mock_db,
        patch("jobs.bulk_change_primary_email.log_event"),
        patch("jobs.bulk_change_primary_email.send_primary_email_changed_notification"),
    ):
        mock_db.users.get_user_by_id.return_value = None

        result = handle_bulk_primary_email_apply(task)

    assert result["errors"] == 1
    assert result["details"][0]["reason"] == "User not found"


def test_apply_switch_idp_disposition():
    """Apply with 'switch' disposition updates user's IdP assignment."""
    from jobs.bulk_change_primary_email import handle_bulk_primary_email_apply

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    email_id = str(uuid4())
    new_idp_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": str(uuid4()),
        "payload": {
            "items": [
                {
                    "user_id": user_id,
                    "new_primary_email": "new@other-domain.com",
                    "idp_disposition": "switch",
                }
            ],
        },
    }

    with (
        patch("jobs.bulk_change_primary_email.database") as mock_db,
        patch("jobs.bulk_change_primary_email.log_event") as mock_log,
        patch("jobs.bulk_change_primary_email.send_primary_email_changed_notification"),
    ):
        mock_db.users.get_user_by_id.return_value = {
            "id": user_id,
            "email": "old@example.com",
            "saml_idp_id": "old-idp",
            "saml_idp_name": "Okta",
        }
        mock_db.user_emails.list_user_emails.return_value = [
            {
                "id": email_id,
                "email": "new@other-domain.com",
                "is_primary": False,
                "verified_at": "2025-01-01",
            },
        ]
        mock_db.saml.get_idp_for_domain.return_value = {
            "id": new_idp_id,
            "name": "Google Workspace",
        }

        result = handle_bulk_primary_email_apply(task)

    assert result["promoted"] == 1
    mock_db.users.saml_assignment.update_user_saml_idp.assert_called_once_with(
        tenant_id, user_id, new_idp_id
    )
    # Should have two log_event calls: primary_email_changed + user_saml_idp_assigned
    assert mock_log.call_count == 2
    event_types = [c.kwargs["event_type"] for c in mock_log.call_args_list]
    assert "primary_email_changed" in event_types
    assert "user_saml_idp_assigned" in event_types


def test_apply_remove_idp_disposition():
    """Apply with 'remove' disposition sets IdP to None."""
    from jobs.bulk_change_primary_email import handle_bulk_primary_email_apply

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    email_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": str(uuid4()),
        "payload": {
            "items": [
                {
                    "user_id": user_id,
                    "new_primary_email": "new@unbound.com",
                    "idp_disposition": "remove",
                }
            ],
        },
    }

    with (
        patch("jobs.bulk_change_primary_email.database") as mock_db,
        patch("jobs.bulk_change_primary_email.log_event") as mock_log,
        patch("jobs.bulk_change_primary_email.send_primary_email_changed_notification"),
    ):
        mock_db.users.get_user_by_id.return_value = {
            "id": user_id,
            "email": "old@example.com",
            "saml_idp_id": "old-idp",
            "saml_idp_name": "Okta",
        }
        mock_db.user_emails.list_user_emails.return_value = [
            {
                "id": email_id,
                "email": "new@unbound.com",
                "is_primary": False,
                "verified_at": "2025-01-01",
            },
        ]

        result = handle_bulk_primary_email_apply(task)

    assert result["promoted"] == 1
    mock_db.users.saml_assignment.update_user_saml_idp.assert_called_once_with(
        tenant_id, user_id, None
    )
    assert mock_log.call_count == 2


def test_apply_sends_notification():
    """Apply sends notification email to old primary address."""
    from jobs.bulk_change_primary_email import handle_bulk_primary_email_apply

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    email_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": str(uuid4()),
        "payload": {
            "items": [
                {
                    "user_id": user_id,
                    "new_primary_email": "new@example.com",
                    "idp_disposition": "keep",
                }
            ],
        },
    }

    with (
        patch("jobs.bulk_change_primary_email.database") as mock_db,
        patch("jobs.bulk_change_primary_email.log_event"),
        patch(
            "jobs.bulk_change_primary_email.send_primary_email_changed_notification"
        ) as mock_send,
    ):
        mock_db.users.get_user_by_id.return_value = {
            "id": user_id,
            "email": "old@example.com",
            "saml_idp_id": None,
        }
        mock_db.user_emails.list_user_emails.return_value = [
            {
                "id": "primary-id",
                "email": "old@example.com",
                "is_primary": True,
                "verified_at": "2025-01-01",
            },
            {
                "id": email_id,
                "email": "new@example.com",
                "is_primary": False,
                "verified_at": "2025-01-01",
            },
        ]

        handle_bulk_primary_email_apply(task)

    mock_send.assert_called_once_with(
        "old@example.com",
        "new@example.com",
        "System (bulk operation)",
        tenant_id=tenant_id,
    )
