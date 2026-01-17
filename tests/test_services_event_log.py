"""Tests for event logging integration in service layer.

These tests verify that service layer write operations correctly log events.
For unit tests, we mock the database and verify log_event is called.
"""

from datetime import UTC
from unittest.mock import patch
from uuid import uuid4


def test_user_create_logs_event(make_requesting_user, make_user_dict, make_email_dict):
    """Test that creating a user logs an event."""
    from schemas.api import UserCreate
    from services import users

    tenant_id = str(uuid4())
    super_admin = make_user_dict(tenant_id=tenant_id, role="super_admin")
    requesting_user = make_requesting_user(
        user_id=super_admin["id"],
        tenant_id=tenant_id,
        role="super_admin",
    )

    new_user_id = str(uuid4())
    unique_email = f"newuser-{uuid4().hex[:8]}@example.com"
    user_data = UserCreate(
        first_name="New",
        last_name="User",
        email=unique_email,
        role="member",
    )

    new_user = make_user_dict(
        user_id=new_user_id,
        tenant_id=tenant_id,
        first_name="New",
        last_name="User",
        email=unique_email,
        role="member",
    )
    new_email = make_email_dict(user_id=new_user_id, email=unique_email)

    with patch("services.users.database") as mock_db, \
         patch("services.users.track_activity"), \
         patch("services.users.log_event") as mock_log:
        # Email check - no existing email
        mock_db.user_emails.email_exists.return_value = False
        # User creation - returns user_id not id
        mock_db.users.create_user.return_value = {"user_id": new_user_id}
        mock_db.user_emails.create_email.return_value = {"id": str(uuid4())}
        # Privileged domains check
        mock_db.privileged_domains.list_domains.return_value = []
        # For the return value - get_user call
        mock_db.users.get_user_by_id.return_value = new_user
        mock_db.user_emails.list_emails_for_user.return_value = [new_email]
        mock_db.user_emails.get_primary_email.return_value = new_email
        mock_db.users.is_service_user.return_value = False

        users.create_user(requesting_user, user_data)

        # Verify log_event was called for user creation
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["artifact_type"] == "user"
        assert call_kwargs["event_type"] == "user_created"
        assert call_kwargs["metadata"]["role"] == "member"

def test_user_update_logs_event(make_requesting_user, make_user_dict):
    """Test that updating a user logs an event."""
    from schemas.api import UserUpdate
    from services import users

    tenant_id = str(uuid4())
    admin = make_user_dict(tenant_id=tenant_id, role="admin")
    target_user = make_user_dict(tenant_id=tenant_id, role="member")
    requesting_user = make_requesting_user(
        user_id=admin["id"],
        tenant_id=tenant_id,
        role="admin",
    )

    user_update = UserUpdate(
        first_name="Updated",
        last_name="Name",
    )

    with patch("services.users.database") as mock_db, \
         patch("services.users.track_activity"), \
         patch("services.users.log_event") as mock_log:
        mock_db.users.get_user_by_id.return_value = target_user
        mock_db.users.update_user.return_value = None
        mock_db.user_emails.get_primary_email.return_value = {"email": target_user["email"]}

        users.update_user(requesting_user, target_user["id"], user_update)

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["artifact_type"] == "user"
        assert call_kwargs["event_type"] == "user_updated"
        assert "changes" in call_kwargs["metadata"]

def test_user_inactivate_logs_event(make_requesting_user, make_user_dict, make_email_dict):
    """Test that inactivating a user logs an event."""
    from services import users

    tenant_id = str(uuid4())
    admin = make_user_dict(tenant_id=tenant_id, role="admin")
    target_user = make_user_dict(tenant_id=tenant_id, role="member")
    requesting_user = make_requesting_user(
        user_id=admin["id"],
        tenant_id=tenant_id,
        role="admin",
    )

    target_email = make_email_dict(user_id=target_user["id"])

    with patch("services.users.database") as mock_db, \
         patch("services.users.track_activity"), \
         patch("services.users.log_event") as mock_log:
        mock_db.users.get_user_by_id.return_value = target_user
        # Not a service user
        mock_db.users.is_service_user.return_value = False
        mock_db.users.inactivate_user.return_value = None
        mock_db.user_emails.list_emails_for_user.return_value = [target_email]
        mock_db.user_emails.get_primary_email.return_value = target_email
        mock_db.user_emails.update_email.return_value = None

        users.inactivate_user(requesting_user, target_user["id"])

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["artifact_type"] == "user"
        assert call_kwargs["event_type"] == "user_inactivated"

def test_user_reactivate_logs_event(make_requesting_user, make_user_dict, make_email_dict):
    """Test that reactivating a user logs an event."""
    from services import users

    tenant_id = str(uuid4())
    admin = make_user_dict(tenant_id=tenant_id, role="admin")
    target_user = make_user_dict(tenant_id=tenant_id, role="member", is_inactivated=True)
    target_email = make_email_dict(user_id=target_user["id"])
    requesting_user = make_requesting_user(
        user_id=admin["id"],
        tenant_id=tenant_id,
        role="admin",
    )

    with patch("services.users.database") as mock_db, \
         patch("services.users.track_activity"), \
         patch("services.users.log_event") as mock_log:
        mock_db.users.get_user_by_id.return_value = target_user
        mock_db.users.reactivate_user.return_value = None
        # For the return value (get_user call)
        mock_db.user_emails.list_emails_for_user.return_value = [target_email]
        mock_db.user_emails.get_primary_email.return_value = target_email
        mock_db.users.is_service_user.return_value = False

        users.reactivate_user(requesting_user, target_user["id"])

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["artifact_type"] == "user"
        assert call_kwargs["event_type"] == "user_reactivated"

def test_privileged_domain_add_logs_event(make_requesting_user):
    """Test that adding a privileged domain logs an event."""
    from schemas.settings import PrivilegedDomainCreate
    from services import settings

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    unique_domain = f"test-{uuid4().hex[:8]}.example.com"
    domain_data = PrivilegedDomainCreate(domain=unique_domain)
    domain_id = str(uuid4())

    with patch("services.settings.database") as mock_db, \
         patch("services.settings.track_activity"), \
         patch("services.settings.log_event") as mock_log:
        # Check domain doesn't exist
        mock_db.settings.privileged_domain_exists.return_value = False
        # Create domain - doesn't need return value
        mock_db.settings.add_privileged_domain.return_value = None
        from datetime import datetime

        # Fetch created domain after creation
        mock_db.settings.list_privileged_domains.return_value = [
            {
                "id": domain_id,
                "domain": unique_domain,
                "first_name": None,
                "last_name": None,
                "created_at": datetime.now(UTC),
            }
        ]

        settings.add_privileged_domain(requesting_user, domain_data)

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["artifact_type"] == "privileged_domain"
        assert call_kwargs["event_type"] == "privileged_domain_added"
        assert call_kwargs["metadata"]["domain"] == unique_domain

def test_privileged_domain_delete_logs_event(make_requesting_user):
    """Test that deleting a privileged domain logs an event."""
    from services import settings

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    domain_id = str(uuid4())
    unique_domain = f"delete-{uuid4().hex[:8]}.example.com"

    with patch("services.settings.database") as mock_db, \
         patch("services.settings.track_activity"), \
         patch("services.settings.log_event") as mock_log:
        # Domain lookup returns list of domains
        mock_db.settings.list_privileged_domains.return_value = [
            {"id": domain_id, "domain": unique_domain}
        ]
        mock_db.settings.delete_privileged_domain.return_value = None

        settings.delete_privileged_domain(requesting_user, domain_id)

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["artifact_type"] == "privileged_domain"
        assert call_kwargs["event_type"] == "privileged_domain_deleted"
        assert call_kwargs["metadata"]["domain"] == unique_domain

def test_tenant_settings_update_logs_event(make_requesting_user):
    """Test that updating tenant settings logs an event."""
    from schemas.settings import TenantSecuritySettingsUpdate
    from services import settings

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")

    settings_update = TenantSecuritySettingsUpdate(
        session_timeout_seconds=7200,
    )

    with patch("services.settings.database") as mock_db, \
         patch("services.settings.track_activity"), \
         patch("services.settings.log_event") as mock_log:
        # Mock getting current settings to calculate changes
        mock_db.tenant_settings.get_settings.return_value = {
            "session_timeout_seconds": 3600,
            "require_mfa": False,
        }
        mock_db.tenant_settings.update_settings.return_value = None

        settings.update_security_settings(requesting_user, settings_update)

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["artifact_type"] == "tenant_settings"
        assert call_kwargs["event_type"] == "tenant_settings_updated"
        assert "changes" in call_kwargs["metadata"]

def test_oauth2_client_created_logs_event(make_requesting_user):
    """Test that creating an OAuth2 client logs an event."""
    from services import oauth2

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    client_id = str(uuid4())
    unique_name = f"Test Client {uuid4().hex[:8]}"

    with patch("services.oauth2.database") as mock_db, \
         patch("services.oauth2.log_event") as mock_log:
        mock_db.oauth2.create_normal_client.return_value = {
            "id": client_id,
            "name": unique_name,
            "client_id": f"client_{client_id[:8]}",
            "client_secret": "secret123",
        }

        oauth2.create_normal_client(
            tenant_id=tenant_id,
            name=unique_name,
            redirect_uris=["http://localhost:3000/callback"],
            created_by=admin_id,
        )

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["artifact_type"] == "oauth2_client"
        assert call_kwargs["event_type"] == "oauth2_client_created"
        assert call_kwargs["metadata"]["name"] == unique_name
        assert call_kwargs["metadata"]["type"] == "normal"

def test_log_event_helper_function(make_requesting_user):
    """Test the log_event helper function directly."""
    from services.event_log import log_event

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    unique_event_type = f"test_helper_{uuid4().hex[:8]}"

    with patch("services.event_log.database") as mock_db, \
         patch("services.event_log.track_activity"):
        mock_db.event_log.create_event.return_value = None

        log_event(
            tenant_id=tenant_id,
            actor_user_id=user_id,
            artifact_type="test",
            artifact_id=user_id,
            event_type=unique_event_type,
            metadata={"test": True},
        )

        mock_db.event_log.create_event.assert_called_once()
        call_kwargs = mock_db.event_log.create_event.call_args.kwargs
        assert call_kwargs["tenant_id"] == tenant_id
        assert call_kwargs["actor_user_id"] == user_id
        assert call_kwargs["artifact_type"] == "test"
        assert call_kwargs["event_type"] == unique_event_type
        assert call_kwargs["combined_metadata"]["test"] is True

def test_log_event_does_not_raise_on_failure(make_requesting_user):
    """Test that log_event fails silently and doesn't disrupt operations."""
    from services.event_log import log_event

    with patch("services.event_log.database") as mock_db, \
         patch("services.event_log.track_activity"):
        # Make the database call raise an exception
        mock_db.event_log.create_event.side_effect = Exception("Database error")

        # This should not raise even when database fails
        log_event(
            tenant_id="invalid-uuid",
            actor_user_id=str(uuid4()),
            artifact_type="test",
            artifact_id=str(uuid4()),
            event_type="test_failure",
        )

        # If we get here, the function didn't raise
        assert True


# --- Authorization Failure Logging Tests ---


def test_mfa_require_admin_logs_authorization_denied(make_requesting_user):
    """Test that _require_admin in MFA service logs authorization denied events."""
    from services.exceptions import ForbiddenError
    from services import mfa
    import pytest

    tenant_id = str(uuid4())
    member_user = make_requesting_user(
        tenant_id=tenant_id,
        role="member",  # Not an admin
    )

    with patch("services.mfa.log_event") as mock_log:
        with pytest.raises(ForbiddenError) as exc_info:
            mfa._require_admin(member_user)

        assert exc_info.value.code == "admin_required"
        # Verify authorization_denied was logged
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["event_type"] == "authorization_denied"
        assert call_kwargs["metadata"]["required_role"] == "admin"
        assert call_kwargs["metadata"]["actual_role"] == "member"
        assert call_kwargs["metadata"]["service"] == "mfa"


def test_saml_require_super_admin_logs_authorization_denied(make_requesting_user):
    """Test that _require_super_admin in SAML service logs authorization denied events."""
    from services.exceptions import ForbiddenError
    from services import saml
    import pytest

    tenant_id = str(uuid4())
    admin_user = make_requesting_user(
        tenant_id=tenant_id,
        role="admin",  # Admin but not super_admin
    )

    with patch("services.saml.log_event") as mock_log:
        with pytest.raises(ForbiddenError) as exc_info:
            saml._require_super_admin(admin_user)

        assert exc_info.value.code == "super_admin_required"
        # Verify authorization_denied was logged
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["event_type"] == "authorization_denied"
        assert call_kwargs["metadata"]["required_role"] == "super_admin"
        assert call_kwargs["metadata"]["actual_role"] == "admin"
        assert call_kwargs["metadata"]["service"] == "saml"


def test_users_require_admin_logs_authorization_denied(make_requesting_user):
    """Test that _require_admin in users service logs authorization denied events."""
    from services.exceptions import ForbiddenError
    from services import users
    import pytest

    tenant_id = str(uuid4())
    member_user = make_requesting_user(
        tenant_id=tenant_id,
        role="member",
    )

    with patch("services.users.log_event") as mock_log:
        with pytest.raises(ForbiddenError) as exc_info:
            users._require_admin(member_user)

        assert exc_info.value.code == "admin_required"
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["event_type"] == "authorization_denied"
        assert call_kwargs["metadata"]["service"] == "users"


def test_users_require_super_admin_logs_authorization_denied(make_requesting_user):
    """Test that _require_super_admin in users service logs authorization denied events."""
    from services.exceptions import ForbiddenError
    from services import users
    import pytest

    tenant_id = str(uuid4())
    admin_user = make_requesting_user(
        tenant_id=tenant_id,
        role="admin",
    )

    with patch("services.users.log_event") as mock_log:
        with pytest.raises(ForbiddenError) as exc_info:
            users._require_super_admin(admin_user)

        assert exc_info.value.code == "super_admin_required"
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["event_type"] == "authorization_denied"
        assert call_kwargs["metadata"]["required_role"] == "super_admin"


def test_users_role_change_logs_authorization_denied(make_requesting_user, make_user_dict):
    """Test that unauthorized role change attempts are logged."""
    from services.exceptions import ForbiddenError
    from services import users
    from schemas.api import UserUpdate
    import pytest

    tenant_id = str(uuid4())
    admin_user = make_requesting_user(
        tenant_id=tenant_id,
        role="admin",  # Admin, not super_admin
    )
    target_user = make_user_dict(tenant_id=tenant_id, role="member")

    # Try to promote to admin (requires super_admin)
    user_update = UserUpdate(role="admin")

    with patch("services.users.database") as mock_db, \
         patch("services.users.track_activity"), \
         patch("services.users.log_event") as mock_log:
        mock_db.users.get_user_by_id.return_value = target_user

        with pytest.raises(ForbiddenError) as exc_info:
            users.update_user(admin_user, target_user["id"], user_update)

        assert exc_info.value.code == "super_admin_role_change_denied"
        # Verify authorization_denied was logged with role change details
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["event_type"] == "authorization_denied"
        assert call_kwargs["metadata"]["action"] == "role_change"
        assert call_kwargs["metadata"]["current_role"] == "member"
        assert call_kwargs["metadata"]["attempted_role"] == "admin"
