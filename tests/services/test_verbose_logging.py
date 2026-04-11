"""Tests for SAML verbose assertion logging feature.

Covers enable/disable toggle, expiry logic, and verbose entry storage.
"""

from datetime import UTC, datetime, timedelta

import pytest
from services.exceptions import ForbiddenError, NotFoundError
from services.types import RequestingUser


def _make_requesting_user(user: dict, tenant_id: str, role: str = None) -> RequestingUser:
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=role or user.get("role", "member"),
    )


def _verify_event_logged(tenant_id: str, event_type: str, artifact_id: str):
    import database

    events = database.event_log.list_events(tenant_id, limit=10)
    matching = [
        e
        for e in events
        if e["event_type"] == event_type and str(e["artifact_id"]) == str(artifact_id)
    ]
    assert len(matching) > 0, f"No events logged for {event_type} with artifact_id {artifact_id}"


@pytest.fixture
def test_idp(test_tenant, test_super_admin_user):
    """Create a test IdP for verbose logging tests."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    idp = saml_service.create_identity_provider(
        requesting_user,
        IdPCreate(
            name="Verbose Test IdP",
            provider_type="okta",
            entity_id="https://verbose-test.example.com/entity",
            sso_url="https://verbose-test.example.com/sso",
        ),
        base_url="https://test.weftid.localhost",
    )
    return idp


# =============================================================================
# Enable/Disable Toggle
# =============================================================================


def test_enable_verbose_logging_as_super_admin(test_tenant, test_super_admin_user, test_idp):
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    result = saml_service.enable_verbose_logging(requesting_user, test_idp.id)

    assert result.verbose_logging_enabled_at is not None
    assert result.verbose_logging_active is True
    _verify_event_logged(test_tenant["id"], "saml_idp_verbose_logging_enabled", test_idp.id)


def test_disable_verbose_logging_as_super_admin(test_tenant, test_super_admin_user, test_idp):
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Enable first
    saml_service.enable_verbose_logging(requesting_user, test_idp.id)

    # Then disable
    result = saml_service.disable_verbose_logging(requesting_user, test_idp.id)

    assert result.verbose_logging_enabled_at is None
    assert result.verbose_logging_active is False
    _verify_event_logged(test_tenant["id"], "saml_idp_verbose_logging_disabled", test_idp.id)


def test_enable_verbose_logging_requires_super_admin(test_tenant, test_admin_user, test_idp):
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(ForbiddenError) as exc_info:
        saml_service.enable_verbose_logging(requesting_user, test_idp.id)

    assert exc_info.value.code == "super_admin_required"


def test_disable_verbose_logging_requires_super_admin(test_tenant, test_admin_user, test_idp):
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(ForbiddenError) as exc_info:
        saml_service.disable_verbose_logging(requesting_user, test_idp.id)

    assert exc_info.value.code == "super_admin_required"


def test_enable_verbose_logging_idp_not_found(test_tenant, test_super_admin_user):
    from uuid import uuid4

    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    with pytest.raises(NotFoundError) as exc_info:
        saml_service.enable_verbose_logging(requesting_user, str(uuid4()))

    assert exc_info.value.code == "idp_not_found"


# =============================================================================
# Expiry Logic (Schema)
# =============================================================================


def test_verbose_logging_active_within_24h():
    from schemas.saml import IdPConfig

    config = IdPConfig(
        id="test",
        name="Test",
        provider_type="okta",
        entity_id=None,
        sso_url=None,
        slo_url=None,
        certificate_pem=None,
        metadata_url=None,
        metadata_xml=None,
        metadata_last_fetched_at=None,
        metadata_fetch_error=None,
        sp_entity_id="https://sp.example.com",
        sp_acs_url="https://sp.example.com/acs",
        attribute_mapping={"email": "email"},
        is_enabled=True,
        is_default=False,
        require_platform_mfa=False,
        jit_provisioning=False,
        trust_established=False,
        verbose_logging_enabled_at=datetime.now(UTC) - timedelta(hours=12),
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    assert config.verbose_logging_active is True


def test_verbose_logging_expired_after_24h():
    from schemas.saml import IdPConfig

    config = IdPConfig(
        id="test",
        name="Test",
        provider_type="okta",
        entity_id=None,
        sso_url=None,
        slo_url=None,
        certificate_pem=None,
        metadata_url=None,
        metadata_xml=None,
        metadata_last_fetched_at=None,
        metadata_fetch_error=None,
        sp_entity_id="https://sp.example.com",
        sp_acs_url="https://sp.example.com/acs",
        attribute_mapping={"email": "email"},
        is_enabled=True,
        is_default=False,
        require_platform_mfa=False,
        jit_provisioning=False,
        trust_established=False,
        verbose_logging_enabled_at=datetime.now(UTC) - timedelta(hours=25),
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    assert config.verbose_logging_active is False


def test_verbose_logging_inactive_when_none():
    from schemas.saml import IdPConfig

    config = IdPConfig(
        id="test",
        name="Test",
        provider_type="okta",
        entity_id=None,
        sso_url=None,
        slo_url=None,
        certificate_pem=None,
        metadata_url=None,
        metadata_xml=None,
        metadata_last_fetched_at=None,
        metadata_fetch_error=None,
        sp_entity_id="https://sp.example.com",
        sp_acs_url="https://sp.example.com/acs",
        attribute_mapping={"email": "email"},
        is_enabled=True,
        is_default=False,
        require_platform_mfa=False,
        jit_provisioning=False,
        trust_established=False,
        verbose_logging_enabled_at=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    assert config.verbose_logging_active is False


# =============================================================================
# is_verbose_logging_active helper
# =============================================================================


def test_is_verbose_logging_active_true(test_tenant, test_super_admin_user, test_idp):
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    saml_service.enable_verbose_logging(requesting_user, test_idp.id)

    assert saml_service.is_verbose_logging_active(test_tenant["id"], test_idp.id) is True


def test_is_verbose_logging_active_false_when_disabled(test_tenant, test_idp):
    from services import saml as saml_service

    assert saml_service.is_verbose_logging_active(test_tenant["id"], test_idp.id) is False


def test_is_verbose_logging_active_false_for_nonexistent_idp(test_tenant):
    from uuid import uuid4

    from services import saml as saml_service

    assert saml_service.is_verbose_logging_active(test_tenant["id"], str(uuid4())) is False


# =============================================================================
# Verbose Debug Entry Storage
# =============================================================================


def test_store_debug_entry_with_verbose_event_logging(test_tenant, test_idp):
    from services import saml as saml_service

    entry_id = saml_service.store_saml_debug_entry(
        tenant_id=test_tenant["id"],
        error_type="auth_failed",
        error_detail="Signature validation failed",
        idp_id=test_idp.id,
        idp_name=test_idp.name,
        verbose_event_logging=True,
    )

    assert entry_id is not None
    _verify_event_logged(test_tenant["id"], "saml_assertion_failed", test_idp.id)


def test_store_debug_entry_without_verbose_no_event(test_tenant, test_idp):
    import database
    from services import saml as saml_service

    # Get event count before
    events_before = database.event_log.list_events(test_tenant["id"], limit=100)
    failed_before = [e for e in events_before if e["event_type"] == "saml_assertion_failed"]

    saml_service.store_saml_debug_entry(
        tenant_id=test_tenant["id"],
        error_type="auth_failed",
        error_detail="Signature validation failed",
        idp_id=test_idp.id,
        idp_name=test_idp.name,
        verbose_event_logging=False,
    )

    # No new saml_assertion_failed events should have been created
    events_after = database.event_log.list_events(test_tenant["id"], limit=100)
    failed_after = [e for e in events_after if e["event_type"] == "saml_assertion_failed"]
    assert len(failed_after) == len(failed_before)


def test_store_debug_entry_returns_id(test_tenant, test_idp):
    from services import saml as saml_service

    entry_id = saml_service.store_saml_debug_entry(
        tenant_id=test_tenant["id"],
        error_type="expired",
        error_detail="Assertion expired",
        idp_id=test_idp.id,
        idp_name=test_idp.name,
    )

    assert entry_id is not None
    # Should be a valid UUID string
    from uuid import UUID

    UUID(entry_id)
