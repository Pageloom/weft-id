"""Tests for database.service_providers module.

These are integration tests that use a real database connection.
"""

from uuid import uuid4


def _create_sp(tenant_id, user_id, name="Test SP", **kwargs):
    """Helper to create a service provider with sensible defaults."""
    import database

    return database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        created_by=str(user_id),
        **kwargs,
    )


# -- create_service_provider ---------------------------------------------------


def test_create_service_provider(test_tenant, test_user):
    """Test creating a basic service provider."""
    sp = _create_sp(test_tenant["id"], test_user["id"], name="My SP")

    assert sp is not None
    assert sp["name"] == "My SP"
    assert sp["enabled"] is True
    assert sp["trust_established"] is False
    assert sp["nameid_format"] == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    assert str(sp["created_by"]) == str(test_user["id"])


def test_create_service_provider_with_jsonb_fields(test_tenant, test_user):
    """Test JSONB fields (attribute_mapping, sp_requested_attributes) round-trip."""
    attr_mapping = {"email": "user.email", "name": "user.displayName"}
    requested_attrs = [
        {"name": "email", "friendly_name": "Email", "required": True},
        {"name": "name", "friendly_name": "Display Name", "required": False},
    ]

    sp = _create_sp(
        test_tenant["id"],
        test_user["id"],
        name="JSONB SP",
        attribute_mapping=attr_mapping,
        sp_requested_attributes=requested_attrs,
    )

    assert sp is not None
    assert sp["attribute_mapping"] == attr_mapping
    assert sp["sp_requested_attributes"] == requested_attrs


def test_create_service_provider_with_all_fields(test_tenant, test_user):
    """Test creating an SP with all optional fields populated."""
    sp = _create_sp(
        test_tenant["id"],
        test_user["id"],
        name="Full SP",
        entity_id="https://sp.example.com/metadata",
        acs_url="https://sp.example.com/acs",
        certificate_pem="-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
        nameid_format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        metadata_xml="<md:EntityDescriptor/>",
        metadata_url="https://sp.example.com/metadata.xml",
        description="A fully configured SP",
        slo_url="https://sp.example.com/slo",
        trust_established=True,
    )

    assert sp is not None
    assert sp["entity_id"] == "https://sp.example.com/metadata"
    assert sp["acs_url"] == "https://sp.example.com/acs"
    assert sp["description"] == "A fully configured SP"
    assert sp["slo_url"] == "https://sp.example.com/slo"
    assert sp["trust_established"] is True
    assert sp["metadata_url"] == "https://sp.example.com/metadata.xml"


# -- get_service_provider / get_service_provider_by_entity_id ------------------


def test_get_service_provider(test_tenant, test_user):
    """Test retrieving an SP by ID."""
    import database

    sp = _create_sp(test_tenant["id"], test_user["id"], name="Get By ID")

    fetched = database.service_providers.get_service_provider(test_tenant["id"], sp["id"])

    assert fetched is not None
    assert fetched["id"] == sp["id"]
    assert fetched["name"] == "Get By ID"


def test_get_service_provider_not_found(test_tenant):
    """Test retrieving a nonexistent SP returns None."""
    import database

    result = database.service_providers.get_service_provider(test_tenant["id"], str(uuid4()))

    assert result is None


def test_get_service_provider_by_entity_id(test_tenant, test_user):
    """Test retrieving an SP by entity_id."""
    import database

    entity_id = f"https://sp-{uuid4().hex[:8]}.example.com/metadata"
    _create_sp(
        test_tenant["id"],
        test_user["id"],
        name="Entity ID SP",
        entity_id=entity_id,
    )

    fetched = database.service_providers.get_service_provider_by_entity_id(
        test_tenant["id"], entity_id
    )

    assert fetched is not None
    assert fetched["entity_id"] == entity_id
    assert fetched["name"] == "Entity ID SP"


def test_get_service_provider_by_entity_id_not_found(test_tenant):
    """Test retrieving by nonexistent entity_id returns None."""
    import database

    result = database.service_providers.get_service_provider_by_entity_id(
        test_tenant["id"], "https://nonexistent.example.com"
    )

    assert result is None


# -- list_service_providers ----------------------------------------------------


def test_list_service_providers(test_tenant, test_user):
    """Test listing SPs returns all in created_at desc order."""
    import database

    sp1 = _create_sp(test_tenant["id"], test_user["id"], name="SP First")
    sp2 = _create_sp(test_tenant["id"], test_user["id"], name="SP Second")

    sps = database.service_providers.list_service_providers(test_tenant["id"])

    assert len(sps) >= 2
    names = [s["name"] for s in sps]
    assert "SP First" in names
    assert "SP Second" in names

    # Most recent first
    ids = [s["id"] for s in sps]
    assert ids.index(sp2["id"]) < ids.index(sp1["id"])


def test_list_service_providers_empty(test_tenant):
    """Test listing SPs when none exist returns empty list."""
    import database

    sps = database.service_providers.list_service_providers(test_tenant["id"])

    assert sps == []


# -- update_service_provider ---------------------------------------------------


def test_update_service_provider(test_tenant, test_user):
    """Test updating allowed fields."""
    import database

    sp = _create_sp(test_tenant["id"], test_user["id"], name="Original Name")

    updated = database.service_providers.update_service_provider(
        test_tenant["id"], sp["id"], name="Updated Name", description="New desc"
    )

    assert updated is not None
    assert updated["name"] == "Updated Name"
    assert updated["description"] == "New desc"
    assert updated["updated_at"] is not None
    assert updated["updated_at"] > sp["created_at"]


def test_update_service_provider_jsonb(test_tenant, test_user):
    """Test updating attribute_mapping (JSONB serialization)."""
    import database

    sp = _create_sp(test_tenant["id"], test_user["id"], name="JSONB Update")

    new_mapping = {"email": "mail", "groups": "memberOf"}
    updated = database.service_providers.update_service_provider(
        test_tenant["id"], sp["id"], attribute_mapping=new_mapping
    )

    assert updated is not None
    assert updated["attribute_mapping"] == new_mapping

    # Verify persistence via fresh read
    fetched = database.service_providers.get_service_provider(test_tenant["id"], sp["id"])
    assert fetched["attribute_mapping"] == new_mapping


def test_update_service_provider_ignores_disallowed_fields(test_tenant, test_user):
    """Test that disallowed fields (entity_id, trust_established, etc.) are ignored."""
    import database

    sp = _create_sp(
        test_tenant["id"],
        test_user["id"],
        name="Disallowed Test",
        entity_id="https://original.example.com",
        trust_established=True,
    )

    updated = database.service_providers.update_service_provider(
        test_tenant["id"],
        sp["id"],
        entity_id="https://hacked.example.com",
        trust_established=False,
        certificate_pem="INJECTED",
    )

    assert updated is not None
    # Disallowed fields unchanged
    assert updated["entity_id"] == "https://original.example.com"
    assert updated["trust_established"] is True
    assert updated["certificate_pem"] is None  # was never set legitimately


def test_update_service_provider_no_valid_fields(test_tenant, test_user):
    """Test that providing no valid fields returns the SP unchanged."""
    import database

    sp = _create_sp(test_tenant["id"], test_user["id"], name="No Update")

    result = database.service_providers.update_service_provider(
        test_tenant["id"], sp["id"], bogus_field="value"
    )

    assert result is not None
    assert result["name"] == "No Update"


def test_update_service_provider_not_found(test_tenant):
    """Test updating a nonexistent SP returns None."""
    import database

    result = database.service_providers.update_service_provider(
        test_tenant["id"], str(uuid4()), name="Ghost"
    )

    assert result is None


# -- set_service_provider_enabled ----------------------------------------------


def test_set_service_provider_enabled(test_tenant, test_user):
    """Test toggling the enabled flag."""
    import database

    sp = _create_sp(test_tenant["id"], test_user["id"], name="Toggle SP")
    assert sp["enabled"] is True

    disabled = database.service_providers.set_service_provider_enabled(
        test_tenant["id"], sp["id"], enabled=False
    )
    assert disabled is not None
    assert disabled["enabled"] is False

    re_enabled = database.service_providers.set_service_provider_enabled(
        test_tenant["id"], sp["id"], enabled=True
    )
    assert re_enabled is not None
    assert re_enabled["enabled"] is True


# -- refresh_sp_metadata_fields ------------------------------------------------


def test_refresh_sp_metadata_fields(test_tenant, test_user):
    """Test that refresh updates metadata fields without touching name/entity_id/enabled."""
    import database

    sp = _create_sp(
        test_tenant["id"],
        test_user["id"],
        name="Refresh SP",
        entity_id="https://refresh.example.com",
        acs_url="https://old-acs.example.com",
    )

    refreshed = database.service_providers.refresh_sp_metadata_fields(
        test_tenant["id"],
        sp["id"],
        acs_url="https://new-acs.example.com",
        certificate_pem="-----BEGIN CERTIFICATE-----\nNEW\n-----END CERTIFICATE-----",
        slo_url="https://refresh.example.com/slo",
        sp_requested_attributes=[{"name": "email", "required": True}],
        attribute_mapping={"email": "mail"},
    )

    assert refreshed is not None
    # Metadata fields updated
    assert refreshed["acs_url"] == "https://new-acs.example.com"
    expected_cert = "-----BEGIN CERTIFICATE-----\nNEW\n-----END CERTIFICATE-----"
    assert refreshed["certificate_pem"] == expected_cert
    assert refreshed["slo_url"] == "https://refresh.example.com/slo"
    assert refreshed["sp_requested_attributes"] == [{"name": "email", "required": True}]
    assert refreshed["attribute_mapping"] == {"email": "mail"}
    # Non-metadata fields preserved
    assert refreshed["name"] == "Refresh SP"
    assert refreshed["entity_id"] == "https://refresh.example.com"
    assert refreshed["enabled"] is True


def test_refresh_sp_metadata_fields_not_found(test_tenant):
    """Test refresh on nonexistent SP returns None."""
    import database

    result = database.service_providers.refresh_sp_metadata_fields(
        test_tenant["id"], str(uuid4()), acs_url="https://nope.example.com"
    )

    assert result is None


# -- establish_trust -----------------------------------------------------------


def test_establish_trust(test_tenant, test_user):
    """Test establishing trust on a pending SP."""
    import database

    sp = _create_sp(test_tenant["id"], test_user["id"], name="Pending SP")
    assert sp["trust_established"] is False

    trusted = database.service_providers.establish_trust(
        test_tenant["id"],
        sp["id"],
        entity_id="https://trusted.example.com",
        acs_url="https://trusted.example.com/acs",
        certificate_pem="CERT_PEM",
        metadata_url="https://trusted.example.com/metadata",
        slo_url="https://trusted.example.com/slo",
        attribute_mapping={"email": "mail"},
    )

    assert trusted is not None
    assert trusted["trust_established"] is True
    assert trusted["entity_id"] == "https://trusted.example.com"
    assert trusted["acs_url"] == "https://trusted.example.com/acs"
    assert trusted["certificate_pem"] == "CERT_PEM"
    assert trusted["metadata_url"] == "https://trusted.example.com/metadata"
    assert trusted["attribute_mapping"] == {"email": "mail"}


def test_establish_trust_already_established(test_tenant, test_user):
    """Test that establish_trust is a no-op when trust is already established."""
    import database

    sp = _create_sp(
        test_tenant["id"],
        test_user["id"],
        name="Already Trusted",
        entity_id="https://already.example.com",
        acs_url="https://already.example.com/acs",
        trust_established=True,
    )

    result = database.service_providers.establish_trust(
        test_tenant["id"],
        sp["id"],
        entity_id="https://overwrite-attempt.example.com",
        acs_url="https://overwrite-attempt.example.com/acs",
    )

    assert result is None

    # Verify original data unchanged
    fetched = database.service_providers.get_service_provider(test_tenant["id"], sp["id"])
    assert fetched["entity_id"] == "https://already.example.com"


# -- delete_service_provider ---------------------------------------------------


def test_delete_service_provider(test_tenant, test_user):
    """Test deleting an SP."""
    import database

    sp = _create_sp(test_tenant["id"], test_user["id"], name="Delete Me")

    rows = database.service_providers.delete_service_provider(test_tenant["id"], sp["id"])

    assert rows == 1
    assert database.service_providers.get_service_provider(test_tenant["id"], sp["id"]) is None


def test_delete_service_provider_not_found(test_tenant):
    """Test deleting a nonexistent SP returns 0."""
    import database

    rows = database.service_providers.delete_service_provider(test_tenant["id"], str(uuid4()))

    assert rows == 0
