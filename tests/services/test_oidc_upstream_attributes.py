"""Tests for OIDC upstream attribute mirroring (Iteration 5).

Covers:
* ``_extract_standard_attributes`` lifts the 14 standard registry keys via the
  per-connection ``claim_mapping`` into a ``standard_attributes`` dict.
* ``apply_oidc_idp_attributes`` writes the OIDC IdP-mirror snapshot and, gated
  on the per-tenant per-attribute ``mirror_from_idp`` flag, the canonical
  ``user_attributes`` row.
* The mirror is soft-fail: a mirror failure never breaks OIDC login.
* ``scrub_oidc_canonical_matches_mirror`` clears canonical rows that still
  match the mirror snapshot on connection delete.
* ``update_claim_mapping`` / ``get_claim_mapping`` drop unknown keys and
  round-trip the mapping.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


def _make_requesting_user(user, tenant_id, role="super_admin"):
    from services.types import RequestingUser

    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=role,
    )


def _make_connection(test_tenant, test_user, **overrides):
    import database

    row = database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Iter5 OIDC",
        provider_type="generic",
        issuer="https://idp.example.com",
        created_by=str(test_user["id"]),
        **overrides,
    )
    return row


def _claims(**overrides):
    claims = {
        "sub": "subject-123",
        "email": "oidc-user@example.com",
        "email_verified": True,
        "given_name": "Oidc",
        "family_name": "User",
    }
    claims.update(overrides)
    return claims


# ---------------------------------------------------------------------------
# _extract_standard_attributes
# ---------------------------------------------------------------------------


class TestExtractStandardAttributes:
    """Unit tests for _extract_standard_attributes (no DB)."""

    def test_lifts_standard_registry_keys_via_mapping(self):
        from services.oidc_upstream.provisioning import _extract_standard_attributes

        mapping = {
            "email": "email",
            "first_name": "given_name",
            "last_name": "family_name",
            "job_title": "title",
            "phone_work": "phone",
            "department": "department",
        }
        claims = {
            "email": "u@e.com",
            "given_name": "Ada",
            "family_name": "Lovelace",
            "title": "Engineer",
            "phone": "+1 555 1234",
            "department": "Research",
        }

        result = _extract_standard_attributes(claims, mapping)

        assert result["job_title"] == "Engineer"
        assert result["phone_work"] == "+1 555 1234"
        assert result["department"] == "Research"
        # Fixed keys are not standard attributes and are excluded.
        assert "email" not in result
        assert "first_name" not in result
        assert "last_name" not in result

    def test_omits_keys_not_present_in_claims(self):
        from services.oidc_upstream.provisioning import _extract_standard_attributes

        mapping = {"job_title": "title", "department": "department"}
        claims = {"title": "Engineer"}

        result = _extract_standard_attributes(claims, mapping)
        assert result == {"job_title": "Engineer"}

    def test_drops_empty_and_non_string_values(self):
        from services.oidc_upstream.provisioning import _extract_standard_attributes

        mapping = {
            "job_title": "title",
            "department": "department",
            "city": "city",
        }
        claims = {
            "title": "",
            "department": "   ",
            "city": "Stockholm",
        }

        result = _extract_standard_attributes(claims, mapping)
        assert "job_title" not in result
        assert "department" not in result
        assert result["city"] == "Stockholm"

    def test_ignores_mapping_keys_not_in_registry(self):
        from services.oidc_upstream.provisioning import _extract_standard_attributes

        mapping = {"bogus": "bogus_claim", "job_title": "title"}
        claims = {"bogus_claim": "x", "title": "Engineer"}

        result = _extract_standard_attributes(claims, mapping)
        assert result == {"job_title": "Engineer"}


# ---------------------------------------------------------------------------
# apply_oidc_idp_attributes end-to-end
# ---------------------------------------------------------------------------


class TestApplyOidcIdpAttributes:
    """Verify the mirror snapshot + canonical write behavior."""

    def _seed_tenant_config(self, tenant_id):
        from services.settings import attributes as attributes_settings

        attributes_settings.seed_tenant_attribute_config(tenant_id)

    def _set_attribute_policy(self, requesting_user, attribute_key, *, enabled, mirror_from_idp):
        from services.settings import attributes as attributes_settings

        attributes_settings.seed_tenant_attribute_config(requesting_user["tenant_id"])
        attributes_settings.update_tenant_attribute_config(
            requesting_user,
            attribute_key,
            enabled=enabled,
            required=False,
            mirror_from_idp=mirror_from_idp,
            locked_for_users=False,
            send_to_sps_default=False,
        )

    def test_mirror_on_writes_canonical_and_snapshot(
        self, test_tenant, test_super_admin_user, test_user
    ):
        import database
        from services.oidc_upstream.attributes import apply_oidc_idp_attributes

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        self._set_attribute_policy(requesting, "job_title", enabled=True, mirror_from_idp=True)

        conn = _make_connection(test_tenant, test_super_admin_user)

        apply_oidc_idp_attributes(
            tenant_id=test_tenant["id"],
            user_id=str(test_user["id"]),
            idp_id=str(conn["id"]),
            attributes={"job_title": "Engineer"},
            actor_user_id=str(test_user["id"]),
        )

        canonical = database.user_attributes.get_attribute(
            test_tenant["id"], str(test_user["id"]), "job_title"
        )
        assert canonical is not None
        assert canonical["value"] == "Engineer"

        snapshot = database.oidc_upstream.list_attributes_for_idp(
            test_tenant["id"], str(test_user["id"]), str(conn["id"])
        )
        snapshot_map = {r["attribute_key"]: r["value"] for r in snapshot}
        assert snapshot_map.get("job_title") == "Engineer"

    def test_mirror_off_writes_snapshot_only(self, test_tenant, test_super_admin_user, test_user):
        import database
        from services.oidc_upstream.attributes import apply_oidc_idp_attributes

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        self._set_attribute_policy(requesting, "department", enabled=True, mirror_from_idp=False)

        conn = _make_connection(test_tenant, test_super_admin_user)

        apply_oidc_idp_attributes(
            tenant_id=test_tenant["id"],
            user_id=str(test_user["id"]),
            idp_id=str(conn["id"]),
            attributes={"department": "Research"},
            actor_user_id=str(test_user["id"]),
        )

        canonical = database.user_attributes.get_attribute(
            test_tenant["id"], str(test_user["id"]), "department"
        )
        assert canonical is None

        snapshot = database.oidc_upstream.list_attributes_for_idp(
            test_tenant["id"], str(test_user["id"]), str(conn["id"])
        )
        snapshot_map = {r["attribute_key"]: r["value"] for r in snapshot}
        assert snapshot_map.get("department") == "Research"

    def test_unknown_attribute_keys_dropped(self, test_tenant, test_super_admin_user, test_user):
        import database
        from services.oidc_upstream.attributes import apply_oidc_idp_attributes

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        self._set_attribute_policy(requesting, "job_title", enabled=True, mirror_from_idp=True)

        conn = _make_connection(test_tenant, test_super_admin_user)

        apply_oidc_idp_attributes(
            tenant_id=test_tenant["id"],
            user_id=str(test_user["id"]),
            idp_id=str(conn["id"]),
            attributes={"job_title": "Engineer", "bogus": "x"},
            actor_user_id=str(test_user["id"]),
        )

        snapshot = database.oidc_upstream.list_attributes_for_idp(
            test_tenant["id"], str(test_user["id"]), str(conn["id"])
        )
        snapshot_keys = {r["attribute_key"] for r in snapshot}
        assert "bogus" not in snapshot_keys
        assert "job_title" in snapshot_keys

    def test_unknown_connection_raises_not_found(
        self, test_tenant, test_super_admin_user, test_user
    ):
        from uuid import uuid4

        from services.exceptions import NotFoundError
        from services.oidc_upstream.attributes import apply_oidc_idp_attributes

        with pytest.raises(NotFoundError) as exc_info:
            apply_oidc_idp_attributes(
                tenant_id=test_tenant["id"],
                user_id=str(test_user["id"]),
                idp_id=str(uuid4()),
                attributes={"job_title": "Engineer"},
                actor_user_id=str(test_user["id"]),
            )
        assert exc_info.value.code == "oidc_connection_not_found"


# ---------------------------------------------------------------------------
# Soft-fail wrapper
# ---------------------------------------------------------------------------


class TestSoftFail:
    """Verify a mirror failure never breaks OIDC login."""

    def test_existing_user_mirror_failure_does_not_break_login(self, test_tenant, test_user):
        import database
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_user)
        database.oidc_upstream.create_link(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            idp_id=str(conn["id"]),
            sub="subject-123",
            user_id=str(test_user["id"]),
        )

        with (
            patch(
                "services.oidc_upstream.attributes.apply_oidc_idp_attributes",
                side_effect=RuntimeError("simulated DB outage"),
            ),
            patch("services.oidc_upstream.provisioning.log_event") as mock_log,
        ):
            user = svc.authenticate_via_oidc(test_tenant["id"], conn, "subject-123", _claims())

        assert str(user["id"]) == str(test_user["id"])

        mirror_failed_calls = [
            c
            for c in mock_log.call_args_list
            if c.kwargs.get("event_type") == "user_idp_attribute_mirror_failed"
        ]
        assert len(mirror_failed_calls) == 1
        meta = mirror_failed_calls[0].kwargs["metadata"]
        assert meta == {"idp_id": str(conn["id"]), "error_class": "RuntimeError"}

    def test_jit_user_mirror_failure_does_not_break_login(self, test_tenant, test_user):
        import database
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_user, jit_provisioning=True)

        with (
            patch(
                "services.oidc_upstream.attributes.apply_oidc_idp_attributes",
                side_effect=RuntimeError("simulated DB outage"),
            ),
            patch("services.oidc_upstream.provisioning.log_event") as mock_log,
        ):
            user = svc.authenticate_via_oidc(test_tenant["id"], conn, "subject-123", _claims())

        assert user is not None
        persisted = database.users.get_user_by_email_for_saml(
            test_tenant["id"], "oidc-user@example.com"
        )
        assert persisted is not None
        assert str(persisted["id"]) == str(user["id"])

        mirror_failed_calls = [
            c
            for c in mock_log.call_args_list
            if c.kwargs.get("event_type") == "user_idp_attribute_mirror_failed"
        ]
        assert len(mirror_failed_calls) == 1


# ---------------------------------------------------------------------------
# Scrub on delete
# ---------------------------------------------------------------------------


class TestScrubOnDelete:
    """Verify scrub_oidc_canonical_matches_mirror clears matching canonical rows."""

    def _seed_tenant_config(self, tenant_id):
        from services.settings import attributes as attributes_settings

        attributes_settings.seed_tenant_attribute_config(tenant_id)

    def _set_attribute_policy(self, requesting_user, attribute_key, *, enabled, mirror_from_idp):
        from services.settings import attributes as attributes_settings

        attributes_settings.seed_tenant_attribute_config(requesting_user["tenant_id"])
        attributes_settings.update_tenant_attribute_config(
            requesting_user,
            attribute_key,
            enabled=enabled,
            required=False,
            mirror_from_idp=mirror_from_idp,
            locked_for_users=False,
            send_to_sps_default=False,
        )

    def test_scrub_clears_matching_canonical_rows(
        self, test_tenant, test_super_admin_user, test_user
    ):
        import database
        from services.oidc_upstream.attributes import (
            apply_oidc_idp_attributes,
            scrub_oidc_canonical_matches_mirror,
        )

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        self._set_attribute_policy(requesting, "job_title", enabled=True, mirror_from_idp=True)

        conn = _make_connection(test_tenant, test_super_admin_user)

        apply_oidc_idp_attributes(
            tenant_id=test_tenant["id"],
            user_id=str(test_user["id"]),
            idp_id=str(conn["id"]),
            attributes={"job_title": "Engineer"},
            actor_user_id=str(test_user["id"]),
        )

        canonical = database.user_attributes.get_attribute(
            test_tenant["id"], str(test_user["id"]), "job_title"
        )
        assert canonical is not None

        scrubbed = scrub_oidc_canonical_matches_mirror(
            tenant_id=test_tenant["id"],
            idp_id=str(conn["id"]),
            actor_user_id=str(test_super_admin_user["id"]),
        )
        assert scrubbed == 1

        canonical = database.user_attributes.get_attribute(
            test_tenant["id"], str(test_user["id"]), "job_title"
        )
        assert canonical is None

    def test_scrub_leaves_diverged_canonical_rows(
        self, test_tenant, test_super_admin_user, test_user
    ):
        import database
        from services.oidc_upstream.attributes import (
            apply_oidc_idp_attributes,
            scrub_oidc_canonical_matches_mirror,
        )

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        self._set_attribute_policy(requesting, "job_title", enabled=True, mirror_from_idp=True)

        conn = _make_connection(test_tenant, test_super_admin_user)

        apply_oidc_idp_attributes(
            tenant_id=test_tenant["id"],
            user_id=str(test_user["id"]),
            idp_id=str(conn["id"]),
            attributes={"job_title": "Engineer"},
            actor_user_id=str(test_user["id"]),
        )

        # User edits the canonical value after the mirror write.
        database.user_attributes.upsert_attribute(
            test_tenant["id"],
            test_tenant["id"],
            str(test_user["id"]),
            "job_title",
            "Senior Engineer",
        )

        scrubbed = scrub_oidc_canonical_matches_mirror(
            tenant_id=test_tenant["id"],
            idp_id=str(conn["id"]),
            actor_user_id=str(test_super_admin_user["id"]),
        )
        assert scrubbed == 0

        canonical = database.user_attributes.get_attribute(
            test_tenant["id"], str(test_user["id"]), "job_title"
        )
        assert canonical is not None
        assert canonical["value"] == "Senior Engineer"


# ---------------------------------------------------------------------------
# Claim mapping service
# ---------------------------------------------------------------------------


class TestClaimMappingService:
    """Verify get/update claim mapping drop unknown keys and round-trip."""

    def test_update_claim_mapping_drops_unknown_keys(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        conn = svc.create_connection(
            requesting,
            _create_data(),
            "https://test.example.com",
        )

        updated = svc.update_claim_mapping(
            requesting,
            conn.id,
            {"email": "email", "job_title": "title", "bogus": "xyz"},
            "https://test.example.com",
        )

        assert "bogus" not in updated.claim_mapping
        assert updated.claim_mapping["job_title"] == "title"
        assert updated.claim_mapping["email"] == "email"

    def test_get_claim_mapping_round_trip(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        conn = svc.create_connection(
            requesting,
            _create_data(),
            "https://test.example.com",
        )

        svc.update_claim_mapping(
            requesting,
            conn.id,
            {"email": "email", "job_title": "title"},
            "https://test.example.com",
        )

        mapping = svc.get_claim_mapping(requesting, conn.id)
        assert mapping["email"] == "email"
        assert mapping["job_title"] == "title"


def _create_data(**overrides):
    from schemas.oidc_upstream import OIDCConnectionCreate

    data = {
        "name": "Iter5 OIDC",
        "provider_type": "generic",
        "issuer": "https://idp.example.com",
    }
    data.update(overrides)
    return OIDCConnectionCreate(**data)


# ---------------------------------------------------------------------------
# Schema validation (unknown-key handling consistency)
# ---------------------------------------------------------------------------


class TestClaimMappingSchemaValidation:
    """OIDCConnectionCreate/Update drop unknown claim-mapping keys (not reject)."""

    def test_create_drops_unknown_keys(self):
        from schemas.oidc_upstream import OIDCConnectionCreate

        data = OIDCConnectionCreate(
            name="X",
            provider_type="generic",
            issuer="https://idp.example.com",
            claim_mapping={"email": "email", "job_title": "title", "bogus": "xyz"},
        )
        assert "bogus" not in data.claim_mapping
        assert data.claim_mapping["job_title"] == "title"

    def test_update_drops_unknown_keys(self):
        from schemas.oidc_upstream import OIDCConnectionUpdate

        data = OIDCConnectionUpdate(claim_mapping={"bogus": "xyz", "job_title": "title"})
        assert "bogus" not in data.claim_mapping
        assert data.claim_mapping["job_title"] == "title"

    def test_update_none_mapping_passes(self):
        from schemas.oidc_upstream import OIDCConnectionUpdate

        assert OIDCConnectionUpdate(claim_mapping=None).claim_mapping is None
