"""Unit tests for database.users.listing clause-building helpers.

These test the pure SQL clause-building functions directly (no database needed).
"""

from datetime import UTC, date, datetime, time, timedelta


class TestBuildRoleClause:
    """Tests for _build_role_clause."""

    def test_no_roles(self):
        from database.users.listing import _build_role_clause

        clauses, params = [], {}
        _build_role_clause(None, clauses, params)
        assert clauses == []

    def test_valid_roles(self):
        from database.users.listing import _build_role_clause

        clauses, params = [], {}
        _build_role_clause(["admin", "member"], clauses, params)
        assert len(clauses) == 1
        assert "ANY" in clauses[0]
        assert params["roles"] == ["admin", "member"]

    def test_negated_roles(self):
        from database.users.listing import _build_role_clause

        clauses, params = [], {}
        _build_role_clause(["admin"], clauses, params, negate=True)
        assert len(clauses) == 1
        assert "!= ALL" in clauses[0]

    def test_invalid_roles_filtered(self):
        from database.users.listing import _build_role_clause

        clauses, params = [], {}
        _build_role_clause(["invalid_role"], clauses, params)
        assert clauses == []


class TestBuildStatusClause:
    """Tests for _build_status_clause."""

    def test_no_statuses(self):
        from database.users.listing import _build_status_clause

        clauses = []
        _build_status_clause(None, clauses)
        assert clauses == []

    def test_active_status(self):
        from database.users.listing import _build_status_clause

        clauses = []
        _build_status_clause(["active"], clauses)
        assert len(clauses) == 1
        assert "is_inactivated = false" in clauses[0]

    def test_inactivated_status(self):
        from database.users.listing import _build_status_clause

        clauses = []
        _build_status_clause(["inactivated"], clauses)
        assert "is_inactivated = true" in clauses[0]

    def test_anonymized_status(self):
        from database.users.listing import _build_status_clause

        clauses = []
        _build_status_clause(["anonymized"], clauses)
        assert "is_anonymized = true" in clauses[0]

    def test_negated_status(self):
        from database.users.listing import _build_status_clause

        clauses = []
        _build_status_clause(["active"], clauses, negate=True)
        assert clauses[0].startswith("not ")

    def test_multiple_statuses(self):
        from database.users.listing import _build_status_clause

        clauses = []
        _build_status_clause(["active", "inactivated"], clauses)
        assert " or " in clauses[0]


class TestBuildAuthMethodClauses:
    """Tests for _build_auth_method_clauses."""

    def test_no_auth_methods(self):
        from database.users.listing import _build_auth_method_clauses

        clauses, params = [], {}
        _build_auth_method_clauses(None, clauses, params)
        assert clauses == []

    def test_password_email(self):
        from database.users.listing import _build_auth_method_clauses

        clauses, params = [], {}
        _build_auth_method_clauses(["password_email"], clauses, params)
        assert len(clauses) == 1
        assert "password_hash is not null" in clauses[0]

    def test_password_totp(self):
        from database.users.listing import _build_auth_method_clauses

        clauses, params = [], {}
        _build_auth_method_clauses(["password_totp"], clauses, params)
        assert "mfa_method = 'totp'" in clauses[0]

    def test_unverified(self):
        from database.users.listing import _build_auth_method_clauses

        clauses, params = [], {}
        _build_auth_method_clauses(["unverified"], clauses, params)
        assert "password_hash is null" in clauses[0]

    def test_idp_uuid(self):
        from database.users.listing import _build_auth_method_clauses

        clauses, params = [], {}
        _build_auth_method_clauses(["idp:some-uuid"], clauses, params)
        assert "auth_idp_ids" in params
        assert params["auth_idp_ids"] == ["some-uuid"]

    def test_idp_totp(self):
        from database.users.listing import _build_auth_method_clauses

        clauses, params = [], {}
        _build_auth_method_clauses(["idp:some-uuid_totp"], clauses, params)
        assert "auth_idp_totp_ids" in params
        assert params["auth_idp_totp_ids"] == ["some-uuid"]

    def test_negated_auth_methods(self):
        from database.users.listing import _build_auth_method_clauses

        clauses, params = [], {}
        _build_auth_method_clauses(["password_email"], clauses, params, negate=True)
        assert clauses[0].startswith("not ")


class TestBuildDomainClause:
    """Tests for _build_domain_clause."""

    def test_no_domain(self):
        from database.users.listing import _build_domain_clause

        clauses, params = [], {}
        _build_domain_clause(None, clauses, params)
        assert clauses == []

    def test_domain_filter(self):
        from database.users.listing import _build_domain_clause

        clauses, params = [], {}
        _build_domain_clause("example.com", clauses, params)
        assert "exists" in clauses[0]
        assert params["domain"] == "example.com"

    def test_negated_domain(self):
        from database.users.listing import _build_domain_clause

        clauses, params = [], {}
        _build_domain_clause("example.com", clauses, params, negate=True)
        assert "not exists" in clauses[0]


class TestBuildGroupClause:
    """Tests for _build_group_clause."""

    def test_no_group(self):
        from database.users.listing import _build_group_clause

        clauses, params = [], {}
        _build_group_clause(None, clauses, params)
        assert clauses == []

    def test_group_with_children(self):
        from database.users.listing import _build_group_clause

        clauses, params = [], {}
        _build_group_clause("group-1", clauses, params, include_children=True)
        assert "group_lineage" in clauses[0]

    def test_group_without_children(self):
        from database.users.listing import _build_group_clause

        clauses, params = [], {}
        _build_group_clause("group-1", clauses, params, include_children=False)
        assert "group_lineage" not in clauses[0]
        assert "gm_f.group_id = :filter_group_id" in clauses[0]

    def test_negated_group(self):
        from database.users.listing import _build_group_clause

        clauses, params = [], {}
        _build_group_clause("group-1", clauses, params, negate=True)
        assert "not exists" in clauses[0]


class TestBuildSecondaryEmailClause:
    """Tests for _build_secondary_email_clause."""

    def test_none(self):
        from database.users.listing import _build_secondary_email_clause

        clauses, params = [], {}
        _build_secondary_email_clause(None, clauses, params)
        assert clauses == []

    def test_has_secondary(self):
        from database.users.listing import _build_secondary_email_clause

        clauses, params = [], {}
        _build_secondary_email_clause(True, clauses, params)
        assert "exists" in clauses[0]
        assert "is_primary = false" in clauses[0]

    def test_no_secondary(self):
        from database.users.listing import _build_secondary_email_clause

        clauses, params = [], {}
        _build_secondary_email_clause(False, clauses, params)
        assert "not exists" in clauses[0]

    def test_domain_filter(self):
        from database.users.listing import _build_secondary_email_clause

        clauses, params = [], {}
        _build_secondary_email_clause("domain:example.com", clauses, params)
        assert "sec_domain" in params
        assert params["sec_domain"] == "example.com"


class TestBuildActivityDateClauses:
    """Tests for _build_activity_date_clauses."""

    def test_no_dates(self):
        from database.users.listing import _build_activity_date_clauses

        clauses, params = [], {}
        _build_activity_date_clauses(None, None, clauses, params)
        assert clauses == []

    def test_start_date(self):
        from database.users.listing import _build_activity_date_clauses

        clauses, params = [], {}
        _build_activity_date_clauses(date(2026, 1, 1), None, clauses, params)
        assert len(clauses) == 1
        assert "activity_start" in params
        assert params["activity_start"] == datetime.combine(date(2026, 1, 1), time.min, tzinfo=UTC)

    def test_end_date(self):
        from database.users.listing import _build_activity_date_clauses

        clauses, params = [], {}
        _build_activity_date_clauses(None, date(2026, 3, 31), clauses, params)
        assert len(clauses) == 1
        assert "activity_end_exclusive" in params
        expected = datetime.combine(date(2026, 3, 31) + timedelta(days=1), time.min, tzinfo=UTC)
        assert params["activity_end_exclusive"] == expected

    def test_both_dates(self):
        from database.users.listing import _build_activity_date_clauses

        clauses, params = [], {}
        _build_activity_date_clauses(date(2026, 1, 1), date(2026, 3, 31), clauses, params)
        assert len(clauses) == 2


class TestBuildSearchClauses:
    """Tests for _build_search_clauses."""

    def test_no_search(self):
        from database.users.listing import _build_search_clauses

        clauses, params = [], {}
        _build_search_clauses(None, clauses, params)
        assert clauses == []

    def test_single_token(self):
        from database.users.listing import _build_search_clauses

        clauses, params = [], {}
        _build_search_clauses("alice", clauses, params)
        assert len(clauses) == 1
        assert "search_0" in params

    def test_multi_token(self):
        from database.users.listing import _build_search_clauses

        clauses, params = [], {}
        _build_search_clauses("alice smith", clauses, params)
        assert len(clauses) == 2
        assert "search_0" in params
        assert "search_1" in params


class TestListUsersByIds:
    """Tests for list_users_by_ids."""

    def test_empty_ids_returns_empty(self):
        from database.users.listing import list_users_by_ids

        result = list_users_by_ids("any-tenant", [])
        assert result == []
