"""E2E tests for group-based SP access control.

Tests:
  - Direct group access: User in a group that has the SP assigned can SSO
  - Inherited group access: User in a child group can SSO to an SP
    assigned to the parent group (DAG hierarchy inheritance)

Uses the two-tenant testbed with extras (group hierarchy data).
"""


class TestDirectGroupAccess:
    """User with direct group membership can access the SP via SSO."""

    def test_direct_group_member_can_sso(self, page, login, idp_config, sp_config):
        """IdP-initiated SSO works for a user directly in an SP-assigned group.

        The base testbed puts the IdP admin in the 'SSO Users' group,
        which has the SP assigned. This test verifies the basic group
        access pattern by performing IdP-initiated SSO.
        """
        idp_base = idp_config["base_url"]
        sp_base = sp_config["base_url"]

        # Login to IdP
        login(idp_base, idp_config["admin_email"])
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=10000)

        # Dashboard should show "My Apps" with the SP
        my_apps = page.locator("text=My Apps")
        assert my_apps.is_visible(), "My Apps section not visible"

        sp_link = page.locator("a[href*='/saml/idp/launch/']").first
        assert sp_link.is_visible(), "SP app tile not visible"

        # Click the SP app tile
        sp_link.click()

        # Consent page
        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=10000)
        page.locator("button", has_text="Continue").first.click()

        # Land at SP dashboard
        page.wait_for_url(f"{sp_base}/dashboard**", timeout=15000)
        assert "/dashboard" in page.url


class TestInheritedGroupAccess:
    """User in a child group inherits SP access from the parent group."""

    def test_child_group_member_can_sso(self, page, login, idp_config, sp_config, extras_config):
        """IdP-initiated SSO works for a user in a child group when the SP
        is assigned to the parent group.

        The extras testbed:
          - Created parent group 'All Staff' with SP assigned
          - Created child group 'Engineering' under 'All Staff'
          - Created engineer@acme.com in 'Engineering' only (NOT in 'All Staff')
          - Created pre-existing user at SP linked to IdP

        The DAG hierarchy means Engineering inherits All Staff's SP access.
        The group_lineage closure table enables this O(1) check.
        """
        idp_base = idp_config["base_url"]
        sp_base = sp_config["base_url"]
        engineer_email = extras_config["group_hierarchy"]["test_email"]

        # Login to IdP as engineer
        login(idp_base, engineer_email)
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=10000)

        # Dashboard should show the SP in "My Apps" (inherited from All Staff)
        sp_link = page.locator("a[href*='/saml/idp/launch/']").first
        assert sp_link.is_visible(), (
            "SP app tile not visible for child group member. "
            "Inherited access via All Staff → Engineering may not be working."
        )

        # Click SP app tile for IdP-initiated SSO
        sp_link.click()

        # Consent page
        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=10000)
        page.locator("button", has_text="Continue").first.click()

        # Land at SP dashboard (pre-existing user matched)
        page.wait_for_url(f"{sp_base}/dashboard**", timeout=15000)
        assert "/dashboard" in page.url
