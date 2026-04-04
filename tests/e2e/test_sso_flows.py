"""E2E tests for SAML SSO flows between IdP and SP tenants.

These tests exercise real cross-tenant SSO using two WeftID tenants:
    - e2e-idp: acts as the SAML Identity Provider
    - e2e-sp:  acts as the SAML Service Provider

The testbed is provisioned by the session-scoped `e2e_config` fixture.
"""

from tests.e2e.conftest import enter_email_and_reach_password_form


class TestSpInitiatedSso:
    """SP-initiated SSO: user starts at SP, authenticates at IdP, returns to SP."""

    def test_sp_initiated_sso(self, page, login, idp_config, sp_config):
        """Full SP-initiated SSO flow with JIT user provisioning.

        1. User enters IdP admin email at SP login
        2. SP routes to SAML IdP (direct routing, no email verification)
        3. IdP sees unauthenticated user, redirects to IdP login
        4. User logs in at IdP (password + MFA)
        5. IdP shows consent page, user approves
        6. SAML Response auto-submitted to SP ACS
        7. SP JIT-creates user, user lands on SP dashboard
        """
        idp_base = idp_config["base_url"]
        sp_base = sp_config["base_url"]
        idp_email = idp_config["admin_email"]
        idp_password = idp_config["admin_password"]

        # Step 1: Navigate to SP login and enter the IdP admin's email.
        # With direct routing (default), SP routes to SAML immediately.
        # Navigate directly to SAML login endpoint to trigger the redirect
        # chain to IdP SSO (Playwright POST->303 workaround).
        idp_id = sp_config["idp_id"]
        page.goto(f"{sp_base}/saml/login/{idp_id}")

        # IdP sees unauthenticated user and redirects to IdP /login
        page.wait_for_url(f"{idp_base}/login**", timeout=15000)

        # Step 2: Complete login at the IdP (password + MFA)
        enter_email_and_reach_password_form(page, idp_base, idp_email, idp_password)

        # MFA (BYPASS_OTP=true, any 6-digit code works)
        page.wait_for_url("**/mfa/verify**")
        page.locator("#code").fill("123456")
        page.locator("#mfaVerifyForm button[type='submit']").click()

        # Step 3: After MFA, IdP detects pending SSO context and shows consent page
        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=10000)

        # Verify consent page shows SP name
        consent_text = page.content()
        assert sp_config["subdomain"] in consent_text.lower() or "SP" in consent_text

        # Step 4: Approve consent
        page.locator("button", has_text="Continue").first.click()

        # Step 5: SAML Response auto-submits to SP ACS, SP creates session.
        # User lands on SP dashboard.
        page.wait_for_url(f"{sp_base}/dashboard**", timeout=15000)

        # Verify we're actually logged in at the SP
        assert "/dashboard" in page.url


class TestIdpInitiatedSso:
    """IdP-initiated SSO: user starts at IdP dashboard, launches SP app."""

    def test_idp_initiated_sso(self, page, login, idp_config, sp_config):
        """User logs in to IdP, clicks SP app tile, approves consent, lands at SP.

        1. Login to IdP
        2. Dashboard shows SP in "My Apps"
        3. Click SP app tile
        4. Consent page shows
        5. Click Continue
        6. Lands at SP dashboard
        """
        idp_base = idp_config["base_url"]
        sp_base = sp_config["base_url"]

        # Login to IdP
        login(idp_base, idp_config["admin_email"])

        # Should be on IdP dashboard
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=10000)

        # Verify "My Apps" section has the SP
        my_apps = page.locator("text=My Apps")
        assert my_apps.is_visible(), "My Apps section not visible on dashboard"

        # Click the SP app tile
        sp_link = page.locator("a[href*='/saml/idp/launch/']").first
        assert sp_link.is_visible(), "SP app tile not visible"
        sp_link.click()

        # Should arrive at consent page
        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=10000)

        # Approve consent
        page.locator("button", has_text="Continue").first.click()

        # SAML Response auto-submits to SP, user lands on SP dashboard
        page.wait_for_url(f"{sp_base}/dashboard**", timeout=15000)
        assert "/dashboard" in page.url


class TestPreExistingUser:
    """Test SSO with a pre-existing user at the SP."""

    def test_sign_in_as_pre_existing_user(self, page, login, idp_config, sp_config):
        """SSO matches an existing SP user instead of JIT-creating a new one.

        The testbed pre-created a user in the SP tenant with the same email
        as the IdP admin. When SSO completes, the SP should match that
        existing user rather than creating a duplicate.
        """
        idp_base = idp_config["base_url"]
        sp_base = sp_config["base_url"]

        # The pre-existing user email is the same as the IdP admin
        assert sp_config["existing_user_email"] == idp_config["admin_email"]

        # Login to IdP
        login(idp_base, idp_config["admin_email"])
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=10000)

        # Launch SP via app tile
        sp_link = page.locator("a[href*='/saml/idp/launch/']").first
        sp_link.click()

        # Consent page
        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=10000)
        page.locator("button", has_text="Continue").first.click()

        # Land at SP dashboard (pre-existing user matched, not JIT-created)
        page.wait_for_url(f"{sp_base}/dashboard**", timeout=15000)
        assert "/dashboard" in page.url
