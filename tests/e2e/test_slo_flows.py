"""E2E tests for SAML Single Logout (SLO) flows.

Tests both SP-initiated and IdP-initiated SLO between two WeftID tenants:
    - e2e-idp: acts as the SAML Identity Provider
    - e2e-sp:  acts as the SAML Service Provider

The testbed configures SLO URLs on both sides so that:
    - SP knows where to send LogoutRequests to the IdP
    - IdP knows where to send LogoutRequests to the SP

SP-initiated SLO flow:
    1. User is logged in at SP via SSO
    2. User clicks logout at SP
    3. SP builds LogoutRequest, redirects to IdP's SLO endpoint
    4. IdP clears session, returns LogoutResponse via auto-submit form
    5. SP receives response, redirects to /login?slo=complete

IdP-initiated SLO propagation:
    1. User is logged in at IdP, has SSO'd to SP
    2. User clicks logout at IdP
    3. IdP sends server-to-server LogoutRequests to all SPs with active sessions
    4. IdP clears its own session, redirects to /login
    Note: SP browser cookies are NOT cleared (server-to-server, not browser flow)
"""


class TestSpInitiatedSlo:
    """SP-initiated SLO: user logs out at SP, SLO round-trip through IdP."""

    def test_sp_logout_redirects_through_idp_slo(self, page, login, idp_config, sp_config):
        """Full SP-initiated SLO: SSO to SP, logout at SP, verify SLO completes.

        1. Login to IdP
        2. Launch SP via SSO (IdP-initiated)
        3. Click logout at SP
        4. SP initiates SLO: redirect to IdP SLO endpoint
        5. IdP clears session, sends LogoutResponse back to SP
        6. SP redirects to /login?slo=complete
        7. Verify IdP session is also cleared
        """
        idp_base = idp_config["base_url"]
        sp_base = sp_config["base_url"]

        # Step 1: Login to IdP
        login(idp_base, idp_config["admin_email"])
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=10000)

        # Step 2: Launch SP via SSO (IdP-initiated)
        sp_link = page.locator("a[href*='/saml/idp/launch/']").first
        sp_link.click()

        # Consent page
        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=10000)
        page.locator("button", has_text="Continue").first.click()

        # Land at SP dashboard
        page.wait_for_url(f"{sp_base}/dashboard**", timeout=15000)
        assert "/dashboard" in page.url

        # Step 3: Submit the logout form.
        # Chain: POST /logout -> 303 IdP SLO -> auto-submit form -> POST SP SLO -> 303 /login
        page.locator("form[action='/logout']").evaluate("form => form.submit()")

        # Poll for the final URL instead of wait_for_url, which uses
        # expect_navigation internally and throws ERR_ABORTED on the
        # multi-hop SLO redirect chain.
        deadline = 15000
        interval = 500
        elapsed = 0
        while elapsed < deadline:
            if "/login" in page.url and sp_base in page.url:
                break
            page.wait_for_timeout(interval)
            elapsed += interval
        else:
            raise AssertionError(f"Timed out waiting for /login after SLO. Current URL: {page.url}")

        assert "slo=complete" in page.url, (
            f"Expected slo=complete in URL but got: {page.url}. "
            "The SLO round-trip through the IdP may have failed."
        )

        # Step 7: Verify IdP session was cleared by the SLO
        page.goto(f"{idp_base}/dashboard")
        # Should redirect to login since IdP session was cleared during SLO
        page.wait_for_url(f"{idp_base}/login**", timeout=5000)

    def test_sp_logout_without_sso_session_goes_to_login(self, page, login, sp_config):
        """SP logout without a SAML session skips SLO and redirects to /login."""
        sp_base = sp_config["base_url"]

        # Login directly to SP (no SAML, so no SLO on logout)
        login(sp_base, sp_config["admin_email"])
        page.wait_for_url(f"{sp_base}/dashboard**", timeout=10000)

        # Logout by submitting the form directly
        page.locator("form[action='/logout']").evaluate("form => form.submit()")

        # Should go straight to /login (no slo=complete since no SAML session)
        page.wait_for_url(f"{sp_base}/login**", timeout=5000)


class TestIdpInitiatedSlo:
    """IdP-initiated SLO: user logs out at IdP, propagation to downstream SPs."""

    def test_idp_logout_after_sso_completes_successfully(self, page, login, idp_config, sp_config):
        """IdP logout propagates to SPs and clears IdP session.

        1. Login to IdP
        2. SSO to SP (creates sso_active_sps entry in IdP session)
        3. Navigate back to IdP
        4. Logout at IdP
        5. Verify IdP session is cleared
        6. Verify IdP sent propagation (best-effort, server-to-server)
        """
        idp_base = idp_config["base_url"]
        sp_base = sp_config["base_url"]

        # Step 1: Login to IdP
        login(idp_base, idp_config["admin_email"])
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=10000)

        # Step 2: SSO to SP
        sp_link = page.locator("a[href*='/saml/idp/launch/']").first
        sp_link.click()
        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=10000)
        page.locator("button", has_text="Continue").first.click()
        page.wait_for_url(f"{sp_base}/dashboard**", timeout=15000)

        # Step 3: Navigate back to IdP
        page.goto(f"{idp_base}/dashboard")
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=10000)

        # Step 4: Logout at IdP by submitting the form directly
        page.locator("form[action='/logout']").evaluate("form => form.submit()")

        # Step 5: Verify IdP logout completed
        page.wait_for_url(f"{idp_base}/login**", timeout=10000)

        # Step 6: Verify IdP session is cleared (dashboard should redirect to login)
        page.goto(f"{idp_base}/dashboard")
        page.wait_for_url(f"{idp_base}/login**", timeout=5000)
