"""E2E test for three-tenant passthrough SSO.

Tests the chain: leaf SP → mid IdP/SP → upstream IdP

The chain testbed provisions three tenants:
  - e2e-upstream: the ultimate IdP (authenticates users)
  - e2e-mid: acts as IdP for leaf AND as SP of upstream
  - e2e-leaf: the leaf SP (where the user starts)

Chain user: chain-user@upstream.test
  - Exists at upstream with password (for authentication)
  - Exists at mid linked to upstream IdP (SAML-only)
  - Does NOT exist at leaf (JIT-provisioned via domain binding)

Domain binding at leaf: upstream.test → mid IdP
"""

from helpers.maildev import clear_emails, extract_otp_code, get_latest_email


class TestChainPassthroughSso:
    """Three-tenant passthrough: leaf → mid → upstream → authenticate → cascade back."""

    def test_chain_sso_passthrough(
        self, page, login, upstream_config, mid_config, leaf_config, chain_user
    ):
        """Full three-tenant SSO chain with passthrough authentication.

        Flow:
          1. User enters email at leaf SP login
          2. Leaf verifies email, domain binding routes to mid IdP
          3. Mid receives AuthnRequest, stores pending SSO, redirects to login
          4. User enters email at mid, verifies, mid routes to upstream IdP
          5. Upstream sees pre-authenticated user → consent page
          6. User approves → SAML Response to mid ACS
          7. Mid processes response, detects pending SSO for leaf → consent
          8. User approves → SAML Response to leaf ACS
          9. Leaf JIT-provisions user → dashboard

        Pre-authentication at upstream (step 0) reduces the test to
        2 email verifications and 2 consent approvals.
        """
        upstream_base = upstream_config["base_url"]
        mid_base = mid_config["base_url"]
        leaf_base = leaf_config["base_url"]
        email = chain_user["email"]

        # Step 0: Pre-authenticate at upstream (skip full login there)
        login(upstream_base, email)

        # Step 1: Enter email at leaf SP login
        clear_emails()
        page.goto(f"{leaf_base}/login")
        page.locator("#email").fill(email)
        page.locator("#emailForm button[type='submit']").click()

        # Step 2: Verify email at leaf
        page.wait_for_url("**/login/verify**")
        mail = get_latest_email(to=email, timeout=10.0)
        assert mail is not None, f"No verification email at leaf for {email}"
        code = extract_otp_code(mail)
        assert code is not None, "Could not extract verification code at leaf"

        page.locator("#code").fill(code)
        page.locator("#verifyCodeForm button[type='submit']").click(no_wait_after=True)
        page.wait_for_timeout(2000)

        # Step 3: Leaf routes to mid IdP via domain binding.
        # Navigate directly to SAML login (Playwright POST→303 workaround).
        mid_idp_id = leaf_config["mid_idp_id"]
        page.goto(f"{leaf_base}/saml/login/{mid_idp_id}")

        # Mid receives AuthnRequest, user not authenticated at mid → login page
        page.wait_for_url(f"{mid_base}/login**", timeout=15000)

        # Step 4: Enter email at mid login and verify
        clear_emails()
        page.locator("#email").fill(email)
        page.locator("#emailForm button[type='submit']").click()

        page.wait_for_url("**/login/verify**")
        mail = get_latest_email(to=email, timeout=10.0)
        assert mail is not None, f"No verification email at mid for {email}"
        code = extract_otp_code(mail)
        assert code is not None, "Could not extract verification code at mid"

        page.locator("#code").fill(code)
        page.locator("#verifyCodeForm button[type='submit']").click(no_wait_after=True)
        page.wait_for_timeout(2000)

        # Mid routes to upstream IdP. Navigate directly to SAML login.
        upstream_idp_id = mid_config["upstream_idp_id"]
        page.goto(f"{mid_base}/saml/login/{upstream_idp_id}")

        # Step 5: Upstream sees pre-authenticated user → consent for mid SP
        page.wait_for_url(f"{upstream_base}/saml/idp/consent**", timeout=15000)

        # Approve consent at upstream (sharing data with mid)
        page.locator("button", has_text="Continue").first.click()

        # Step 6-7: SAML Response → mid ACS → mid detects pending SSO → consent for leaf
        page.wait_for_url(f"{mid_base}/saml/idp/consent**", timeout=15000)

        # Approve consent at mid (sharing data with leaf)
        page.locator("button", has_text="Continue").first.click()

        # Step 8-9: SAML Response → leaf ACS → JIT-provision → dashboard
        page.wait_for_url(f"{leaf_base}/dashboard**", timeout=15000)
        assert "/dashboard" in page.url
