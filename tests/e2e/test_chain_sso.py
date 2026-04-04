"""E2E test for three-tenant passthrough SSO.

Tests the chain: leaf SP -> mid IdP/SP -> upstream IdP

The chain testbed provisions three tenants:
  - e2e-upstream: the ultimate IdP (authenticates users)
  - e2e-mid: acts as IdP for leaf AND as SP of upstream
  - e2e-leaf: the leaf SP (where the user starts)

Chain user: chain-user@upstream.test
  - Exists at upstream with password (for authentication)
  - Exists at mid linked to upstream IdP (SAML-only)
  - Does NOT exist at leaf (JIT-provisioned via domain binding)

Domain binding at leaf: upstream.test -> mid IdP
"""


class TestChainPassthroughSso:
    """Three-tenant passthrough: leaf -> mid -> upstream -> authenticate -> cascade back."""

    def test_chain_sso_passthrough(
        self, page, login, upstream_config, mid_config, leaf_config, chain_user
    ):
        """Full three-tenant SSO chain with passthrough authentication.

        Flow (with direct routing, no email verification):
          1. Navigate to leaf SAML login (domain binding routes to mid IdP)
          2. Mid receives AuthnRequest, stores pending SSO, redirects to login
          3. Navigate to mid SAML login (mid routes to upstream IdP)
          4. Upstream sees pre-authenticated user -> consent page
          5. User approves -> SAML Response to mid ACS
          6. Mid processes response, detects pending SSO for leaf -> consent
          7. User approves -> SAML Response to leaf ACS
          8. Leaf JIT-provisions user -> dashboard

        Pre-authentication at upstream (step 0) reduces the test to
        2 consent approvals.
        """
        upstream_base = upstream_config["base_url"]
        mid_base = mid_config["base_url"]
        leaf_base = leaf_config["base_url"]
        email = chain_user["email"]

        # Step 0: Pre-authenticate at upstream (skip full login there)
        login(upstream_base, email)

        # Step 1: Leaf routes to mid IdP via domain binding.
        # Navigate directly to SAML login (Playwright POST->303 workaround).
        mid_idp_id = leaf_config["mid_idp_id"]
        page.goto(f"{leaf_base}/saml/login/{mid_idp_id}")

        # Mid receives AuthnRequest, user not authenticated at mid -> login page
        page.wait_for_url(f"{mid_base}/login**", timeout=15000)

        # Step 2: At mid, the user's email domain routes to upstream IdP.
        # Navigate directly to mid SAML login (Playwright workaround).
        upstream_idp_id = mid_config["upstream_idp_id"]
        page.goto(f"{mid_base}/saml/login/{upstream_idp_id}")

        # Step 3: Upstream sees pre-authenticated user -> consent for mid SP
        page.wait_for_url(f"{upstream_base}/saml/idp/consent**", timeout=15000)

        # Approve consent at upstream (sharing data with mid)
        page.locator("button", has_text="Continue").first.click()

        # Step 4-5: SAML Response -> mid ACS -> mid detects pending SSO -> consent for leaf
        page.wait_for_url(f"{mid_base}/saml/idp/consent**", timeout=15000)

        # Approve consent at mid (sharing data with leaf)
        page.locator("button", has_text="Continue").first.click()

        # Step 6-7: SAML Response -> leaf ACS -> JIT-provision -> dashboard
        page.wait_for_url(f"{leaf_base}/dashboard**", timeout=15000)
        assert "/dashboard" in page.url
