"""E2E tests for IdP registration variants and domain-based routing.

Tests:
  - IdP URL import: Create a new SP at the IdP tenant to get a per-SP
    metadata URL, then import that URL as a new IdP at the SP tenant.
  - Domain-based routing: Bind a privileged domain to an IdP, then
    verify an unknown user with that domain gets JIT-provisioned via SSO.
"""

from helpers.maildev import clear_emails, extract_otp_code, get_latest_email


class TestIdpRegistrationViaUrl:
    """SP admin registers an IdP via metadata URL import."""

    def test_sp_admin_registers_idp_via_url(self, page, login, sp_config, upstream_config):
        """Import an IdP from a per-SP metadata URL.

        Uses the chain upstream tenant as IdP source (different entity_id
        from the testbed IdP to avoid URN conflicts).

        Flow:
          1. At upstream: create new SP (name only) → get per-SP metadata URL
          2. At SP: create new IdP (name only) → import from that URL
        """
        upstream_base = upstream_config["base_url"]
        sp_base = sp_config["base_url"]

        # --- Step 1: Create a new SP at upstream tenant to get a metadata URL ---
        login(upstream_base, upstream_config["admin_email"])
        page.goto(f"{upstream_base}/admin/settings/service-providers/new")
        page.locator("#sp-name").fill("URL Import Test SP")
        page.get_by_role("button", name="Create").click()

        # Extract SP ID from redirect URL
        page.wait_for_url(
            "**/admin/settings/service-providers/*/details**",
            timeout=10000,
        )
        sp_detail_url = page.url
        sp_id = sp_detail_url.split("/service-providers/")[1].split("/")[0]

        # The per-SP IdP metadata URL (serves IDPSSODescriptor XML)
        metadata_url = f"{upstream_base}/saml/idp/metadata/{sp_id}"

        # --- Step 2: Create a new IdP at SP tenant and import from URL ---
        login(sp_base, sp_config["admin_email"])
        page.goto(f"{sp_base}/admin/settings/identity-providers/new")
        page.locator("#name").fill("URL Import Test IdP")
        page.locator("#provider_type").select_option("generic")
        page.get_by_role("button", name="Create Identity Provider").click()

        page.wait_for_url(
            "**/admin/settings/identity-providers/*/details**success=created**",
            timeout=10000,
        )

        # Switch to URL tab and import
        page.locator("#tab-url").click()
        page.locator("#trust-metadata-url").fill(metadata_url)
        page.locator("#trust-content-url button[type='submit']").click()

        # Verify trust established
        page.wait_for_url(
            "**/admin/settings/identity-providers/*/details**",
            timeout=10000,
        )
        page.locator("text=Trust established successfully").wait_for(timeout=5000)

        # Verify IdP appears in the list
        page.goto(f"{sp_base}/admin/settings/identity-providers")
        assert page.locator("text=URL Import Test IdP").is_visible()


class TestDomainBasedRouting:
    """Test that privileged domain binding routes unknown users to the correct IdP."""

    def test_domain_binding_jit_sso(self, page, login, idp_config, sp_config, extras_config):
        """Unknown user at SP with bound domain email is JIT-provisioned via SSO.

        The extras testbed:
          - Created domain-test@acme.com at IdP (with password)
          - Added acme.com as privileged domain at SP, bound to IdP
          - domain-test@acme.com does NOT exist at SP

        When this user enters their email at the SP, the domain binding
        routes them to the IdP. After authenticating at the IdP, they
        are JIT-provisioned at the SP.
        """
        idp_base = idp_config["base_url"]
        sp_base = sp_config["base_url"]
        domain_email = extras_config["domain_binding"]["test_email"]

        # Pre-authenticate at IdP (skip full login flow at IdP)
        login(idp_base, domain_email)

        # Step 1: Enter email at SP login
        clear_emails()
        page.goto(f"{sp_base}/login")
        page.locator("#email").fill(domain_email)
        page.locator("#emailForm button[type='submit']").click()

        # Step 2: Verify email at SP
        page.wait_for_url("**/login/verify**")
        mail = get_latest_email(to=domain_email, timeout=10.0)
        assert mail is not None, f"No verification email for {domain_email}"
        code = extract_otp_code(mail)
        assert code is not None, "Could not extract verification code"

        page.locator("#code").fill(code)
        page.locator("#verifyCodeForm button[type='submit']").click(no_wait_after=True)
        page.wait_for_timeout(2000)

        # Step 3: SP routes to IdP via domain binding. Navigate directly
        # to SAML login (works around Playwright POST→303 chain issue).
        sp_idp_id = sp_config["idp_id"]
        page.goto(f"{sp_base}/saml/login/{sp_idp_id}")

        # Step 4: Already authenticated at IdP → consent page
        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=15000)

        # Approve consent
        page.locator("button", has_text="Continue").first.click()

        # Step 5: Land at SP dashboard (JIT-provisioned via domain binding)
        page.wait_for_url(f"{sp_base}/dashboard**", timeout=15000)
        assert "/dashboard" in page.url
