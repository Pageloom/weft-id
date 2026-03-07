"""E2E tests for SP registration variants.

Tests:
  - SP URL import: Import an SP from a live per-IdP metadata URL
  - SP manual configuration: Establish trust via manual entity_id + ACS URL entry

Uses the two-tenant testbed for both tests.
"""

# Minimal SP metadata with a unique entity ID for manual config testing.
# This entity_id must not conflict with any testbed-registered SPs.
_MANUAL_ENTITY_ID = "https://manual-test-sp.example.com/saml/metadata"
_MANUAL_ACS_URL = "https://manual-test-sp.example.com/saml/acs"


class TestSpRegistrationViaUrl:
    """IdP admin registers an SP via per-IdP SP metadata URL import."""

    def test_idp_admin_registers_sp_via_url(self, page, login, idp_config, mid_config):
        """Import an SP from a live per-IdP SP metadata URL.

        Uses the chain mid tenant as SP source (different entity_id from
        the testbed SP to avoid URN conflicts).

        Flow:
          1. At mid (acting as SP): create new IdP → get per-IdP SP metadata URL
          2. At IdP: create new SP and import from that URL
        """
        idp_base = idp_config["base_url"]
        mid_base = mid_config["base_url"]

        # Step 1: Create a new IdP at mid tenant to get a per-IdP SP metadata URL.
        # Creating an IdP auto-generates a per-IdP SP certificate, so the
        # metadata endpoint serves valid XML immediately.
        login(mid_base, mid_config["admin_email"])
        page.goto(f"{mid_base}/admin/settings/identity-providers/new")
        page.locator("#name").fill("URL Import Source IdP")
        page.locator("#provider_type").select_option("generic")
        page.get_by_role("button", name="Create Identity Provider").click()

        page.wait_for_url(
            "**/admin/settings/identity-providers/*/details**",
            timeout=10000,
        )

        # Extract IdP ID from redirect URL to build per-IdP SP metadata URL
        idp_detail_url = page.url
        new_idp_id = idp_detail_url.split("/identity-providers/")[1].split("/")[0]
        sp_metadata_url = f"{mid_base}/saml/metadata/{new_idp_id}"

        # Step 2: At IdP tenant, create a new SP and import from that URL
        login(idp_base, idp_config["admin_email"])
        page.goto(f"{idp_base}/admin/settings/service-providers/new")
        page.locator("#sp-name").fill("SP Metadata Import Test")
        page.get_by_role("button", name="Create").click()

        page.wait_for_url(
            "**/admin/settings/service-providers/*/details**success=created**",
            timeout=10000,
        )

        # Switch to URL tab and import from the per-IdP SP metadata URL
        page.locator("[data-tab='trust-url']").click()
        page.locator("#trust-metadata-url").fill(sp_metadata_url)
        page.locator("#tab-trust-url button[type='submit']").click()

        # Verify trust established: URN entity_id visible on details page
        page.wait_for_url(
            "**/admin/settings/service-providers/*/details**",
            timeout=10000,
        )
        page.get_by_text("urn:weftid:").first.wait_for(timeout=5000)

        # Verify SP appears in the list
        page.goto(f"{idp_base}/admin/settings/service-providers")
        assert page.locator("text=SP Metadata Import Test").is_visible()


class TestSpManualConfiguration:
    """IdP admin registers an SP via manual configuration."""

    def test_idp_admin_registers_sp_manually(self, page, login, idp_config):
        """Create an SP and establish trust via manual entry of entity_id and ACS URL.

        Manual configuration is the fallback when SP metadata is not available.
        It requires entering at minimum the entity_id and ACS URL.
        """
        idp_base = idp_config["base_url"]

        # Login to IdP as admin
        login(idp_base, idp_config["admin_email"])

        # Step 1: Create SP with name only
        page.goto(f"{idp_base}/admin/settings/service-providers/new")
        page.locator("#sp-name").fill("Manual Config Test SP")
        page.get_by_role("button", name="Create").click()

        page.wait_for_url(
            "**/admin/settings/service-providers/*/details**success=created**",
            timeout=10000,
        )

        # Step 2: Switch to Manual tab and fill in entity_id + ACS URL
        page.locator("[data-tab='trust-manual']").click()
        page.locator("#trust-entity-id").fill(_MANUAL_ENTITY_ID)
        page.locator("#trust-acs-url").fill(_MANUAL_ACS_URL)
        page.locator("#tab-trust-manual button[type='submit']").click()

        # Verify trust established: Entity ID visible on the details page
        page.wait_for_url(
            "**/admin/settings/service-providers/*/details**",
            timeout=10000,
        )
        page.get_by_text(_MANUAL_ENTITY_ID).first.wait_for(timeout=5000)

        # Verify SP appears in the list
        page.goto(f"{idp_base}/admin/settings/service-providers")
        assert page.locator("text=Manual Config Test SP").is_visible()
