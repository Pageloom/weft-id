"""E2E test for the outbound SCIM admin UI on the SP detail SCIM tab.

Exercises the create-token plaintext-display flow end-to-end:
  1. Super-admin lands on `/admin/settings/service-providers/{sp_id}/scim`.
  2. Clicks "Create token".
  3. The amber plaintext box appears with the token visible.
  4. The Copy button is clickable (we do not require clipboard permissions
     to grant, only that the button responds to the click).
  5. Clicking Done triggers a reload.
  6. After reload, a new credential row is visible in the active list.

The testbed (sso_testbed.py) already registers an SP between the IdP and SP
tenants. The SCIM tab is super-admin gated; we use the IdP super admin
because the SP lives in the IdP tenant.
"""


class TestScimAdminCreateToken:
    """Super admin creates a SCIM bearer token via the SCIM tab."""

    def test_create_token_shows_plaintext_and_reloads(self, page, login, idp_config):
        """Create a SCIM bearer token; amber box renders; Done reloads to a new row."""
        idp_base = idp_config["base_url"]
        sp_id = idp_config["sp_id"]

        # Login to IdP as super admin
        login(idp_base, idp_config["admin_email"])

        # Navigate to the SCIM tab for the existing registered SP.
        scim_url = f"{idp_base}/admin/settings/service-providers/{sp_id}/scim"
        page.goto(scim_url)
        page.wait_for_url("**/scim**", timeout=10000)

        # Sanity: the create-token control is present, the plaintext box is hidden.
        create_btn = page.locator("#scim-create-token")
        create_btn.wait_for(timeout=10000)
        plaintext_box = page.locator("#scim-plaintext-display")
        assert "hidden" in (plaintext_box.get_attribute("class") or "")

        # Click "Create token" -- the JS calls the API and reveals the amber box.
        create_btn.click()

        # The amber plaintext box becomes visible and the value is populated.
        page.wait_for_selector("#scim-plaintext-display:not(.hidden)", timeout=10000)
        plaintext_value = page.locator("#scim-plaintext-value")
        plaintext_value.wait_for(timeout=5000)
        token = plaintext_value.text_content() or ""
        assert token.strip(), "Plaintext token should be displayed in the amber box"

        # Copy button is present and clickable.
        copy_btn = page.locator("#scim-plaintext-copy")
        assert copy_btn.is_visible()
        copy_btn.click()  # Clicking is enough; we don't assert clipboard contents

        # Click Done -- triggers window.location.reload().
        done_btn = page.locator("#scim-plaintext-done")
        done_btn.click()

        # After reload, the credential list is populated. The empty-state paragraph
        # (`#scim-credentials-empty`) should be gone, and at least one
        # `[data-credential-id]` row should be visible.
        page.wait_for_load_state("networkidle", timeout=10000)
        page.wait_for_selector("#scim-credentials-list li[data-credential-id]", timeout=10000)
        rows = page.locator("#scim-credentials-list li[data-credential-id]")
        assert rows.count() >= 1, "Expected at least one credential row after create"
