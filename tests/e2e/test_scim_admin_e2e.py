"""E2E tests for the outbound SCIM admin UI on the SP detail SCIM tab.

Coverage:
  * create-token plaintext display + reload
  * rotate -> overlap-window confirm -> new plaintext box + old row shows
    "expires" relative timestamp after reload
  * revoke -> confirm -> page reload, row removed from active list
  * retry dead-lettered -> seeded queue row -> confirm -> page reload,
    dead-letter count clears + queue count refreshes

The testbed (sso_testbed.py) already registers an SP between the IdP and SP
tenants. The SCIM tab is super-admin gated; we use the IdP super admin
because the SP lives in the IdP tenant.
"""

import subprocess

from tests.e2e.conftest import DOCKER_COMPOSE


def _run_sql(sql: str) -> str:
    """Execute a single SQL statement against the dev DB, return stdout."""
    result = subprocess.run(
        [
            *DOCKER_COMPOSE,
            "exec",
            "-T",
            "db",
            "psql",
            "-U",
            "postgres",
            "-d",
            "appdb",
            "-At",  # tuples-only, unaligned
            "-c",
            sql,
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"SQL failed (rc={result.returncode}): {result.stderr}\nSQL: {sql}")
    return result.stdout.strip()


def _seed_dead_letter_queue_row(tenant_id: str, sp_id: str) -> str:
    """Insert a dead-lettered `scim_push_queue` row directly via SQL.

    Returns the inserted row id. Mirrors what the worker would write after
    exhausting retries on a permanently failing push. Used by the E2E
    test to exercise the Retry-dead-lettered button without having to
    actually break a downstream and wait for the worker to give up.
    """
    sql = (
        "INSERT INTO scim_push_queue "
        "(tenant_id, sp_id, resource_type, resource_id, attempts, last_error, dead_letter_at) "
        f"VALUES ('{tenant_id}', '{sp_id}', 'user', gen_random_uuid(), 5, "
        "'seeded dead-letter for e2e', now()) RETURNING id;"
    )
    return _run_sql(sql)


def _clear_queue_rows_for_sp(sp_id: str) -> None:
    """Tidy queue rows for one SP. Best-effort cleanup between tests."""
    try:
        _run_sql(f"DELETE FROM scim_push_queue WHERE sp_id = '{sp_id}';")
    except Exception:
        pass


def _delete_credentials_for_sp(sp_id: str) -> None:
    """Tidy SCIM credentials for one SP between tests.

    Each rotate/revoke test creates and leaves residue; this keeps the
    SCIM tab in a deterministic baseline state for the next test.
    """
    try:
        _run_sql(f"DELETE FROM sp_scim_credentials WHERE sp_id = '{sp_id}';")
    except Exception:
        pass


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


class TestScimAdminRotateToken:
    """Super admin rotates a SCIM bearer token via the SCIM tab.

    Flow:
      1. Land on the SCIM tab and ensure at least one credential exists.
      2. Click Rotate on the existing credential.
      3. Confirm the overlap-window dialog.
      4. The amber plaintext box appears with the new token.
      5. Click Done -- the page reloads.
      6. Verify both the new credential row and the old credential row
         are visible. The old row shows the iteration 7b "expires" copy
         (a relative timestamp, e.g. "expires in a day").
    """

    def test_rotate_shows_plaintext_and_old_row_marks_expires(self, page, login, idp_config):
        idp_base = idp_config["base_url"]
        sp_id = idp_config["sp_id"]

        # Baseline: no residual credentials from a prior test in this session.
        _delete_credentials_for_sp(sp_id)

        login(idp_base, idp_config["admin_email"])

        # Go to the SCIM tab and create an initial token (the pre-rotate
        # credential). Reloading after Done leaves us on the tab with one
        # active credential row.
        page.goto(f"{idp_base}/admin/settings/service-providers/{sp_id}/scim")
        page.wait_for_selector("#scim-create-token", timeout=10000)
        page.locator("#scim-create-token").click()
        page.wait_for_selector("#scim-plaintext-display:not(.hidden)", timeout=10000)
        page.locator("#scim-plaintext-done").click()
        page.wait_for_load_state("networkidle", timeout=10000)
        page.wait_for_selector("#scim-credentials-list li[data-credential-id]", timeout=10000)

        before_rows = page.locator("#scim-credentials-list li[data-credential-id]")
        assert before_rows.count() == 1, "Test expects exactly one credential pre-rotate"
        old_credential_id = before_rows.first.get_attribute("data-credential-id")
        assert old_credential_id, "Expected data-credential-id on the existing row"

        # Click Rotate on the existing credential. WeftUtils.confirm pops the
        # shared confirm modal (#weft-confirm-modal); accept it.
        rotate_btn = page.locator(f'[data-op="rotate"][data-credential-id="{old_credential_id}"]')
        rotate_btn.click()
        page.wait_for_selector("#weft-confirm-modal:not(.hidden)", timeout=5000)
        page.locator("#weft-confirm-ok").click()

        # The plaintext box for the new token appears.
        page.wait_for_selector("#scim-plaintext-display:not(.hidden)", timeout=10000)
        new_token = page.locator("#scim-plaintext-value").text_content() or ""
        assert new_token.strip(), "Rotate must surface a new plaintext token"

        # Done reloads. After reload, both rows are present: the new active
        # credential AND the old credential with the "expires" label
        # (iter 7b copy fix on `cred.revoked_at` rendering).
        page.locator("#scim-plaintext-done").click()
        page.wait_for_load_state("networkidle", timeout=10000)
        page.wait_for_selector("#scim-credentials-list li[data-credential-id]", timeout=10000)

        after_rows = page.locator("#scim-credentials-list li[data-credential-id]")
        assert after_rows.count() >= 2, "Rotate must leave both old and new rows visible"

        # Find the old row by data-credential-id. It MUST carry the
        # "expires" copy (the iter 7b fix replaced "revoked" with
        # "expires" for the in-overlap-window state).
        old_row = page.locator(
            f'#scim-credentials-list li[data-credential-id="{old_credential_id}"]'
        )
        assert old_row.count() == 1
        old_row_text = old_row.text_content() or ""
        assert "expires" in old_row_text.lower(), (
            f"Old credential row must show 'expires' relative timestamp; "
            f"actual text: {old_row_text!r}"
        )

        # Tidy for the next test.
        _delete_credentials_for_sp(sp_id)


class TestScimAdminRevokeToken:
    """Super admin revokes a SCIM bearer token via the SCIM tab.

    After revoke + reload, the credential MUST disappear from the active
    list (`#scim-credentials-list li[data-credential-id]`). The empty
    state (`#scim-credentials-empty`) should reappear when no other
    credentials remain.
    """

    def test_revoke_removes_credential_from_active_list(self, page, login, idp_config):
        idp_base = idp_config["base_url"]
        sp_id = idp_config["sp_id"]

        _delete_credentials_for_sp(sp_id)

        login(idp_base, idp_config["admin_email"])
        page.goto(f"{idp_base}/admin/settings/service-providers/{sp_id}/scim")
        page.wait_for_selector("#scim-create-token", timeout=10000)

        # Create a token (test fixture), then dismiss the plaintext box.
        page.locator("#scim-create-token").click()
        page.wait_for_selector("#scim-plaintext-display:not(.hidden)", timeout=10000)
        page.locator("#scim-plaintext-done").click()
        page.wait_for_load_state("networkidle", timeout=10000)
        page.wait_for_selector("#scim-credentials-list li[data-credential-id]", timeout=10000)

        before_rows = page.locator("#scim-credentials-list li[data-credential-id]")
        assert before_rows.count() == 1
        credential_id = before_rows.first.get_attribute("data-credential-id")
        assert credential_id

        # Click Revoke and confirm. The DELETE call + reload happens inside
        # the confirm callback; wait for the navigation/reload to settle
        # using `expect_navigation` so we don't race the assertion.
        with page.expect_navigation(wait_until="load", timeout=15000):
            page.locator(f'[data-op="revoke"][data-credential-id="{credential_id}"]').click()
            page.wait_for_selector("#weft-confirm-modal:not(.hidden)", timeout=5000)
            page.locator("#weft-confirm-ok").click()

        # Tab content should be fully reloaded.
        page.wait_for_selector("#scim-create-token", timeout=10000)
        # Give the credential list a moment to render its post-revoke state.
        page.wait_for_load_state("networkidle", timeout=10000)

        revoked_row = page.locator(
            f'#scim-credentials-list li[data-credential-id="{credential_id}"]'
        )
        assert revoked_row.count() == 0, (
            "Revoked credential must be gone from the active credentials list"
        )

        _delete_credentials_for_sp(sp_id)


class TestScimAdminRetryDeadLettered:
    """Super admin retries dead-lettered queue rows via the Retry button.

    Seeds a dead-lettered row directly into `scim_push_queue` via SQL
    (approach (a) -- see ITERATION_outbound_scim.md). After clicking the
    Retry button + confirming, the worker treats the row as fresh; the
    dead-letter counter clears on reload and the pending count
    increments by 1.
    """

    def test_retry_dead_lettered_button_revives_seeded_row(self, page, login, idp_config):
        idp_base = idp_config["base_url"]
        sp_id = idp_config["sp_id"]
        tenant_id = idp_config["tenant_id"]

        # Baseline: clear any residual queue rows so counters start at 0.
        _clear_queue_rows_for_sp(sp_id)

        # Seed one dead-lettered row directly.
        _seed_dead_letter_queue_row(tenant_id=tenant_id, sp_id=sp_id)

        login(idp_base, idp_config["admin_email"])
        page.goto(f"{idp_base}/admin/settings/service-providers/{sp_id}/scim")
        page.wait_for_selector("#scim-queue-dead", timeout=10000)

        # Sanity: the dead counter shows 1 and the Retry button is visible.
        dead_text = page.locator("#scim-queue-dead").text_content() or ""
        assert dead_text.strip() == "1", (
            f"Expected one dead-lettered row pre-click; got {dead_text!r}"
        )
        retry_btn = page.locator("#scim-retry-dead-letter")
        assert retry_btn.is_visible(), "Retry-dead-lettered button must be visible when dead > 0"

        # Click + confirm.
        retry_btn.click()
        page.wait_for_selector("#weft-confirm-modal:not(.hidden)", timeout=5000)
        page.locator("#weft-confirm-ok").click()

        # The endpoint clears `dead_letter_at` and resets attempts; the JS
        # reloads. After reload the dead counter should be 0 and the
        # pending counter should be 1 (the row was revived, not deleted).
        page.wait_for_load_state("networkidle", timeout=10000)
        page.wait_for_selector("#scim-queue-dead", timeout=10000)

        dead_text_after = page.locator("#scim-queue-dead").text_content() or ""
        pending_text_after = page.locator("#scim-queue-pending").text_content() or ""
        assert dead_text_after.strip() == "0", (
            f"Dead counter must be 0 after retry; got {dead_text_after!r}"
        )
        assert pending_text_after.strip() == "1", (
            f"Pending counter must reflect revived row (1); got {pending_text_after!r}"
        )

        # The Retry button is conditional on dead > 0, so it should now be gone.
        retry_btn_after = page.locator("#scim-retry-dead-letter")
        assert retry_btn_after.count() == 0, (
            "Retry-dead-lettered button must be hidden when dead_lettered == 0"
        )

        _clear_queue_rows_for_sp(sp_id)
