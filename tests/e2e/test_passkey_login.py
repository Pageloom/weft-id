"""E2E: passkey registration + passkey sign-in via Playwright virtual authenticator.

Uses Chrome DevTools Protocol's `WebAuthn.*` domain to attach a virtual
platform authenticator to the page. The authenticator handles the full
FIDO2 registration and assertion ceremonies so both the iteration 2
registration path and the iteration 3 login path run end-to-end.
"""


def _enable_virtual_authenticator(page):
    """Attach a platform-style virtual authenticator via CDP.

    Returns the Chrome WebAuthn authenticator id.
    """
    cdp = page.context.new_cdp_session(page)
    cdp.send("WebAuthn.enable", {"enableUI": False})
    result = cdp.send(
        "WebAuthn.addVirtualAuthenticator",
        {
            "options": {
                "protocol": "ctap2",
                "transport": "internal",
                "hasResidentKey": True,
                "hasUserVerification": True,
                "isUserVerified": True,
                "automaticPresenceSimulation": True,
            }
        },
    )
    return cdp, result["authenticatorId"]


def test_passkey_register_then_sign_in(page, idp_config):
    """Register a passkey via the account page, sign out, then sign in with it."""
    base_url = idp_config["base_url"]
    email = idp_config["admin_email"]
    password = idp_config["admin_password"]

    # 1. Attach a virtual authenticator BEFORE any WebAuthn ceremony.
    cdp, _auth_id = _enable_virtual_authenticator(page)

    # 2. Sign in with password + email MFA to reach the account passkeys page.
    page.goto(f"{base_url}/login")
    page.locator("#email").fill(email)
    page.locator("#emailForm button[type='submit']").click()
    page.wait_for_url("**/login?**show_password**", timeout=10000)

    page.locator("input[name='password']").fill(password)
    page.locator("#loginForm button[type='submit']").click()

    page.wait_for_url("**/mfa/verify**", timeout=10000)
    page.locator("#code").fill("123456")
    page.locator("#mfaVerifyForm button[type='submit']").click()
    page.wait_for_url("**/dashboard**", timeout=10000)

    # 3. Register a passkey.
    page.goto(f"{base_url}/account/passkeys")
    page.locator("#register-passkey-btn").click()
    page.locator("#passkey-name-input").fill("E2E Virtual Key")
    page.locator("#passkey-name-confirm").click()

    # Wait for the backup-codes modal OR the registered-success redirect.
    # A first passkey registration shows the backup-codes modal; subsequent
    # runs against a re-used tenant would redirect. Handle both.
    try:
        page.wait_for_selector("#passkey-backup-modal:not(.hidden)", timeout=15000)
        page.locator("#passkey-backup-close").click()
    except Exception:
        # Possibly redirected straight to the listing on a re-run. Continue.
        pass
    page.wait_for_url("**/account/passkeys**", timeout=10000)
    # The registered passkey appears in the list.
    assert page.locator("text=E2E Virtual Key").count() >= 1

    # 4. Sign out (clear session). /logout is a POST route; submit the form
    # directly via JS to avoid relying on the user-menu open state.
    page.goto(f"{base_url}/dashboard")
    page.locator("form[action='/logout']").first.evaluate("form => form.submit()")
    page.wait_for_url("**/login**", timeout=10000)

    # 5. Sign in again. After entering the email, the passkey-first variant
    # should render and auto-complete the ceremony.
    page.goto(f"{base_url}/login")
    page.locator("#email").fill(email)
    page.locator("#emailForm button[type='submit']").click()

    page.wait_for_url("**/login?**show_password**", timeout=10000)
    # Passkey-first UI markers
    assert page.locator("#passkey-flow").count() == 1
    # Ceremony completes and lands on the dashboard without password or MFA.
    page.wait_for_url("**/dashboard**", timeout=15000)

    # 6. Clean up: delete the passkey so sibling tests that log in with
    # password + MFA still see the plain password form. Tenants in the
    # session-scoped testbed are shared across tests.
    page.goto(f"{base_url}/account/passkeys")
    delete_form = page.locator("form[action*='/delete']").first
    if delete_form.count() > 0:
        delete_form.evaluate("form => form.submit()")
        page.wait_for_url("**/account/passkeys?**", timeout=10000)


def test_passkey_first_hidden_for_password_only_user(page, sp_config):
    """A user without any passkey must see the plain password form."""
    base_url = sp_config["base_url"]
    email = sp_config["admin_email"]

    page.goto(f"{base_url}/login")
    page.locator("#email").fill(email)
    page.locator("#emailForm button[type='submit']").click()
    page.wait_for_url("**/login?**show_password**", timeout=10000)

    # Plain password form: no passkey-flow container.
    assert page.locator("#passkey-flow").count() == 0
    assert page.locator("#loginForm input[name='password']").count() == 1
