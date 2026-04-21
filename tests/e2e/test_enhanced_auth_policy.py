"""E2E: Enhanced auth policy enforcement across all login paths.

Tests the tenant-level ``required_auth_strength = 'enhanced'`` policy
end-to-end through a real browser. These flows cannot be covered by
unit/integration tests because they involve:

- WebAuthn ceremony auto-start, abandonment, and fallback
- Multi-step redirect chains with session state across pages
- Browser-side JS driving the passkey-first UX
- Full enrollment page interaction (passkey registration during enrollment)

Uses the two-tenant testbed's IdP tenant (``idp_config``).
"""

import subprocess

import pytest

from tests.e2e.conftest import DOCKER_COMPOSE

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_OTP_BYPASS_CODE = "123456"


def _set_auth_policy(subdomain: str, policy: str):
    """Set ``required_auth_strength`` for a tenant via SQL.

    Uses INSERT ON CONFLICT so it works whether or not the security
    settings row already exists.
    """
    sql = (
        f"INSERT INTO tenant_security_settings "
        f"(tenant_id, required_auth_strength) "
        f"SELECT id, '{policy}' FROM tenants WHERE subdomain = '{subdomain}' "
        f"ON CONFLICT (tenant_id) DO UPDATE "
        f"SET required_auth_strength = '{policy}';"
    )
    subprocess.run(
        [*DOCKER_COMPOSE, "exec", "-T", "db", "psql", "-U", "postgres", "-d", "appdb", "-c", sql],
        capture_output=True,
        timeout=10,
    )


def _delete_all_passkeys_for_admin(subdomain: str):
    """Remove all webauthn_credentials for the admin user of a tenant."""
    sql = (
        f"DELETE FROM webauthn_credentials "
        f"WHERE user_id IN ("
        f"  SELECT u.id FROM users u "
        f"  JOIN tenants t ON u.tenant_id = t.id "
        f"  WHERE t.subdomain = '{subdomain}' AND u.role = 'super_admin'"
        f");"
    )
    subprocess.run(
        [*DOCKER_COMPOSE, "exec", "-T", "db", "psql", "-U", "postgres", "-d", "appdb", "-c", sql],
        capture_output=True,
        timeout=10,
    )


def _enable_virtual_authenticator(page):
    """Attach a platform-style virtual authenticator via CDP.

    Returns ``(cdp_session, authenticator_id)``.
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


def _sign_in_with_password_and_otp(page, base_url, email, password):
    """Sign in via the password + email OTP path (bypass OTP)."""
    page.goto(f"{base_url}/login")
    page.locator("#email").fill(email)
    page.locator("#emailForm button[type='submit']").click()
    page.wait_for_url("**/login?**show_password**", timeout=10000)

    page.locator("input[name='password']").fill(password)
    page.locator("#loginForm button[type='submit']").click()

    page.wait_for_url("**/mfa/verify**", timeout=10000)
    page.locator("#code").fill(_OTP_BYPASS_CODE)
    page.locator("#mfaVerifyForm button[type='submit']").click()
    page.wait_for_load_state("networkidle", timeout=10000)


def _register_passkey_via_account_page(page, base_url, name="E2E Policy Key"):
    """Register a passkey on /account/mfa. Virtual authenticator must be active."""
    page.goto(f"{base_url}/account/mfa")
    page.locator("#register-passkey-btn").click()
    page.locator("#passkey-name-input").fill(name)
    page.locator("#passkey-name-confirm").click()

    try:
        page.wait_for_selector("#passkey-backup-modal:not(.hidden)", timeout=15000)
        page.locator("#passkey-backup-close").click()
    except Exception:
        pass
    page.wait_for_url("**/account/mfa**", timeout=10000)
    assert page.locator(f"text={name}").count() >= 1


def _sign_out(page, base_url):
    """Sign out by submitting the logout form."""
    page.goto(f"{base_url}/dashboard")
    page.locator("form[action='/logout']").first.evaluate("form => form.submit()")
    page.wait_for_url("**/login**", timeout=10000)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEnhancedPolicyEnforcement:
    """Enhanced auth policy blocks email OTP and forces enrollment."""

    def test_email_only_user_redirected_to_enrollment(self, page, idp_config):
        """Under enhanced policy, a user with only email MFA is redirected
        to the enrollment page after successful password + email OTP login."""
        base_url = idp_config["base_url"]
        email = idp_config["admin_email"]
        password = idp_config["admin_password"]
        subdomain = idp_config["subdomain"]

        _delete_all_passkeys_for_admin(subdomain)
        _set_auth_policy(subdomain, "enhanced")
        try:
            _sign_in_with_password_and_otp(page, base_url, email, password)
            assert "/login/enroll-enhanced-auth" in page.url, (
                f"Expected enrollment redirect, got {page.url}"
            )
            assert page.locator("text=Set up enhanced sign-in").count() >= 1
        finally:
            _set_auth_policy(subdomain, "baseline")

    def test_totp_user_passes_enhanced_policy(self, page, idp_config):
        """Under enhanced policy, a user who completes TOTP enrollment on
        the enforcement page reaches the dashboard on the same sign-in."""
        base_url = idp_config["base_url"]
        email = idp_config["admin_email"]
        password = idp_config["admin_password"]
        subdomain = idp_config["subdomain"]

        _delete_all_passkeys_for_admin(subdomain)
        _set_auth_policy(subdomain, "enhanced")
        try:
            # Sign in -> should land on enrollment page
            _sign_in_with_password_and_otp(page, base_url, email, password)
            assert "/login/enroll-enhanced-auth" in page.url

            # The enrollment page shows a TOTP secret inside a <details>.
            # Open it and read the secret key from the <code> element.
            page.locator("details summary").click()
            secret_el = page.locator("details code")
            secret_el.wait_for(timeout=5000)
            raw_secret = secret_el.text_content() or ""
            # Strip spaces, newlines, and any non-base32 characters
            import re

            secret = re.sub(r"[^A-Z2-7]", "", raw_secret.upper())

            import pyotp

            totp = pyotp.TOTP(secret)
            code = totp.now()

            page.locator("#code").fill(code)
            page.locator("form[action='/login/enroll-enhanced-auth'] button[type='submit']").click()
            page.wait_for_load_state("networkidle", timeout=10000)

            assert "/dashboard" in page.url, f"Expected dashboard, got {page.url}"
        finally:
            _set_auth_policy(subdomain, "baseline")
            # Reset MFA back to email so the admin user is in a clean state.
            # The TOTP enrollment changed mfa_method to 'totp'; undo that.
            sql = (
                f"UPDATE users SET mfa_method = 'email' "
                f"WHERE tenant_id = (SELECT id FROM tenants WHERE subdomain = '{subdomain}') "
                f"AND role = 'super_admin';"
            )
            subprocess.run(
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
                    "-c",
                    sql,
                ],
                capture_output=True,
                timeout=10,
            )
            # Also delete the mfa_totp row
            sql2 = (
                f"DELETE FROM mfa_totp WHERE user_id IN ("
                f"  SELECT u.id FROM users u JOIN tenants t ON u.tenant_id = t.id "
                f"  WHERE t.subdomain = '{subdomain}' AND u.role = 'super_admin'"
                f");"
            )
            subprocess.run(
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
                    "-c",
                    sql2,
                ],
                capture_output=True,
                timeout=10,
            )


class TestEnhancedPolicyPasskeyInteraction:
    """Tests for passkey + enhanced policy interaction.

    These require a virtual authenticator for WebAuthn ceremonies.
    """

    def test_passkey_login_succeeds_under_enhanced(self, page, idp_config):
        """Under enhanced policy, passkey login goes straight to dashboard
        with no enrollment gate (passkey IS the strong factor)."""
        base_url = idp_config["base_url"]
        email = idp_config["admin_email"]
        password = idp_config["admin_password"]
        subdomain = idp_config["subdomain"]

        cdp, auth_id = _enable_virtual_authenticator(page)
        try:
            # Register a passkey under baseline policy first
            _sign_in_with_password_and_otp(page, base_url, email, password)
            _register_passkey_via_account_page(page, base_url)
            _sign_out(page, base_url)

            # Now set enhanced policy and sign in with passkey
            _set_auth_policy(subdomain, "enhanced")

            page.goto(f"{base_url}/login")
            page.locator("#email").fill(email)
            page.locator("#emailForm button[type='submit']").click()
            page.wait_for_url("**/login?**show_password**", timeout=10000)

            # Passkey-first UI auto-starts; virtual auth auto-completes
            assert page.locator("#passkey-flow").count() == 1
            page.wait_for_url("**/dashboard**", timeout=15000)
        finally:
            _set_auth_policy(subdomain, "baseline")
            _delete_all_passkeys_for_admin(subdomain)

    @pytest.mark.xfail(
        reason="BUG: user_must_enroll_enhanced checks passkey existence, not usage. "
        "A user with a registered passkey can bypass enhanced policy via "
        "password + email OTP by abandoning the passkey ceremony.",
        strict=True,
    )
    def test_passkey_user_cannot_bypass_via_email_otp(self, page, idp_config):
        """Under enhanced policy, a user who has a passkey but abandons the
        ceremony and falls back to password + email OTP should NOT reach
        the dashboard. The policy says email OTP is not acceptable.

        Current behavior (BUG): ``user_must_enroll_enhanced`` returns False
        because the user has a passkey, allowing email OTP login to complete.

        Expected behavior: the user should be blocked or redirected, because
        they authenticated with a weak factor despite having a strong one.
        """
        base_url = idp_config["base_url"]
        email = idp_config["admin_email"]
        password = idp_config["admin_password"]
        subdomain = idp_config["subdomain"]

        cdp, auth_id = _enable_virtual_authenticator(page)
        try:
            # Register a passkey under baseline
            _sign_in_with_password_and_otp(page, base_url, email, password)
            _register_passkey_via_account_page(page, base_url)
            _sign_out(page, base_url)

            # Remove the virtual authenticator so the ceremony will fail
            # when the browser tries navigator.credentials.get() with no
            # authenticator available. This simulates the user abandoning
            # the passkey ceremony (NotAllowedError -> password form).
            cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": auth_id})

            # Set enhanced policy
            _set_auth_policy(subdomain, "enhanced")

            # Login: passkey ceremony will fail without an authenticator.
            # Click "Use password instead" to skip it immediately.
            page.goto(f"{base_url}/login")
            page.locator("#email").fill(email)
            page.locator("#emailForm button[type='submit']").click()
            page.wait_for_url("**/login?**show_password**", timeout=10000)

            page.locator("#use-password-link").click()
            page.locator("input[name='password']").fill(password)
            page.locator("#loginForm button[type='submit']").click()

            # MFA verify with email OTP
            page.wait_for_url("**/mfa/verify**", timeout=10000)
            page.locator("#code").fill(_OTP_BYPASS_CODE)
            page.locator("#mfaVerifyForm button[type='submit']").click()
            page.wait_for_load_state("networkidle", timeout=10000)

            # EXPECTED: should NOT be on dashboard (enrollment required)
            assert "/dashboard" not in page.url, (
                "BUG: user reached dashboard via email OTP under enhanced policy "
                "despite having a registered passkey. The enhanced policy should "
                "block email OTP regardless of passkey existence."
            )
            assert "/login/enroll-enhanced-auth" in page.url
        finally:
            _set_auth_policy(subdomain, "baseline")
            _delete_all_passkeys_for_admin(subdomain)

    def test_enrollment_via_passkey_completes_login(self, page, idp_config):
        """Under enhanced policy, an email-only user who registers a passkey
        on the enrollment page completes sign-in and reaches the dashboard."""
        base_url = idp_config["base_url"]
        email = idp_config["admin_email"]
        password = idp_config["admin_password"]
        subdomain = idp_config["subdomain"]

        _delete_all_passkeys_for_admin(subdomain)
        _set_auth_policy(subdomain, "enhanced")
        cdp, auth_id = _enable_virtual_authenticator(page)
        try:
            # Sign in -> land on enrollment page
            _sign_in_with_password_and_otp(page, base_url, email, password)
            assert "/login/enroll-enhanced-auth" in page.url

            # Register a passkey on the enrollment page
            page.locator("#register-passkey-btn").click()
            page.locator("#passkey-name-input").wait_for(timeout=5000)
            page.locator("#passkey-name-input").fill("E2E Enrollment Key")
            page.locator("#passkey-name-confirm").click()

            # Backup codes modal may appear on first passkey registration
            try:
                page.wait_for_selector("#passkey-backup-modal:not(.hidden)", timeout=15000)
                page.locator("#passkey-backup-close").click()
            except Exception:
                pass

            # After closing the backup modal (or if none), JS navigates to
            # the redirect_url returned by the server.
            page.wait_for_url("**/dashboard**", timeout=15000)
        finally:
            _set_auth_policy(subdomain, "baseline")
            _delete_all_passkeys_for_admin(subdomain)


class TestBaselinePolicyControl:
    """Control tests proving baseline policy permits email OTP."""

    def test_baseline_allows_email_otp_for_passkey_user(self, page, idp_config):
        """Under baseline policy, a user with a passkey can still sign in
        via password + email OTP. This is the CORRECT baseline behavior
        (email OTP is acceptable under baseline)."""
        base_url = idp_config["base_url"]
        email = idp_config["admin_email"]
        password = idp_config["admin_password"]
        subdomain = idp_config["subdomain"]

        cdp, auth_id = _enable_virtual_authenticator(page)
        try:
            # Register a passkey
            _sign_in_with_password_and_otp(page, base_url, email, password)
            _register_passkey_via_account_page(page, base_url)
            _sign_out(page, base_url)

            # Remove authenticator so ceremony will fail
            cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": auth_id})

            # Baseline policy (default) should allow email OTP
            _set_auth_policy(subdomain, "baseline")

            page.goto(f"{base_url}/login")
            page.locator("#email").fill(email)
            page.locator("#emailForm button[type='submit']").click()
            page.wait_for_url("**/login?**show_password**", timeout=10000)

            # Passkey-first UI renders but ceremony will fail without an
            # authenticator. Click "Use password instead" to skip it.
            page.locator("#use-password-link").click()
            page.locator("input[name='password']").fill(password)
            page.locator("#loginForm button[type='submit']").click()

            page.wait_for_url("**/mfa/verify**", timeout=10000)
            page.locator("#code").fill(_OTP_BYPASS_CODE)
            page.locator("#mfaVerifyForm button[type='submit']").click()
            page.wait_for_load_state("networkidle", timeout=10000)

            assert "/dashboard" in page.url, (
                f"Baseline policy should allow email OTP, got {page.url}"
            )
        finally:
            _set_auth_policy(subdomain, "baseline")
            _delete_all_passkeys_for_admin(subdomain)
