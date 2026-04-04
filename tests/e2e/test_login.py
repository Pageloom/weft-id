from helpers.maildev import clear_emails, extract_otp_code, get_latest_email

from tests.e2e.conftest import _set_email_verification_required


class TestDirectLoginFlow:
    """Tests for the default sign-in flow (no email verification)."""

    def test_password_user_sees_password_form_immediately(self, page, idp_config):
        """
        Default flow: enter email -> immediately see password form (no
        verification code step). Complete login through password + MFA.
        """
        base_url = idp_config["base_url"]
        email = idp_config["admin_email"]
        password = idp_config["admin_password"]

        page.goto(f"{base_url}/login")
        page.locator("#email").fill(email)
        page.locator("#emailForm button[type='submit']").click()

        # Should go directly to password form, not /login/verify
        page.wait_for_url("**/login?**show_password**", timeout=10000)
        assert "/login/verify" not in page.url

        # Complete password + MFA
        page.locator("input[name='password']").fill(password)
        page.locator("#loginForm button[type='submit']").click()

        page.wait_for_url("**/mfa/verify**")
        page.locator("#code").fill("123456")
        page.locator("#mfaVerifyForm button[type='submit']").click()
        page.wait_for_load_state("networkidle")

        assert "/dashboard" in page.url

    def test_nonexistent_email_sees_password_form(self, page, idp_config):
        """
        Default flow: a non-existent email is routed to the password form
        with no indication that the account doesn't exist.
        """
        base_url = idp_config["base_url"]

        page.goto(f"{base_url}/login")
        page.locator("#email").fill("nobody-at-all@example.com")
        page.locator("#emailForm button[type='submit']").click()

        # Should show password form (no info leak)
        page.wait_for_url("**/login?**show_password**", timeout=10000)
        assert "not_found" not in page.url
        assert "error" not in page.url


class TestVerificationLoginFlow:
    """Tests for the opt-in sign-in flow (email verification required)."""

    def test_email_verification_required_before_password(self, page, idp_config):
        """
        Opt-in flow: enable the setting, then enter email -> must verify
        email possession via code -> then see password form -> MFA -> dashboard.
        """
        base_url = idp_config["base_url"]
        email = idp_config["admin_email"]
        password = idp_config["admin_password"]
        subdomain = idp_config["subdomain"]

        # Enable email verification for this tenant
        _set_email_verification_required(subdomain, True)

        try:
            clear_emails()

            page.goto(f"{base_url}/login")
            page.locator("#email").fill(email)
            page.locator("#emailForm button[type='submit']").click()

            # Should navigate to verification page (not directly to password)
            page.wait_for_url("**/login/verify**", timeout=10000)

            # Get verification code from email
            mail = get_latest_email(to=email, timeout=10.0)
            assert mail is not None, f"No verification email received for {email}"
            code = extract_otp_code(mail)
            assert code is not None, "Could not extract verification code"

            # Enter code
            page.locator("#code").fill(code)
            page.locator("#verifyCodeForm button[type='submit']").click()
            page.wait_for_load_state("networkidle")

            # After verification, should land on password form
            assert "show_password" in page.url

            # Complete password + MFA
            page.locator("input[name='password']").fill(password)
            page.locator("#loginForm button[type='submit']").click()

            page.wait_for_url("**/mfa/verify**")
            page.locator("#code").fill("123456")
            page.locator("#mfaVerifyForm button[type='submit']").click()
            page.wait_for_load_state("networkidle")

            assert "/dashboard" in page.url

        finally:
            # Restore default (direct routing) for other tests
            _set_email_verification_required(subdomain, False)
