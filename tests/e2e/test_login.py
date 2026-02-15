from helpers.maildev import clear_emails, extract_otp_code, get_latest_email


class TestBasicLogin:
    def test_email_login(self, page, idp_config):
        """
        Log in a user in via the multistep email+password flow.
        """
        base_url, email, password = (
            idp_config["base_url"],
            idp_config["admin_email"],
            idp_config["admin_password"],
        )

        # Clear maildev inbox for this recipient before starting
        clear_emails()

        # Step 1: Navigate to login page and enter email
        page.goto(f"{base_url}/login")
        page.locator("#email").fill(email)
        page.locator("#emailForm button[type='submit']").click()

        # Step 2: Wait for email verification page
        page.wait_for_url("**/login/verify**")

        # Step 3: Capture verification code from MailDev
        mail = get_latest_email(to=email, timeout=10.0)
        assert mail is not None, f"No verification email received for {email}"
        code = extract_otp_code(mail)
        assert code is not None, "Could not extract verification code from email"

        # Step 4: Enter verification code
        page.locator("#code").fill(code)
        page.locator("#verifyCodeForm button[type='submit']").click()

        # Step 5: After code verification, determine_auth_route() decides next step.
        # For password-based users, it redirects to /login?show_password=true.
        # For SAML users, it redirects to /saml/login/{idp_id} which then
        # redirects to the IdP SSO endpoint.
        # We wait for whichever page loads next.
        page.wait_for_load_state("networkidle")

        # If we landed on the password form, fill it in and handle MFA
        if "/login" in page.url and "show_password" in page.url:
            page.locator("input[name='password']").fill(password)
            page.locator("#loginForm button[type='submit']").click()

            # After password, we land on /mfa/verify.
            # BYPASS_OTP=true in dev, so any 6-digit code works.
            page.wait_for_url("**/mfa/verify**")
            page.locator("#code").fill("123456")
            page.locator("#mfaVerifyForm button[type='submit']").click()
            page.wait_for_load_state("networkidle")

        # Verify we landed on the dashboard
        assert "/dashboard" in page.url
