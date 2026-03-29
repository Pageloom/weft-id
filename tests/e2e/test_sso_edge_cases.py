"""E2E tests for SAML SSO edge cases.

Tests:
  - Consent denial: user cancels at consent screen
  - Unauthorized access: user without group membership is denied
  - Certificate rotation: SSO works after rotating the per-SP signing cert
  - Switch account: user changes identity during SSO consent flow

Uses the two-tenant testbed with extras (no-access user, second SSO user).
"""

import subprocess
import textwrap

from helpers.maildev import clear_emails, extract_otp_code, get_latest_email


class TestConsentDenial:
    """User cancels at the consent screen during IdP-initiated SSO."""

    def test_cancel_returns_to_dashboard(self, page, login, idp_config, sp_config):
        """Cancel at consent redirects to IdP dashboard, user stays logged in.

        1. Login to IdP
        2. Launch SP (IdP-initiated SSO)
        3. Reach consent page
        4. Click "Cancel"
        5. Verify redirect to IdP dashboard (not SP)
        6. Verify user remains logged in at IdP
        """
        idp_base = idp_config["base_url"]

        # Login to IdP
        login(idp_base, idp_config["admin_email"])
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=10000)

        # Launch SP via app tile
        sp_link = page.locator("a[href*='/saml/idp/launch/']").first
        sp_link.click()

        # Consent page
        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=10000)

        # Click Cancel (the consent form's cancel button, not the confirm dialog's)
        page.locator(
            "form[action='/saml/idp/consent'] button[type='submit']", has_text="Cancel"
        ).click()

        # Should redirect to IdP dashboard (not the SP)
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=10000)
        assert "/dashboard" in page.url
        assert idp_base in page.url

        # Verify user is still logged in (dashboard loads, not redirected to login)
        page.reload()
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=5000)


class TestUnauthorizedUserAccess:
    """User without SP group membership is denied SSO access."""

    def test_no_access_user_sees_access_denied(
        self, page, login, idp_config, sp_config, extras_config
    ):
        """User not in any SP-assigned group gets Access Denied error page.

        1. Login as no-access user
        2. Navigate to IdP-initiated SSO launch
        3. Verify "Access Denied" error page renders
        4. Verify error message mentions group membership
        5. Verify "Return to Dashboard" link works
        """
        idp_base = idp_config["base_url"]
        no_access_email = extras_config["no_access_user"]["email"]
        sp_id = idp_config["sp_id"]

        # Login as no-access user
        login(idp_base, no_access_email)
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=10000)

        # Attempt IdP-initiated SSO (direct URL since user won't see the tile)
        page.goto(f"{idp_base}/saml/idp/launch/{sp_id}")

        # Should see the Access Denied error page
        page.wait_for_load_state("networkidle")
        assert "Access Denied" in page.content()
        assert "Group membership required" in page.content()

        # Click "Return to Dashboard" link
        page.locator("a", has_text="Return to Dashboard").click()
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=5000)


class TestCertificateRotation:
    """SSO continues to work after rotating the per-SP signing certificate."""

    def test_sso_works_after_cert_rotation(self, page, login, idp_config, sp_config):
        """Rotate the IdP signing cert, sync to SP, verify SSO still works.

        1. Login to IdP, perform SSO to SP (verify baseline works)
        2. Navigate to IdP admin, rotate the per-SP signing certificate
        3. Sync the new certificate to the SP's IdP certificate store
        4. Perform SSO again
        5. Verify SSO completes successfully
        """
        idp_base = idp_config["base_url"]
        sp_base = sp_config["base_url"]
        sp_id = idp_config["sp_id"]

        # Step 1: Baseline SSO
        login(idp_base, idp_config["admin_email"])
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=10000)

        sp_link = page.locator("a[href*='/saml/idp/launch/']").first
        sp_link.click()
        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=10000)
        page.locator("button", has_text="Continue").first.click()
        page.wait_for_url(f"{sp_base}/dashboard**", timeout=15000)
        assert "/dashboard" in page.url

        # Step 2: Rotate the per-SP signing certificate via IdP admin UI
        page.goto(f"{idp_base}/admin/settings/service-providers/{sp_id}/certificates")
        page.wait_for_load_state("networkidle")

        # Click the Rotate Certificate button
        rotate_btn = page.locator("button", has_text="Rotate Certificate")
        assert rotate_btn.is_visible(), "Rotate Certificate button not found"
        # Handle the confirmation dialog
        page.on("dialog", lambda dialog: dialog.accept())
        rotate_btn.click()

        # Should redirect back to certificates tab with success
        page.wait_for_url(f"**/{sp_id}/certificates**", timeout=10000)

        # Step 3: Sync the new IdP cert to the SP's certificate store
        # After rotation, the IdP signs with the new cert. The SP needs it.
        idp_tenant_id = idp_config["tenant_id"]
        sp_tenant_id = sp_config["tenant_id"]
        sp_idp_id = sp_config["idp_id"]

        sync_script = textwrap.dedent(f"""\
            import database
            import database.saml
            import database.sp_signing_certificates
            from utils.saml import get_certificate_fingerprint, get_certificate_expiry

            # Get the new cert from IdP's per-SP signing certificate
            cert = database.sp_signing_certificates.get_signing_certificate(
                '{idp_tenant_id}', '{sp_id}'
            )
            new_cert_pem = cert['certificate_pem']
            fingerprint = get_certificate_fingerprint(new_cert_pem)

            # Check if SP already has this cert
            existing = database.saml.list_idp_certificates('{sp_tenant_id}', '{sp_idp_id}')
            existing_fps = {{r['fingerprint'] for r in existing if r.get('fingerprint')}}
            if fingerprint not in existing_fps:
                expires_at = get_certificate_expiry(new_cert_pem)
                database.saml.create_idp_certificate(
                    tenant_id='{sp_tenant_id}',
                    idp_id='{sp_idp_id}',
                    tenant_id_value='{sp_tenant_id}',
                    certificate_pem=new_cert_pem,
                    fingerprint=fingerprint,
                    expires_at=expires_at,
                )
                print('Synced new certificate to SP')
            else:
                print('Certificate already exists at SP')
        """)

        result = subprocess.run(
            ["docker", "compose", "exec", "-T", "app", "python", "-c", sync_script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Certificate sync failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

        # Step 4: Perform SSO again from the IdP
        page.goto(f"{idp_base}/dashboard")
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=10000)

        sp_link = page.locator("a[href*='/saml/idp/launch/']").first
        sp_link.click()
        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=10000)
        page.locator("button", has_text="Continue").first.click()

        # Step 5: Verify SSO completes with the rotated certificate
        page.wait_for_url(f"{sp_base}/dashboard**", timeout=15000)
        assert "/dashboard" in page.url


class TestSwitchAccount:
    """User switches identity during the SSO consent flow."""

    def test_switch_account_completes_sso_as_new_user(
        self, page, login, idp_config, sp_config, extras_config
    ):
        """Switch account at consent, re-authenticate, SSO completes as new user.

        1. Login as user A (IdP admin)
        2. Launch SP (IdP-initiated SSO)
        3. Reach consent page, verify user A's email shown
        4. Click "Use a different account"
        5. Redirected to /login (SSO context preserved)
        6. Login as user B (second SSO user): email, verify, password, MFA
        7. Redirected to consent page (SSO context detected)
        8. Verify user B's email shown on consent page
        9. Click "Continue"
        10. Verify SSO completes, lands on SP dashboard
        """
        idp_base = idp_config["base_url"]
        sp_base = sp_config["base_url"]
        user_a_email = idp_config["admin_email"]
        user_b_email = extras_config["second_sso_user"]["email"]
        user_b_password = extras_config["second_sso_user"]["password"]

        # Step 1: Login as user A
        login(idp_base, user_a_email)
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=10000)

        # Step 2: Launch SP via app tile
        sp_link = page.locator("a[href*='/saml/idp/launch/']").first
        sp_link.click()

        # Step 3: Consent page - verify user A's email is shown
        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=10000)
        consent_content = page.content()
        assert user_a_email in consent_content, (
            f"Expected {user_a_email} on consent page but not found"
        )

        # Step 4: Click "Use a different account"
        page.locator("button", has_text="Use a different account").click()

        # Step 5: Redirected to /login with SSO context preserved
        page.wait_for_url(f"{idp_base}/login**", timeout=10000)

        # Step 6: Full multi-step login as user B
        clear_emails()
        page.locator("#email").fill(user_b_email)
        page.locator("#emailForm button[type='submit']").click()

        # Email verification
        page.wait_for_url("**/login/verify**")
        mail = get_latest_email(to=user_b_email, timeout=10.0)
        assert mail is not None, f"No verification email received for {user_b_email}"
        code = extract_otp_code(mail)
        assert code is not None, "Could not extract verification code"

        page.locator("#code").fill(code)
        page.locator("#verifyCodeForm button[type='submit']").click()

        # Password form
        page.wait_for_url("**/login?**show_password**")
        page.locator("input[name='password']").fill(user_b_password)
        page.locator("#loginForm button[type='submit']").click()

        # MFA (BYPASS_OTP=true in dev, any 6-digit code works)
        page.wait_for_url("**/mfa/verify**")
        page.locator("#code").fill("123456")
        page.locator("#mfaVerifyForm button[type='submit']").click()

        # Step 7: After MFA, SSO context detected, redirected to consent page
        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=10000)

        # Step 8: Verify user B's email is shown on consent page
        consent_content = page.content()
        assert user_b_email in consent_content, (
            f"Expected {user_b_email} on consent page after switch-account, "
            f"but got content without it"
        )

        # Step 9: Click Continue
        page.locator("button", has_text="Continue").first.click()

        # Step 10: SSO completes, lands on SP dashboard
        page.wait_for_url(f"{sp_base}/dashboard**", timeout=15000)
        assert "/dashboard" in page.url
