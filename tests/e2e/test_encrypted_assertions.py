"""E2E tests for encrypted SAML assertions.

When WeftId acts as IdP and the SP advertises an encryption certificate,
assertions are encrypted so only the SP can read them. The SP side
(python3-saml) decrypts transparently using its private key.

The testbed sets up encryption_certificate_pem on the SP registration
at the IdP (step_5c), so assertions are encrypted by default.
"""

import subprocess
import textwrap


class TestEncryptedAssertionSso:
    """SSO works end-to-end with encrypted assertions."""

    def test_idp_initiated_sso_with_encrypted_assertion(self, page, login, idp_config, sp_config):
        """IdP encrypts assertion, SP decrypts it, SSO completes.

        1. Login to IdP
        2. Launch SP via app tile
        3. Approve consent
        4. SP decrypts encrypted assertion, creates session
        5. Verify user lands on SP dashboard
        6. Verify event log recorded assertion_encrypted=true
        """
        idp_base = idp_config["base_url"]
        sp_base = sp_config["base_url"]

        # Verify the SP registration at the IdP has an encryption cert
        idp_tenant_id = idp_config["tenant_id"]
        sp_id = idp_config["sp_id"]
        check_script = textwrap.dedent(f"""\
            import database
            sp = database.service_providers.get_service_provider(
                '{idp_tenant_id}', '{sp_id}'
            )
            enc = sp.get('encryption_certificate_pem') if sp else None
            print(f"enc_cert_present={{bool(enc)}}")
        """)
        result = subprocess.run(
            ["docker", "compose", "exec", "-T", "app", "python", "-c", check_script],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert "enc_cert_present=True" in result.stdout, (
            f"Encryption cert not set on SP registration. stdout: {result.stdout}"
        )

        # Login to IdP
        login(idp_base, idp_config["admin_email"])
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=10000)

        # Launch SP via app tile (IdP-initiated SSO)
        sp_link = page.locator("a[href*='/saml/idp/launch/']").first
        assert sp_link.is_visible(), "SP app tile not visible"
        sp_link.click()

        # Consent page
        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=10000)
        page.locator("button", has_text="Continue").first.click()

        # SP decrypts encrypted assertion, user lands on SP dashboard
        page.wait_for_url(f"{sp_base}/dashboard**", timeout=15000)
        assert "/dashboard" in page.url

        # Verify the event log recorded assertion_encrypted=true
        verify_script = textwrap.dedent(f"""\
            import database
            events = database.fetchall(
                '{idp_tenant_id}',
                \"\"\"
                select metadata from event_log
                where event_type = 'sso_assertion_issued'
                  and artifact_id = :sp_id
                order by created_at desc
                limit 1
                \"\"\",
                {{'sp_id': '{sp_id}'}},
            )
            if events:
                meta = events[0].get('metadata', {{}})
                encrypted = meta.get('assertion_encrypted')
                print(f"assertion_encrypted={{encrypted}}")
            else:
                print("no_event_found")
        """)
        result = subprocess.run(
            ["docker", "compose", "exec", "-T", "app", "python", "-c", verify_script],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert "assertion_encrypted=True" in result.stdout, (
            f"Expected assertion_encrypted=True in event log. stdout: {result.stdout}"
        )
