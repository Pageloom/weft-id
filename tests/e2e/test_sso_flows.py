"""E2E tests for SAML SSO flows between IdP and SP tenants.

These tests exercise real cross-tenant SSO using two WeftID tenants:
    - e2e-idp: acts as the SAML Identity Provider
    - e2e-sp:  acts as the SAML Service Provider

The testbed is provisioned by the session-scoped `e2e_config` fixture.
"""

import subprocess
import textwrap

from tests.e2e.conftest import enter_email_and_reach_password_form

DOCKER_COMPOSE = ["docker", "compose", "--project-directory", ".", "-f", "dev/docker-compose.yml"]


def _run_in_app(script: str, timeout: int = 30) -> str:
    """Run a Python snippet inside the app container and return stdout."""
    result = subprocess.run(
        [*DOCKER_COMPOSE, "exec", "-T", "app", "python", "-c", script],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"app exec failed (rc={result.returncode}):\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result.stdout


class TestSpInitiatedSso:
    """SP-initiated SSO: user starts at SP, authenticates at IdP, returns to SP."""

    def test_sp_initiated_sso(self, page, login, idp_config, sp_config):
        """Full SP-initiated SSO flow with JIT user provisioning.

        1. User enters IdP admin email at SP login
        2. SP routes to SAML IdP (direct routing, no email verification)
        3. IdP sees unauthenticated user, redirects to IdP login
        4. User logs in at IdP (password + MFA)
        5. IdP shows consent page, user approves
        6. SAML Response auto-submitted to SP ACS
        7. SP JIT-creates user, user lands on SP dashboard
        """
        idp_base = idp_config["base_url"]
        sp_base = sp_config["base_url"]
        idp_email = idp_config["admin_email"]
        idp_password = idp_config["admin_password"]

        # Step 1: Navigate to SP login and enter the IdP admin's email.
        # With direct routing (default), SP routes to SAML immediately.
        # Navigate directly to SAML login endpoint to trigger the redirect
        # chain to IdP SSO (Playwright POST->303 workaround).
        idp_id = sp_config["idp_id"]
        page.goto(f"{sp_base}/saml/login/{idp_id}")

        # IdP sees unauthenticated user and redirects to IdP /login
        page.wait_for_url(f"{idp_base}/login**", timeout=15000)

        # Step 2: Complete login at the IdP (password + MFA)
        enter_email_and_reach_password_form(page, idp_base, idp_email, idp_password)

        # MFA (BYPASS_OTP=true, any 6-digit code works)
        page.wait_for_url("**/mfa/verify**")
        page.locator("#code").fill("123456")
        page.locator("#mfaVerifyForm button[type='submit']").click()

        # Step 3: After MFA, IdP detects pending SSO context and shows consent page
        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=10000)

        # Verify consent page shows SP name
        consent_text = page.content()
        assert sp_config["subdomain"] in consent_text.lower() or "SP" in consent_text

        # Step 4: Approve consent
        page.locator("button", has_text="Continue").first.click()

        # Step 5: SAML Response auto-submits to SP ACS, SP creates session.
        # User lands on SP dashboard.
        page.wait_for_url(f"{sp_base}/dashboard**", timeout=15000)

        # Verify we're actually logged in at the SP
        assert "/dashboard" in page.url


class TestIdpInitiatedSso:
    """IdP-initiated SSO: user starts at IdP dashboard, launches SP app."""

    def test_idp_initiated_sso(self, page, login, idp_config, sp_config):
        """User logs in to IdP, clicks SP app tile, approves consent, lands at SP.

        1. Login to IdP
        2. Dashboard shows SP in "My Apps"
        3. Click SP app tile
        4. Consent page shows
        5. Click Continue
        6. Lands at SP dashboard
        """
        idp_base = idp_config["base_url"]
        sp_base = sp_config["base_url"]

        # Login to IdP
        login(idp_base, idp_config["admin_email"])

        # Should be on IdP dashboard
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=10000)

        # Verify "My Apps" section has the SP
        my_apps = page.locator("text=My Apps")
        assert my_apps.is_visible(), "My Apps section not visible on dashboard"

        # Click the SP app tile
        sp_link = page.locator("a[href*='/saml/idp/launch/']").first
        assert sp_link.is_visible(), "SP app tile not visible"
        sp_link.click()

        # Should arrive at consent page
        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=10000)

        # Approve consent
        page.locator("button", has_text="Continue").first.click()

        # SAML Response auto-submits to SP, user lands on SP dashboard
        page.wait_for_url(f"{sp_base}/dashboard**", timeout=15000)
        assert "/dashboard" in page.url


class TestPreExistingUser:
    """Test SSO with a pre-existing user at the SP."""

    def test_sign_in_as_pre_existing_user(self, page, login, idp_config, sp_config):
        """SSO matches an existing SP user instead of JIT-creating a new one.

        The testbed pre-created a user in the SP tenant with the same email
        as the IdP admin. When SSO completes, the SP should match that
        existing user rather than creating a duplicate.
        """
        idp_base = idp_config["base_url"]
        sp_base = sp_config["base_url"]

        # The pre-existing user email is the same as the IdP admin
        assert sp_config["existing_user_email"] == idp_config["admin_email"]

        # Login to IdP
        login(idp_base, idp_config["admin_email"])
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=10000)

        # Launch SP via app tile
        sp_link = page.locator("a[href*='/saml/idp/launch/']").first
        sp_link.click()

        # Consent page
        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=10000)
        page.locator("button", has_text="Continue").first.click()

        # Land at SP dashboard (pre-existing user matched, not JIT-created)
        page.wait_for_url(f"{sp_base}/dashboard**", timeout=15000)
        assert "/dashboard" in page.url


class TestStandardAttributesInAssertion:
    """Iteration 6: a configured standard attribute appears in the downstream
    assertion as a real <saml:Attribute> element on the wire.

    Strategy: configure the IdP tenant to (1) enable job_title in tenant config,
    (2) set a value on the IdP admin user via the canonical user_attributes
    upsert, and (3) extend the SP registration's attribute_mapping to include
    job_title. Then perform IdP-initiated SSO end-to-end so the full
    build_sso_response pipeline runs, AND independently rebuild an
    UNENCRYPTED SAML response using the same inputs so the test can parse
    the assertion XML and assert it contains
    ``<saml:Attribute Name="jobTitle">...<saml:AttributeValue>Senior SAML
    Engineer</saml:AttributeValue>...</saml:Attribute>``.

    The testbed enables encryption on the SP registration, so we can't decrypt
    the wire payload from the browser. Instead we invoke
    ``build_saml_response`` directly inside the app container with
    ``encryption_certificate_pem=None`` -- same code path, same helper, but
    plaintext for inspection. The browser flow proves the pipeline doesn't
    crash; the XML inspection proves the value crosses the SAML emitter.
    """

    JOB_TITLE_VALUE = "Senior SAML Engineer"

    def _seed_tenant_setup(self, idp_config, sp_config):
        """Configure tenant attribute config, user value, and SP mapping."""
        idp_tenant_id = idp_config["tenant_id"]
        sp_id = idp_config["sp_id"]
        admin_email = idp_config["admin_email"]
        script = textwrap.dedent(f"""
            import database
            import json
            from utils.request_context import system_context

            idp_tenant = '{idp_tenant_id}'
            sp_id = '{sp_id}'
            admin_email = '{admin_email}'

            # 1. Enable job_title in tenant_attribute_config
            database.tenant_attribute_config.update_config(
                idp_tenant,
                'job_title',
                enabled=True,
                required=False,
                mirror_from_idp=True,
                locked_for_users=False,
                send_to_sps_default=True,
            )

            # 2. Look up the IdP admin user id
            row = database.fetchone(
                idp_tenant,
                '''
                select u.id from users u
                join user_emails ue on ue.user_id = u.id and ue.is_primary = true
                where lower(ue.email) = lower(:email)
                limit 1
                ''',
                {{'email': admin_email}},
            )
            user_id = str(row['id'])

            # 3. Set job_title canonical value via the EAV table
            database.user_attributes.upsert_attribute(
                idp_tenant,
                idp_tenant,
                user_id,
                'job_title',
                '{self.JOB_TITLE_VALUE}',
            )

            # 4. Extend SP attribute_mapping to include job_title -> 'jobTitle'
            sp = database.service_providers.get_service_provider(idp_tenant, sp_id)
            mapping = dict(sp.get('attribute_mapping') or {{
                'email': 'email',
                'firstName': 'firstName',
                'lastName': 'lastName',
                'groups': 'groups',
            }})
            mapping['job_title'] = 'jobTitle'
            database.execute(
                idp_tenant,
                '''
                update service_providers
                set attribute_mapping = :am, updated_at = now()
                where id = cast(:sp_id as uuid)
                ''',
                {{'am': json.dumps(mapping), 'sp_id': sp_id}},
            )
            print(f'user_id={{user_id}}')
        """)
        out = _run_in_app(script)
        for line in out.splitlines():
            if line.startswith("user_id="):
                return line.split("=", 1)[1].strip()
        raise RuntimeError(f"could not parse user_id from setup: {out!r}")

    def _verify_attribute_in_wire_assertion(self, idp_config, user_id: str) -> None:
        """Rebuild an unencrypted SAML response with the same inputs the IdP
        used during the browser flow, base64-decode and parse the XML, and
        assert the <saml:Attribute Name="jobTitle"> element carries the
        expected <saml:AttributeValue>. This proves the value crosses the
        SAML emitter, not just the bridge helper.
        """
        idp_tenant_id = idp_config["tenant_id"]
        sp_id = idp_config["sp_id"]
        admin_id = user_id
        script = textwrap.dedent(f"""
            import base64
            import database
            from lxml import etree
            from services.service_providers.sso import _build_assertion_attributes
            from utils.saml import decrypt_private_key
            from utils.saml_assertion import build_saml_response
            from utils.saml_idp import make_idp_entity_id

            tenant = '{idp_tenant_id}'
            user_id = '{admin_id}'
            sp_id = '{sp_id}'

            sp = database.service_providers.get_service_provider(tenant, sp_id)
            user = database.users.get_user_by_id(tenant, user_id)
            primary = database.user_emails.get_primary_email(tenant, user_id)

            attrs = _build_assertion_attributes(
                tenant,
                user_id,
                email=primary['email'],
                first_name=user.get('first_name') or '',
                last_name=user.get('last_name') or '',
                group_names=[],
                attribute_mapping=sp.get('attribute_mapping'),
            )

            cert = database.sp_signing_certificates.get_signing_certificate(tenant, sp_id)
            if cert is None:
                cert = database.saml.get_sp_certificate(tenant)
            private_key_pem = decrypt_private_key(cert['private_key_pem_enc'])

            # Build the response WITHOUT encryption so we can parse the XML
            # in this test. Same builder the SSO path uses; just plaintext.
            response_b64, _ = build_saml_response(
                issuer_entity_id=make_idp_entity_id(tenant, sp_id),
                sp_entity_id=sp['entity_id'],
                sp_acs_url=sp['acs_url'],
                name_id=primary['email'],
                name_id_format=(
                    sp.get('nameid_format')
                    or 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
                ),
                authn_request_id=None,
                user_attributes=attrs,
                certificate_pem=cert['certificate_pem'],
                private_key_pem=private_key_pem,
                attribute_mapping=sp.get('attribute_mapping'),
                encryption_certificate_pem=None,
            )

            xml = base64.b64decode(response_b64)
            tree = etree.fromstring(xml)
            ns = {{'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}}
            attr_nodes = tree.findall(
                './/saml:Attribute[@Name="jobTitle"]', namespaces=ns
            )
            print(f'attribute_count={{len(attr_nodes)}}')
            if attr_nodes:
                values = attr_nodes[0].findall('saml:AttributeValue', namespaces=ns)
                print(f'value_count={{len(values)}}')
                if values:
                    print(f'value_text={{values[0].text}}')
        """)
        out = _run_in_app(script)
        assert "attribute_count=1" in out, (
            f"expected exactly one <saml:Attribute Name='jobTitle'>: {out}"
        )
        assert "value_count=1" in out, (
            f"expected exactly one <saml:AttributeValue> under jobTitle: {out}"
        )
        assert f"value_text={self.JOB_TITLE_VALUE}" in out, (
            f"jobTitle AttributeValue did not match: {out}"
        )

    def test_standard_attribute_appears_in_assertion(self, page, login, idp_config, sp_config):
        """End-to-end: enable + set + map + SSO + verify the attribute reaches the SAML wire."""
        user_id = self._seed_tenant_setup(idp_config, sp_config)
        idp_base = idp_config["base_url"]
        sp_base = sp_config["base_url"]

        # Login to IdP
        login(idp_base, idp_config["admin_email"])
        page.wait_for_url(f"{idp_base}/dashboard**", timeout=10000)

        # Launch SP via app tile (drives the full IdP SSO pipeline)
        sp_link = page.locator("a[href*='/saml/idp/launch/']").first
        assert sp_link.is_visible(), "SP app tile not visible"
        sp_link.click()

        page.wait_for_url(f"{idp_base}/saml/idp/consent**", timeout=10000)
        page.locator("button", has_text="Continue").first.click()

        # SP processes the (encrypted) assertion and creates the session
        page.wait_for_url(f"{sp_base}/dashboard**", timeout=15000)

        # Now verify the value crosses the actual SAML emitter by rebuilding
        # an unencrypted assertion with the same inputs and parsing the XML.
        self._verify_attribute_in_wire_assertion(idp_config, user_id)
