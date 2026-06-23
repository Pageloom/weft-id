"""E2E: the full user_attributes cross-iteration journey.

This is the deferred regression anchor for the standard user attributes
feature: the complete human-driven path across the iterations that built
it, exercised through a real browser.

    admin configures (Iteration 2 settings UI)
        -> a member fills the value (Iteration 4 profile UI)
            -> the SP receives it (Iteration 6 assertion emitter)

It is deliberately distinct from ``TestStandardAttributesInAssertion`` in
``test_sso_flows.py``, which seeds both the tenant config and the value via
direct DB upserts on the *admin* user. Provenance is role-based: a value an
admin sets is ``source='admin'`` (authority-grade, always emitted), so that
test never crosses the self-sourced provenance gate. Here a non-admin
*member* fills the value through the profile form, producing
``source='self'``, which only reaches a signed assertion when an admin has
opted the attribute in via ``allow_self_sourced_to_sp``. Both states of that
gate are covered:

* ``test_admin_optin_member_fill_reaches_sp`` -- admin enables the attribute
  AND toggles "Allow user-edited to SPs" in the settings grid; the member's
  self-set value crosses the SAML emitter.
* ``test_member_self_value_withheld_without_optin`` -- admin enables the
  attribute but leaves the opt-in off; the member's self-set value is
  withheld from the assertion (default-deny gate).

"SP receives" is verified the same way the sibling test proves it: rebuild an
*unencrypted* assertion through the real ``_build_assertion_attributes`` +
``build_saml_response`` path and parse the XML. The testbed encrypts the SP
registration, so the browser-delivered payload can't be inspected directly;
rebuilding with the same canonical inputs runs the authoritative emitter
(including the provenance gate) and is parseable.

Uses the ``department`` attribute (free-text, professional) to stay clear of
``job_title`` / ``employee_id`` used by the sibling SSO and force-completion
tests on the shared session testbed.
"""

from __future__ import annotations

import subprocess
import textwrap
import time
import uuid

from tests.e2e.conftest import DOCKER_COMPOSE

ATTR_KEY = "department"
# attribute_mapping value -> the <saml:Attribute Name="..."> on the wire.
WIRE_NAME = "department"


# ---------------------------------------------------------------------------
# psql / app-exec helpers
# ---------------------------------------------------------------------------


def _psql(sql: str) -> str:
    """Run a single SQL statement via psql in the db container."""
    cmd = [
        *DOCKER_COMPOSE,
        "exec",
        "-T",
        "db",
        "psql",
        "-U",
        "postgres",
        "-d",
        "appdb",
        "-tA",
        "-c",
        sql,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, (
        f"psql failed (rc={result.returncode}):\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}\nsql: {sql}"
    )
    return result.stdout.strip()


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


def _tenant_id_for(subdomain: str) -> str:
    return _psql(f"SELECT id FROM tenants WHERE subdomain = '{subdomain}';")


def _allow_users_edit_profile(subdomain: str) -> None:
    """Ensure the tenant lets non-admins edit their own profile (the default,
    asserted explicitly so a prior test can't leave it off)."""
    _psql(
        "INSERT INTO tenant_security_settings (tenant_id, allow_users_edit_profile) "
        f"SELECT id, true FROM tenants WHERE subdomain = '{subdomain}' "
        "ON CONFLICT (tenant_id) DO UPDATE SET allow_users_edit_profile = true;"
    )


def _create_member_user(tenant_id: str, email: str) -> str:
    """Create a fresh member (non-admin) user with a verified primary email."""
    user_id = str(uuid.uuid4())
    _psql(
        f"INSERT INTO users (id, tenant_id, first_name, last_name, role) "
        f"VALUES ('{user_id}', '{tenant_id}', 'Attr', 'Journey', 'member');"
    )
    _psql(
        f"INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at) "
        f"VALUES ('{tenant_id}', '{user_id}', '{email}', true, now());"
    )
    return user_id


def _delete_user(tenant_id: str, user_id: str) -> None:
    _psql(f"DELETE FROM users WHERE tenant_id = '{tenant_id}' AND id = '{user_id}';")


def _reset_attribute_config(tenant_id: str) -> None:
    _psql(
        "UPDATE tenant_attribute_config SET "
        "enabled = false, required = false, locked_for_users = false, "
        "allow_self_sourced_to_sp = false "
        f"WHERE tenant_id = '{tenant_id}' AND attribute_key = '{ATTR_KEY}';"
    )


def _attr_source_and_value(tenant_id: str, user_id: str) -> tuple[str, str]:
    """Return (source, value) of the member's department row, or ('','')."""
    out = _psql(
        f"SELECT source || '|' || value FROM user_attributes "
        f"WHERE tenant_id = '{tenant_id}' AND user_id = '{user_id}' "
        f"AND attribute_key = '{ATTR_KEY}';"
    )
    if not out:
        return "", ""
    source, _, value = out.partition("|")
    return source, value


def _wait_for_attr_config(
    tenant_id: str, *, enabled: bool, allow_self: bool, timeout_s: int = 15
) -> None:
    """Poll until the persisted config matches (the settings grid saves async)."""
    # Postgres renders boolean->text as 'true'/'false' (not psql's t/f display).
    want = f"{'true' if enabled else 'false'}|{'true' if allow_self else 'false'}"
    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        last = _psql(
            f"SELECT enabled || '|' || allow_self_sourced_to_sp "
            f"FROM tenant_attribute_config "
            f"WHERE tenant_id = '{tenant_id}' AND attribute_key = '{ATTR_KEY}';"
        )
        if last == want:
            return
        time.sleep(0.25)
    raise AssertionError(
        f"attribute config did not reach enabled={enabled}, allow_self={allow_self} "
        f"within {timeout_s}s (last saw {last!r})"
    )


def _map_attribute_to_sp(idp_config) -> None:
    """Add the department key to the SP registration's attribute_mapping.

    Mapping an attribute onto a specific SP is an SP-registration concern
    (the per-SP detail page), separate from the tenant-level attribute
    config the admin drives in the browser here. Set via DB to keep the
    browser journey focused on the config + profile UIs, mirroring the
    sibling assertion test.
    """
    script = textwrap.dedent(f"""
        import database, json
        tenant = '{idp_config["tenant_id"]}'
        sp_id = '{idp_config["sp_id"]}'
        sp = database.service_providers.get_service_provider(tenant, sp_id)
        mapping = dict(sp.get('attribute_mapping') or {{
            'email': 'email', 'firstName': 'firstName',
            'lastName': 'lastName', 'groups': 'groups',
        }})
        mapping['{ATTR_KEY}'] = '{WIRE_NAME}'
        database.execute(
            tenant,
            'update service_providers set attribute_mapping = :am, updated_at = now() '
            'where id = cast(:sp_id as uuid)',
            {{'am': json.dumps(mapping), 'sp_id': sp_id}},
        )
        print('mapped')
    """)
    assert "mapped" in _run_in_app(script)


def _rebuilt_assertion_probe(idp_config, user_id: str) -> str:
    """Rebuild an unencrypted assertion for ``user_id`` through the real
    emitter and return parser output lines (attribute_count / value_text)."""
    script = textwrap.dedent(f"""
        import base64
        import database
        from lxml import etree
        from services.service_providers.sso import _build_assertion_attributes
        from utils.saml import decrypt_private_key
        from utils.saml_assertion import build_saml_response
        from utils.saml_idp import make_idp_entity_id

        tenant = '{idp_config["tenant_id"]}'
        user_id = '{user_id}'
        sp_id = '{idp_config["sp_id"]}'

        sp = database.service_providers.get_service_provider(tenant, sp_id)
        user = database.users.get_user_by_id(tenant, user_id)
        primary = database.user_emails.get_primary_email(tenant, user_id)

        attrs = _build_assertion_attributes(
            tenant, user_id,
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
        nodes = tree.findall('.//saml:Attribute[@Name="{WIRE_NAME}"]', namespaces=ns)
        print(f'attribute_count={{len(nodes)}}')
        if nodes:
            values = nodes[0].findall('saml:AttributeValue', namespaces=ns)
            print(f'value_count={{len(values)}}')
            if values:
                print(f'value_text={{values[0].text}}')
    """)
    return _run_in_app(script)


# ---------------------------------------------------------------------------
# Browser steps
# ---------------------------------------------------------------------------


def _admin_configure_attribute(page, idp_config, *, allow_self: bool) -> None:
    """Drive the admin user-attributes settings grid: enable the attribute and
    optionally toggle "Allow user-edited to SPs". Each checkbox saves on change
    via apiFetch; we poll the DB until the persisted state matches."""
    base_url = idp_config["base_url"]
    tenant_id = idp_config["tenant_id"]

    page.goto(f"{base_url}/dev/login?email={idp_config['admin_email']}")
    page.wait_for_url("**/dashboard**", timeout=10000)
    page.goto(f"{base_url}/admin/settings/user-attributes")

    row = page.locator(f"tr.attribute-row[data-key='{ATTR_KEY}']")
    row.wait_for(state="visible", timeout=10000)

    # Enabling unlocks the secondary flags (the change handler clears their
    # disabled attribute synchronously before the async save).
    row.locator("input.flag-enabled").check()
    if allow_self:
        row.locator("input.flag-allow-self").check()

    _wait_for_attr_config(tenant_id, enabled=True, allow_self=allow_self)


def _member_fill_attribute(page, idp_config, member_email: str, value: str) -> None:
    """Log in as the member and submit the department value via the profile form."""
    base_url = idp_config["base_url"]

    page.goto(f"{base_url}/dev/login?email={member_email}")
    page.wait_for_url("**/dashboard**", timeout=10000)
    page.goto(f"{base_url}/account/profile")

    field = page.locator(f"input[name='attr_{ATTR_KEY}']")
    field.wait_for(state="visible", timeout=10000)
    field.fill(value)
    page.locator(
        "form[action='/account/profile/update-attributes'] button[type='submit']"
    ).first.click()
    page.wait_for_url("**/account/profile?success=attributes_saved", timeout=10000)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestUserAttributesJourney:
    """admin configures -> member fills -> SP receives, through the real UIs."""

    def test_admin_optin_member_fill_reaches_sp(self, page, idp_config, sp_config):
        """With the admin opt-in on, a member's self-set value crosses the wire."""
        tenant_id = _tenant_id_for(idp_config["subdomain"])
        _allow_users_edit_profile(idp_config["subdomain"])

        member_email = f"attrjourney-{uuid.uuid4().hex[:8]}@e2e.local"
        member_id = _create_member_user(tenant_id, member_email)
        value = "Platform Engineering"

        try:
            # Iteration 2: admin enables + opts the attribute in to SPs (UI).
            _admin_configure_attribute(page, idp_config, allow_self=True)
            _map_attribute_to_sp(idp_config)

            # Iteration 4: the member fills the value (UI). Provenance = self.
            _member_fill_attribute(page, idp_config, member_email, value)
            source, stored = _attr_source_and_value(tenant_id, member_id)
            assert source == "self", f"expected self-sourced value, got source={source!r}"
            assert stored == value

            # Iteration 6: the value crosses the real SAML emitter.
            out = _rebuilt_assertion_probe(idp_config, member_id)
            assert "attribute_count=1" in out, out
            assert "value_count=1" in out, out
            assert f"value_text={value}" in out, out
        finally:
            _delete_user(tenant_id, member_id)
            _reset_attribute_config(tenant_id)

    def test_member_self_value_withheld_without_optin(self, page, idp_config, sp_config):
        """Default-deny: without the opt-in, a member's self value is withheld."""
        tenant_id = _tenant_id_for(idp_config["subdomain"])
        _allow_users_edit_profile(idp_config["subdomain"])

        member_email = f"attrgate-{uuid.uuid4().hex[:8]}@e2e.local"
        member_id = _create_member_user(tenant_id, member_email)

        try:
            # Enabled but NOT opted in to self-sourced emission.
            _admin_configure_attribute(page, idp_config, allow_self=False)
            _map_attribute_to_sp(idp_config)

            _member_fill_attribute(page, idp_config, member_email, "Secret Org Unit")
            source, _ = _attr_source_and_value(tenant_id, member_id)
            assert source == "self"

            # The provenance gate drops the self value from the assertion.
            out = _rebuilt_assertion_probe(idp_config, member_id)
            assert "attribute_count=0" in out, (
                f"self-sourced value leaked into assertion without opt-in: {out}"
            )
        finally:
            _delete_user(tenant_id, member_id)
            _reset_attribute_config(tenant_id)
