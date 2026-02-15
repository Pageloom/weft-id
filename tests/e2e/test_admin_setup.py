"""E2E tests for admin UI SP/IdP management via metadata XML import.

The testbed has already created the primary SAML config between the two tenants.
These tests verify the admin UI works by importing *crafted* metadata XML (with
unique entity IDs that don't conflict with the testbed's registrations).
"""

# Minimal valid SP metadata XML template
_SP_METADATA_XML = """\
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://e2e-test-app.example.com/saml/metadata">
  <md:SPSSODescriptor
      AuthnRequestsSigned="false"
      WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://e2e-test-app.example.com/saml/acs"
        index="0"
        isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"""

# Minimal valid IdP metadata XML template (includes a dummy X.509 cert, required by parser)
_IDP_METADATA_XML = """\
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="https://e2e-test-idp.example.com/saml/metadata">
  <md:IDPSSODescriptor
      WantAuthnRequestsSigned="false"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIDBzCCAe+gAwIBAgIUYY9aUHKKXkwW5EjDnJPtNWdZ9UgwDQYJKoZIhvcNAQEL\
BQAwEzERMA8GA1UEAwwIZTJlLXRlc3QwHhcNMjYwMjE0MjM1MjAxWhcNMjcwMjE0\
MjM1MjAxWjATMREwDwYDVQQDDAhlMmUtdGVzdDCCASIwDQYJKoZIhvcNAQEBBQAD\
ggEPADCCAQoCggEBAJ7GCr2yRuSab+yCySEIhPTFTwLP+vnfJV++BJCJZoUPRR7x\
PIv51WpwZWZMxXSOCgsG99oJJ3qfkqcrSRElHfjWuxy89yPlhpn1CIXMF6DDYvPE\
mm71YMntLQC3eUk3LnXqJyxx8QWN2+CIV7xOf4pem+MmqowOGbtXDCXBNnmIVqSk\
0yC2cYu5EYUWaw8FTW6PsLNeM0zd69XY0Qulu2KYZEXaZFLlzi59h0z0tYqV0jEz\
Kjn2JjiW5KWpx2F9Qh8ikYD66FbmI65cUKs8p4fS6cTr6STaIXk1PZ7bDsMEQjgn\
4PLmq5gHK17b7LZKl3G82ZQxFOiOKRbedtyC+VsCAwEAAaNTMFEwHQYDVR0OBBYE\
FLzfWZggQ4NstLPiTBeZJcD+PghxMB8GA1UdIwQYMBaAFLzfWZggQ4NstLPiTBeZ\
JcD+PghxMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAHVOjyfo\
Ljp3W8/pCj1lmeJCZSS5Mup4+CD7JGVnc7VCsDEmHQRFvMLprOk/b7Z4EPAAFUT6\
ztVto/To3wu7S3GuoId6yhF4DJ/FjXFukfwbr+V0Okf0rMytt7bT2eq8ftS5+xwm\
Grs+WggHV7XJixAySlDie5kcG4C0QSuDkkdq00sbNRZ1md+1zwkCMm3yk9ueErQU\
99YOoVfWJYia+0mk5Ry6g1S9XXfyZnvowiDB10ZYP5ZiwZgjLdMyStLUAh2r0cyz\
pPYxUhi49JrccmOz6TcDQX1I14DCYIUHhguOvFcqN9K1o8VyLY0euhsDLIl5Ocjx\
T8LgM4JC638MXYM=</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://e2e-test-idp.example.com/saml/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"""


class TestIdpAdminRegistersSp:
    """IdP admin imports SP metadata XML to register a new Service Provider."""

    def test_idp_admin_registers_sp_via_xml(self, page, login, idp_config, sp_config):
        """Import SP metadata XML at the IdP and verify it appears in the list.

        Uses crafted metadata XML with a unique entity ID to avoid conflicting
        with the testbed's existing SP registration.
        """
        idp_base = idp_config["base_url"]

        # Login to IdP as super admin
        login(idp_base, idp_config["admin_email"], idp_config["admin_password"])

        # Navigate to SP creation page
        page.goto(f"{idp_base}/admin/settings/service-providers/new")

        # Click the "Metadata XML" tab
        page.locator("[data-tab='metadata-xml']").click()

        # Fill in the form
        sp_name = "E2E Test SP (XML Import)"
        page.locator("#xml-name").fill(sp_name)
        page.locator("#metadata-xml").fill(_SP_METADATA_XML)

        # Submit the form (use no_wait_after to avoid Playwright aborting
        # the POST→303→GET redirect chain)
        xml_form = page.locator(
            "form[action='/admin/settings/service-providers/import-metadata-xml']"
        )
        xml_form.locator("button[type='submit']").click(no_wait_after=True)
        page.wait_for_timeout(2000)

        # Navigate to SP list to verify the import succeeded
        page.goto(f"{idp_base}/admin/settings/service-providers")

        # Verify the new SP is visible in the list
        assert page.locator(f"text={sp_name}").is_visible()


class TestSpAdminRegistersIdp:
    """SP admin imports IdP metadata XML to register a new Identity Provider."""

    def test_sp_admin_registers_idp_via_xml(self, page, login, idp_config, sp_config):
        """Import IdP metadata XML at the SP and verify it appears in the list.

        Uses crafted metadata XML with a unique entity ID to avoid conflicting
        with the testbed's existing IdP registration.
        """
        sp_base = sp_config["base_url"]

        # Login to SP as super admin
        login(sp_base, sp_config["admin_email"], sp_config["admin_password"])

        # Navigate to IdP creation page
        page.goto(f"{sp_base}/admin/settings/identity-providers/new")

        # Click the "Paste Metadata XML" tab
        page.locator("#tab-xml").click()

        # Fill in the form
        idp_name = "E2E Test IdP (XML Import)"
        page.locator("#xml-name").fill(idp_name)
        page.locator("#xml-provider_type").select_option("generic")
        page.locator("#metadata_xml").fill(_IDP_METADATA_XML)

        # Submit the form
        xml_form = page.locator(
            "form[action='/admin/settings/identity-providers/import-metadata-xml']"
        )
        xml_form.locator("button[type='submit']").click()

        # Should redirect to IdP list with success
        page.wait_for_url("**/admin/settings/identity-providers**success=created**", timeout=10000)

        # Verify success message
        page.locator("text=Identity provider created successfully").wait_for(timeout=5000)

        # Verify the new IdP is visible in the list
        assert page.locator(f"text={idp_name}").is_visible()
