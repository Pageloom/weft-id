"""E2E tests for admin UI SP/IdP registration via the two-step creation flow.

The new flow is:
  1. Create the SP or IdP with a display name only
  2. Redirected to the details page (pending trust)
  3. Establish trust by importing metadata (URL, XML, or manual entry)

The testbed has already created the primary SAML config between the two tenants.
These tests verify the admin UI works by importing *crafted* metadata XML (with
unique entity IDs that don't conflict with the testbed's registrations).
"""

from uuid import uuid4

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
    """IdP admin creates a new SP via the two-step flow (name, then trust)."""

    def test_idp_admin_registers_sp_via_xml(self, page, login, idp_config):
        """Create an SP, then establish trust by pasting SP metadata XML.

        Step 1: Create SP with name only
        Step 2: On details page, switch to 'Metadata XML' tab and paste XML
        """
        idp_base = idp_config["base_url"]

        # Login to IdP as super admin
        login(idp_base, idp_config["admin_email"])

        # Step 1: Create SP with name only
        page.goto(f"{idp_base}/admin/settings/service-providers/new")
        sp_name = f"E2E Test SP (XML Import) {uuid4().hex[:8]}"
        page.locator("#sp-name").fill(sp_name)
        page.get_by_role("button", name="Create").click()

        # Should redirect to the new SP's details page (pending trust)
        page.wait_for_url(
            "**/admin/settings/service-providers/*/details**success=created**",
            timeout=10000,
        )

        # Step 2: Establish trust via Metadata XML tab
        page.locator("[data-tab='trust-xml']").click()
        page.locator("#trust-metadata-xml").fill(_SP_METADATA_XML)
        page.locator("#tab-trust-xml button[type='submit']").click()

        # Should redirect back to details with trust established
        page.wait_for_url(
            "**/admin/settings/service-providers/*/details**",
            timeout=10000,
        )

        # Verify trust is established: the Entity ID should be visible
        # (only shown after trust is established)
        page.get_by_text("https://e2e-test-app.example.com/saml/metadata").first.wait_for(
            timeout=5000
        )

        # Verify the SP appears in the list
        page.goto(f"{idp_base}/admin/settings/service-providers")
        assert page.locator(f"text={sp_name}").is_visible()


class TestSpAdminRegistersIdp:
    """SP admin creates a new IdP via the two-step flow (name, then trust)."""

    def test_sp_admin_registers_idp_via_xml(self, page, login, sp_config):
        """Create an IdP, then establish trust by pasting IdP metadata XML.

        Step 1: Create IdP with name and provider type
        Step 2: On details page, switch to 'Paste Metadata XML' tab and paste XML
        """
        sp_base = sp_config["base_url"]

        # Login to SP as super admin
        login(sp_base, sp_config["admin_email"])

        # Step 1: Create IdP with name and provider type
        page.goto(f"{sp_base}/admin/settings/identity-providers/new")
        idp_name = f"E2E Test IdP (XML Import) {uuid4().hex[:8]}"
        page.locator("#name").fill(idp_name)
        page.locator("#provider_type").select_option("generic")
        page.get_by_role("button", name="Create Identity Provider").click()

        # Should redirect to the new IdP's details page (pending trust)
        page.wait_for_url(
            "**/admin/settings/identity-providers/*/details**success=created**",
            timeout=10000,
        )

        # Step 2: Establish trust via Paste Metadata XML tab
        page.locator("#tab-xml").click()
        page.locator("#trust-metadata-xml").fill(_IDP_METADATA_XML)
        page.locator("#trust-content-xml button[type='submit']").click()

        # Should redirect back to details with trust established
        page.wait_for_url(
            "**/admin/settings/identity-providers/*/details**",
            timeout=10000,
        )

        # Verify trust is established: success message or entity ID shown
        page.locator("text=Trust established").wait_for(timeout=5000)

        # Verify the IdP appears in the list
        page.goto(f"{sp_base}/admin/settings/identity-providers")
        assert page.locator(f"text={idp_name}").is_visible()
