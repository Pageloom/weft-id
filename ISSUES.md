# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 2 | SSRF, RLS policy defect |
| Medium | 1 | XML Injection |
| Low | 2 | SLO validation, cert cleanup race |

**Last security scan:** 2026-02-21 (SAML IdP focused assessment, 3 issues; 30-day incremental assessment, 2 new issues)
**Last compliance scan:** 2026-02-21 (all clear, scanner now cross-references migrations)
**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-12 (standard full scan, 4 prior items resolved, 2 new)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-07 (parametrization applied to duplicated test patterns)

---

## [SECURITY] SSRF via Metadata URL Fetch

**Found in:** `app/utils/saml_idp.py:264-322` (`fetch_sp_metadata`), also `app/utils/saml.py:268-323` (`fetch_idp_metadata`)
**Severity:** High
**OWASP Category:** A10:2021 - Server-Side Request Forgery (SSRF)
**Description:** The `fetch_sp_metadata()` and `fetch_idp_metadata()` functions accept arbitrary URLs without validating the scheme or target host. `urllib.request.urlopen` supports `file://`, `ftp://`, and `http://` schemes by default, and no host blocklist prevents requests to internal networks.
**Attack Scenario:** A super_admin (tenant-level administrator in a multi-tenant SaaS) provides a metadata URL targeting internal resources. For example:
- `file:///etc/passwd` reads local files
- `http://169.254.169.254/latest/meta-data/` accesses cloud instance metadata (AWS/GCP credentials)
- `http://localhost:5432/` port-scans internal services

While XML parsing will fail for non-XML responses (preventing direct exfiltration), the HTTP request itself is still made, enabling port scanning and interaction with internal services. Additionally, `response.read()` has no size limit, risking memory exhaustion from large responses.
**Evidence:**
```python
# saml_idp.py:264 - No scheme or host validation
def fetch_sp_metadata(url: str, timeout: int = 10) -> str:
    ...
    req = urllib.request.Request(urlunparse(parsed), headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as response:
        content: str = response.read().decode("utf-8")  # No size limit
```
**Impact:** Internal network reconnaissance, cloud credential theft, local file read attempts, memory exhaustion via unbounded response.
**Remediation:**
1. Validate URL scheme is `https://` only (or `http://` in dev mode)
2. Resolve the hostname and reject private/internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1)
3. Add a response size limit (e.g., 5 MB) using `response.read(max_size)`
4. Apply the same validation to both `fetch_sp_metadata` and `fetch_idp_metadata`

Example fix:
```python
from urllib.parse import urlparse
import ipaddress, socket

_MAX_METADATA_SIZE = 5 * 1024 * 1024  # 5 MB

def _validate_metadata_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError("URL missing hostname")
    # Resolve and check IP
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    except (socket.gaierror, ValueError):
        raise ValueError(f"Cannot resolve hostname: {parsed.hostname}")
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError("URL targets a private/internal address")
```

---

## [SECURITY] XML Injection in IdP Metadata Generation via String Interpolation

**Found in:** `app/utils/saml_idp.py:191-261` (`generate_idp_metadata_xml`), also `app/utils/saml.py:325-427` (`generate_sp_metadata_xml`)
**Severity:** Medium
**OWASP Category:** A03:2021 - Injection
**Description:** IdP metadata XML is generated using f-string interpolation without XML escaping. User-configurable `attribute_mapping` values (both keys and values) are interpolated directly into XML attribute positions. A value containing `"` or `<` can break out of the XML attribute and inject arbitrary XML content.
**Attack Scenario:** A super_admin sets an attribute mapping value containing XML special characters (either directly via the admin UI, or indirectly by importing SP metadata with crafted `RequestedAttribute` elements that are auto-detected into the mapping). The per-SP IdP metadata endpoint (`/saml/idp/metadata/{sp_id}`) then serves the poisoned XML to downstream consumers.
**Evidence:**
```python
# saml_idp.py:230-234 - No XML escaping on user-configurable values
for friendly_name, uri in (attribute_mapping or SAML_ATTRIBUTE_URIS).items():
    attr_elements += f"""
    <saml:Attribute
        Name="{uri}"
        NameFormat="{attr_format}"
        FriendlyName="{friendly_name}" />"""
```

A mapping like `{"email": 'foo"/><Evil xmlns="http://evil'}` would inject:
```xml
<saml:Attribute
    Name="foo"/><Evil xmlns="http://evil"
    NameFormat="..."
    FriendlyName="email" />
```
**Impact:** Malformed or poisoned IdP metadata served to downstream SPs. Could cause SP configuration failures or exploit vulnerabilities in SP metadata parsers.
**Remediation:** Use `xml.sax.saxutils.escape()` and `xml.sax.saxutils.quoteattr()` to escape all interpolated values, or switch to `lxml.etree` element construction (already used in `saml_assertion.py`) instead of f-string templates.

Example fix:
```python
from xml.sax.saxutils import escape

for friendly_name, uri in (attribute_mapping or SAML_ATTRIBUTE_URIS).items():
    attr_elements += f"""
    <saml:Attribute
        Name="{escape(uri, {'"': '&quot;'})}"
        NameFormat="{attr_format}"
        FriendlyName="{escape(friendly_name, {'"': '&quot;'})}" />"""
```

---

## [SECURITY] SLO LogoutRequest Processed Without Validation

**Found in:** `app/routers/saml_idp/slo.py:69-116` (`_handle_slo_request`)
**Severity:** Low
**OWASP Category:** A07:2021 - Identification and Authentication Failures
**Description:** Two issues in the SLO flow combine to allow forced user logout:

1. **Session cleared before issuer validation** (line 88): The user's session is cleared immediately after parsing the LogoutRequest XML, before checking whether the issuer is a registered SP. Any syntactically valid LogoutRequest (even from an unregistered source) will destroy the user's session.

2. **No signature validation on LogoutRequests**: `parse_sp_logout_request()` parses the XML structure but does not validate the XML signature. Any party can forge a LogoutRequest.

**Attack Scenario:** An attacker crafts a minimal valid LogoutRequest (just needs an `<ID>` attribute and wrapping `<LogoutRequest>` element) and redirects a victim's browser to `/saml/idp/slo?SAMLRequest=<base64_encoded_forged_request>`. The victim's session is destroyed, forcing a re-login.
**Evidence:**
```python
# slo.py:77-88 - Session cleared unconditionally before issuer check
def _handle_slo_request(...):
    # 1. Parse the LogoutRequest
    try:
        parsed = parse_sp_logout_request(saml_request, binding)
    except ValueError as e:
        ...

    # 2. Clear the user's session (before any SP validation!)
    request.session.clear()

    # 3. Build LogoutResponse (this is where issuer is first checked)
    ...
    logout_response_b64, slo_url = process_sp_logout_request(...)
```
**Impact:** Forced user logout (denial of service). No data leakage or privilege escalation.
**Remediation:**
1. Move `request.session.clear()` after `process_sp_logout_request()` succeeds (after the issuer is validated as a registered SP)
2. Consider adding LogoutRequest signature validation using the SP's registered certificate

Example fix:
```python
def _handle_slo_request(...):
    try:
        parsed = parse_sp_logout_request(saml_request, binding)
    except ValueError as e:
        return RedirectResponse(url="/login", status_code=303)

    base_url = get_base_url(request)
    try:
        logout_response_b64, slo_url = process_sp_logout_request(
            tenant_id=tenant_id, parsed_request=parsed, base_url=base_url,
        )
    except Exception as e:
        return RedirectResponse(url="/login", status_code=303)

    # Only clear session after validating the request came from a registered SP
    request.session.clear()
    ...
```

---

## [SECURITY] RLS Policy Defect on saml_idp_sp_certificates Table

**Found in:** `db-init/schema.sql:1049-1050`
**Severity:** High
**OWASP Category:** A01:2021 - Broken Access Control
**Description:** The `saml_idp_sp_certificates` table has a defective RLS policy with three problems compared to every other tenant-isolated table in the schema:

1. **Missing `WITH CHECK` clause**: The policy only has `USING` (governs SELECT/UPDATE/DELETE visibility) but no `WITH CHECK` (governs INSERT/UPDATE write validation). This means INSERT and UPDATE operations bypass tenant scoping entirely for this table.

2. **Missing `true` parameter in `current_setting()`**: All other tables use `current_setting('app.tenant_id'::text, true)` which returns NULL when the setting is absent. This table uses `current_setting('app.tenant_id'::text)` which raises an ERROR when `app.tenant_id` is not set, causing unexpected failures in code paths that use `UNSCOPED` queries.

3. **Missing `NULLIF()` handling**: Other tables that were added around the same time (e.g., `saml_sp_certificates`, `service_providers`) wrap the setting in `NULLIF(..., ''::text)` to handle empty strings. This table does not.

**Attack Scenario:** An application bug or code path that fails to set `app.tenant_id` before inserting into `saml_idp_sp_certificates` could write a certificate row associated with Tenant A while operating in a Tenant B context. Because there is no `WITH CHECK`, PostgreSQL will not reject the insert even if the `tenant_id` in the row does not match the session's `app.tenant_id`.

**Evidence:**
```sql
-- saml_idp_sp_certificates (DEFECTIVE - line 1049)
CREATE POLICY tenant_isolation ON public.saml_idp_sp_certificates
    USING ((tenant_id = (current_setting('app.tenant_id'::text))::uuid));

-- Every other table uses this pattern (e.g., saml_sp_certificates - line 1043)
CREATE POLICY saml_sp_certificates_tenant_isolation ON public.saml_sp_certificates
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));
```
**Impact:** Tenant isolation bypass on writes to the per-IdP SP signing certificates table. Could allow cross-tenant certificate contamination.
**Remediation:** Replace the policy to match the standard pattern:

```sql
DROP POLICY tenant_isolation ON public.saml_idp_sp_certificates;
CREATE POLICY saml_idp_sp_certificates_tenant_isolation ON public.saml_idp_sp_certificates
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));
```

---

## [SECURITY] Certificate Cleanup Race Condition

**Found in:** `app/jobs/rotate_certificates.py:278-316`, `app/database/sp_signing_certificates.py:160-181`
**Severity:** Low
**OWASP Category:** A04:2021 - Insecure Design
**Description:** The certificate cleanup job selects certificates whose `rotation_grace_period_ends_at < now()`, then issues an UPDATE to clear the previous certificate fields. The UPDATE does not re-verify that `rotation_grace_period_ends_at` still matches the value seen at selection time. If an admin manually rotates the same certificate between the SELECT and UPDATE, the cleanup will clear the newly-set previous certificate, bypassing its grace period.

**Attack Scenario:** This is not directly exploitable by an external attacker. It requires a coincidence: the rotation job must be running cleanup at the exact moment an admin triggers a manual certificate rotation for the same SP. The result is that the previous certificate (which SPs may still be using during the grace window) is prematurely cleared, causing brief SSO validation failures for that SP.

**Evidence:**
```python
# rotate_certificates.py:287 - No re-check of grace period timestamp
result = database.sp_signing_certificates.clear_previous_signing_certificate(
    tenant_id, sp_id
)

# sp_signing_certificates.py:166-180 - UPDATE has no WHERE guard on timestamp
update sp_signing_certificates
set previous_certificate_pem = null,
    previous_private_key_pem_enc = null,
    previous_expires_at = null,
    rotation_grace_period_ends_at = null
where sp_id = :sp_id  -- No: AND rotation_grace_period_ends_at < now()
returning ...
```
**Impact:** Premature grace period termination causing brief SSO disruption for a single SP. No data leakage or privilege escalation.
**Remediation:** Add a timestamp guard to the cleanup UPDATE:

```sql
update sp_signing_certificates
set previous_certificate_pem = null,
    previous_private_key_pem_enc = null,
    previous_expires_at = null,
    rotation_grace_period_ends_at = null
where sp_id = :sp_id
  and rotation_grace_period_ends_at is not null
  and rotation_grace_period_ends_at < now()
returning ...
```

---
