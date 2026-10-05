# Audit

Review a complete event log of all actions taken in your tenant. Navigate to **Audit > Event Log**.

## Event log

Every write operation in WeftID is recorded in the event log. Events capture who performed the action, what was affected, when it happened, and relevant context.

### Visibility tiers

Events are classified into four visibility tiers. Toggle tiers on or off using the colored buttons above the event list.

| Tier | Color | What it covers | Shown by default |
|------|-------|----------------|-----------------|
| **Security** | Red | Authentication, authorization, credential changes, account lifecycle | Yes |
| **Admin** | Blue | Configuration changes by admins (IdP/SP setup, settings, groups, emails, branding) | Yes |
| **Operational** | Amber | High-volume automated activity (SSO assertions, certificate auto-rotation, group sync) | No |
| **System** | Gray | Internal bookkeeping (export jobs, task creation, setup steps) | No |

By default, the event log shows security and admin events. Enable operational or system tiers to see the full picture.

Each event's tier is shown as a colored badge in both the list and detail views.

### Filtering

Filter by tier with the toggles above the list. The [API](../../api/index.md) (`GET /api/v1/events`) accepts the same `tiers` parameter.

### Event detail

Click any event to see its full details, including metadata and request information (IP address, user agent).

### Event log export

Export events as a password-encrypted XLSX spreadsheet. Optionally filter by date range using the **From** and **To** fields before clicking **Export**.

The export runs as a background job. Check progress at [Background Jobs](../../user-guide/background-jobs.md). When complete, the job shows a **Download** link and the file password (copy it before downloading).

The XLSX file resolves IDs to human-readable names: user names, group names, SP names, and IdP names appear alongside their UUIDs. Cells are locked to prevent accidental modification.

Files are retained for 24 hours, then automatically deleted. Admin role required.

## User export

Export a comprehensive snapshot of all users, group memberships, and application access. Navigate to **Directory > Exports** and click **Export Users**.

The export produces a password-encrypted XLSX workbook with three sheets:

* **Users**: role, status, auth method, two-step verification, last sign-in, app count, and more
* **Group Memberships**: one row per user-group pair, with group name, type, and membership date
* **App Access**: one row per user-application pair, with last authentication date and how access is granted (group names or "All users")

The export runs as a background job, same as event log exports. See [Background Jobs](../../user-guide/background-jobs.md) for downloading and file passwords.

## SAML debug log

Navigate to **Audit > SAML Debug Log** to view a log of SAML authentication failures. Each entry shows the error type, identity provider, timestamp, and the raw SAML response XML for troubleshooting.

By default, only failures are logged. To temporarily log successful assertions (for debugging attribute mapping or encryption), enable **Verbose logging** on the identity provider's detail page.

See [SAML Setup > SAML debug log](../identity-providers/saml-setup.md#saml-debug-log) for details.

## Event types

Events cover all areas of the platform:

| Category | Examples |
|----------|---------|
| Authentication | Sign-in, sign-out, password changes, password resets, breach detection, passkey sign-in |
| Users | Created, updated, deactivated (manually, in bulk, or for inactivity), reactivated, anonymized, profile updated |
| User attributes | Tenant attribute settings changed, IdP attribute values mirrored at sign-in, mirrored values scrubbed on IdP delete |
| Groups | Created, deleted, members added/removed, relationships changed, IdP groups discovered or renamed |
| SAML identity providers | Created, updated, trust established, deleted, domains bound, sign-in received or failed |
| OIDC and social sign-in providers | Connection created, updated, tested, deleted; domains bound; sign-in started, completed, failed, or refused by the account-linking policy; JIT provisioning |
| Account linking | Sign-in account linked to or unlinked from a user |
| SAML service providers | Created, updated, deleted, group access changed, SSO assertions issued |
| OAuth2 / OIDC apps | Created, updated, client authentication or subject type changed, OIDC enabled, group access changed, access denied, ID token issued |
| Client registration | Client registered, updated, or deleted itself; initial access tokens issued or revoked; settings changed |
| Consent and tokens | Consent granted, widened, or revoked; token revoked; authorization code reused; device sign-in approved or denied; pushed authorization request (PAR) |
| Forward auth | Protected domain registered, verified, or deleted; proxy app changed; group grant added or removed; access granted or denied |
| Outbound SCIM | Configuration updated, bearer token created, imported, rotated, revoked |
| Inbound SCIM | Bearer token created/revoked, user received/updated/deactivated/reactivated/rebound, group received/updated/deleted |
| Certificates and keys | SAML certificates created or rotated, OIDC signing key rotated |
| Settings | Session, certificate, permission, branding, and group assertion scope changes |
| Two-step verification | Method changed, backup codes regenerated, admin resets, passkey registered/deleted/renamed |
| Authentication policy | Tenant authentication strength changed, user enhanced-auth enrollment completed |

## Activity tracking

Read operations (viewing user lists, group details, etc.) are tracked separately from the event log. Activity tracking records the last time each user accessed the system. This data feeds into the [automatic deactivation](../security/sessions.md) feature.
