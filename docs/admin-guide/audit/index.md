# Audit

Review a complete event log of all actions taken in your tenant. Navigate to **Audit > Events**.

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

Filter the event log by date range, event type, actor (who performed the action), artifact type, and artifact ID.

### Event detail

Click any event to see its full details, including metadata and request information (IP address, user agent).

### Event log export

Export events as a password-encrypted XLSX spreadsheet. Optionally filter by date range using the **From** and **To** fields before clicking **Export**.

The export runs as a background job. Check progress at [Background Jobs](../../user-guide/background-jobs.md). When complete, the job shows a **Download** link and the file password (copy it before downloading).

The XLSX file resolves IDs to human-readable names: user names, group names, SP names, and IdP names appear alongside their UUIDs. Cells are locked to prevent accidental modification.

Files are retained for 24 hours, then automatically deleted. Admin role required.

## User export

Export a comprehensive snapshot of all users, group memberships, and application access. Navigate to **Audit > User Export** and click **Export Users**.

The export produces a password-encrypted XLSX workbook with three sheets:

* **Users** -- role, status, auth method, two-step verification, last sign-in, app count, and more
* **Group Memberships** -- one row per user-group pair, with group name, type, and membership date
* **App Access** -- one row per user-application pair, with last authentication date and how access is granted (group names or "All users")

The export runs as a background job, same as event log exports. See [Background Jobs](../../user-guide/background-jobs.md) for downloading and file passwords.

## SAML debug log

Navigate to **Audit > SAML Debug** to view a log of SAML authentication failures. Each entry shows the error type, identity provider, timestamp, and the raw SAML response XML for troubleshooting.

By default, only failures are logged. To temporarily log successful assertions (for debugging attribute mapping or encryption), enable **Verbose logging** on the identity provider's detail page.

See [SAML Setup > SAML debug log](../identity-providers/saml-setup.md#saml-debug-log) for details.

## Event types

Events cover all areas of the platform:

| Category | Examples |
|----------|---------|
| Authentication | Sign-in, sign-out, password changes, password resets, breach detection |
| Users | Created, updated, inactivated, reactivated, anonymized |
| Groups | Created, deleted, members added/removed, relationships changed |
| Identity providers | Created, updated, trust established, deleted |
| Service providers | Created, updated, deleted, SSO assertions issued |
| Certificates | Created, rotated |
| Settings | Session, certificate, permission, branding, and group assertion scope changes |
| Two-step verification | Method changed, backup codes regenerated, admin resets |

## Activity tracking

Read operations (viewing user lists, group details, etc.) are tracked separately from the event log. Activity tracking records the last time each user accessed the system. This data feeds into the [automatic inactivation](../security/sessions.md) feature.
