# Audit

Review a complete event log of all actions taken in your tenant. Navigate to **Audit > Events**.

## Event log

Every write operation in WeftID is recorded in the event log. Events capture who performed the action, what was affected, when it happened, and relevant context.

### Filtering

Filter the event log by date range, event type, actor (who performed the action), artifact type, and artifact ID.

### Event detail

Click any event to see its full details, including metadata and request information (IP address, user agent).

### Export

Export events as a password-encrypted XLSX spreadsheet. Optionally filter by date range using the **From** and **To** fields before clicking **Export**.

The export runs as a background job. Check progress at [Background Jobs](../../user-guide/background-jobs.md). When complete, the job shows a **Download** link and the file password (copy it before downloading).

The XLSX file resolves IDs to human-readable names: user names, group names, SP names, and IdP names appear alongside their UUIDs. Cells are locked to prevent accidental modification.

Files are retained for 24 hours, then automatically deleted. Admin role required.

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
