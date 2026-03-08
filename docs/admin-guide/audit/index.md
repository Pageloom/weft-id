# Audit

Review a complete event log of all actions taken in your tenant. Navigate to **Audit > Events**.

## Event log

Every write operation in WeftId is recorded in the event log. Events capture who performed the action, what was affected, when it happened, and relevant context.

### Filtering

Filter the event log by date range, event type, actor (who performed the action), artifact type, and artifact ID.

### Event detail

Click any event to see its full details, including metadata and request information (IP address, user agent).

### Export

Click **Export All Events** to generate a compressed JSON export of the entire event log. The export runs as a background job. You are redirected to [Background Jobs](../../user-guide/background-jobs.md) where you can track progress and download the file when ready.

The export file is a gzipped JSON archive containing all events, event type descriptions, and export metadata. Files are retained for 24 hours, after which they are automatically deleted. Admin role is required to export.

## Event types

Events cover all areas of the platform:

| Category | Examples |
|----------|---------|
| Authentication | Sign-in, sign-out, password changes |
| Users | Created, updated, inactivated, reactivated, anonymized |
| Groups | Created, deleted, members added/removed, relationships changed |
| Identity providers | Created, updated, trust established, deleted |
| Service providers | Created, updated, deleted, SSO assertions issued |
| Certificates | Created, rotated |
| Settings | Session, certificate, permission, and branding changes |
| Two-step verification | Method changed, backup codes regenerated, admin resets |

## Activity tracking

Read operations (viewing user lists, group details, etc.) are tracked separately from the event log. Activity tracking records the last time each user accessed the system. This data feeds into the [automatic inactivation](../security/sessions.md) feature.
