# Email Management

Email addresses in WeftID are managed by administrators. Users can view their emails at **Account > Emails** but cannot add, remove, or promote them.

## Viewing a user's emails

Open the user's detail page (**Users > click a user > Profile tab**). The **Email Addresses** section shows all emails with their status (primary, verified, unverified) and creation date.

## Adding a secondary email

On the user's profile tab, scroll to **Add Secondary Email**. Enter an email address from a [privileged domain](../identity-providers/privileged-domains.md) and click **Add Email**. The email is auto-verified and immediately usable.

Only emails from privileged domains can be added individually. For bulk additions without this restriction, see [Bulk add secondary emails](#bulk-add-secondary-emails) below.

## Promoting to primary

Click **Make Primary** next to any verified secondary email. The primary email is the one used for sign-in and included in SAML assertions as the NameID (for email-format assertions).

### Impact warnings

When a primary email change affects downstream systems, WeftID shows a warning before proceeding:

**SP assertion impact.** If service providers use the user's email as their NameID, those SPs will receive a different identity in future SAML assertions. The warning lists each affected SP and its NameID format. SPs using persistent or transient NameIDs are not affected.

**IdP routing change.** If the new email's domain is bound to a different identity provider than the user's current one, the warning shows the routing change (e.g., "Okta to Azure AD"). This means the user may authenticate differently after the change.

Review the impact, then click **Confirm & Promote** to proceed.

## Removing an email

Click **Remove** next to any secondary email. The primary email cannot be removed. A user must always have at least one email address.

## Resending invitations

If a user hasn't completed onboarding (no password set), a **Resend Invitation** button appears on their profile tab. Clicking it sends a fresh invitation email and invalidates any previous invitation link.

WeftID automatically detects the right email type:

- If the user's email is already verified, they receive a set-password link
- If not yet verified, they receive a verification link first

Invitation links are one-time use. Once a user sets their password, the link expires.

---

## Bulk email operations

For changes across many users at once, WeftID provides two bulk operations. Both are accessible from the user list page.

### Selecting users

1. Navigate to **Users > User List**
2. Use checkboxes to select individual users, or use the header checkbox to select all on the current page
3. For large result sets: after selecting all on the page, click **Select all N matching users** to include every user matching the current search and filters (across all pages)

Once users are selected, the bulk action bar appears at the bottom with available operations.

### Bulk add secondary emails

Add a secondary email address to multiple users at once.

1. Select users from the user list
2. Click **Manage Secondary Emails**
3. For each user, enter a new secondary email address or leave blank to skip
4. Click **Add Secondary Emails** to submit

A background job processes the additions. Check progress at **Account > Background Jobs**.

Each email in the results has one of three statuses:

| Status | Meaning |
|--------|---------|
| Added | Email added and auto-verified |
| Skipped | Email already exists in the tenant |
| Error | User not found or another issue |

!!! note
    Unlike single-user email additions, bulk operations do not restrict emails to privileged domains. Any valid email address is accepted.

### Bulk change primary emails

Change the primary email for multiple users at once, with a preview of downstream impact before applying.

**Step 1: Select new emails.** After selecting users and clicking **Change Primary Email**, choose a secondary email to promote for each user. Users without secondary emails show "No secondary emails." Leave a user on "No change" to skip them.

**Step 2: Preview impact.** Click **Preview Changes** to run a dry-run analysis. WeftID checks each user for:

- **SP assertion impact** -- how many service providers use email-based NameIDs and will see a different identity in future assertions. SPs using persistent or transient NameIDs are unaffected.
- **IdP routing change** -- whether the new email's domain routes to a different identity provider. This could change how the user authenticates.

The preview table shows each user's impact with color indicators:

| Color | Meaning |
|-------|---------|
| Green | No impact. All SPs use persistent/transient NameIDs and no IdP change. |
| Amber | SP assertions will change, or IdP routing will change. Review before applying. |
| Red | Error during preview (e.g., user not found). |

**Step 3: Choose IdP disposition.** For users with an IdP routing change, a dropdown lets you choose what happens to their IdP assignment:

| Option | Effect |
|--------|--------|
| Keep current IdP | Primary email changes, but authentication method stays the same |
| Switch to new IdP | User moves to the IdP bound to the new email's domain |
| Remove IdP (password) | User reverts to password authentication |

**Step 4: Apply changes.** Click **Apply Changes** to execute. A background job processes each user and reports results.

The old primary email address receives a notification about the change.
