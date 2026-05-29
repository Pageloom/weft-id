# Inbound SCIM Provisioning

WeftID can receive user and group changes pushed from an upstream
identity provider over SCIM 2.0. With inbound SCIM enabled, Okta or
Entra creates, updates, and deactivates user and group records in
WeftID without waiting for the user to sign in.

This guide covers what inbound SCIM does, when to enable it, how to
mint a bearer token, the lifecycle of users provisioned this way, and
how to troubleshoot common issues. Vendor-specific setup walkthroughs
live in separate pages.

## What inbound SCIM does

WeftID is a SCIM 2.0 *server* in this direction: the upstream IdP is
the client, WeftID is the receiver. Each push from the IdP creates,
updates, or deactivates a user or group inside the tenant.

Without inbound SCIM, WeftID only learns about a user when they
first sign in via SAML (just-in-time provisioning). That means:

* A deprovisioned upstream user retains their WeftID account until
  their next sign-in attempt fails.
* An admin cannot grant downstream SP access to a user who has not
  yet signed in.
* New hires do not appear in the WeftID directory until their first
  login.

With inbound SCIM, WeftID's directory state mirrors the upstream IdP
within seconds of any change. Combined with [outbound
SCIM](../service-providers/scim.md), this closes the end-to-end loop:
upstream IdP, then WeftID, then downstream SaaS.

## When to use inbound SCIM

Enable inbound SCIM if any of the following apply:

* You want to pre-provision SP access for new hires before they sign
  in for the first time.
* You want WeftID to deprovision a user the moment the upstream IdP
  removes them, not at their next failed login.
* You manage group membership in the upstream IdP and want the same
  membership reflected in WeftID for SP access grants.
* You have already enabled [outbound
  SCIM](../service-providers/scim.md) to downstream SaaS and want
  upstream changes to cascade end-to-end.

If your users always sign in regularly and your downstream apps do
not use outbound SCIM, just-in-time provisioning may be sufficient.

## Prerequisites

* **A SAML IdP connection must already exist.** Inbound SCIM tokens
  are bound to a specific `saml_identity_providers` row. Create and
  test the SAML connection first (see [SAML Setup](saml-setup.md));
  inbound SCIM is configured on a tab of the same IdP detail page.
* **Super-admin role.** Only super admins can mint or revoke inbound
  SCIM tokens.
* **The tenant's public hostname must be reachable from the
  upstream IdP.** Okta and Entra both push from public network
  egress. Self-hosted deployments behind a private network must
  expose the SCIM endpoint via a public ingress.

!!! note
    Inbound SCIM never writes role, MFA enforcement, or platform
    authentication policy. Those remain admin-only. Inbound SCIM is
    a directory mirror: email, names, status, custom mirrored
    attributes, and group membership.

## Enabling inbound SCIM

Inbound SCIM lives on its own tab on each SAML IdP's detail page.
Open the IdP, click **SCIM Provisioning**, and follow the steps in
the vendor-specific walkthroughs ([Okta](inbound-scim-okta.md),
[Entra](inbound-scim-entra.md)).

The tab shows two things admins need:

* **SCIM base URL** of the form
  `https://<tenant-subdomain>.weftid.com/scim/v2/inbound/<idp-id>/`.
  Copy this into the upstream IdP's SCIM connector configuration.
* **Bearer tokens** list, with a **Create token** action. The
  plaintext value is shown once at creation time.

## Credential lifecycle

Bearer tokens authenticate the inbound SCIM client (Okta, Entra,
or any spec-correct SCIM 2.0 client).

### Create a token

1. On the SCIM Provisioning tab, click **Create token**.
2. Give the token a name (e.g. "Okta production"). Names are not
   required to be unique; an admin may legitimately want two tokens
   both labelled "Okta production" during a careful rotation.
3. The plaintext bearer is shown once. Copy it immediately into the
   upstream IdP's SCIM bearer-token field.
4. Click **Done** to refresh the page. The token appears in the
   active list, identified by its first few characters.

!!! warning
    The plaintext is shown once and never again. WeftID stores only a
    SHA-256 hash of the token. If you lose the value before pasting
    it into the upstream IdP, revoke the token and create a new one.

### Revoke a token

Use **Revoke** when you need to invalidate a token immediately (lost
device, departing admin, suspected leak, or end of life for a
rotation). Revocation is instantaneous: the next push from the IdP
using that token returns a SCIM 401.

Revocation cannot be undone. Create a fresh token after revoking.

### No overlap window

Unlike outbound SCIM (where a rotation overlap window protects
in-flight pushes), inbound SCIM tokens have no rotation overlap.
Inbound traffic is request and response: there are no buffered
pushes to drain. The rotation pattern is therefore:

1. Create a new token.
2. Paste the new token into the upstream IdP's connector.
3. Verify a SCIM push succeeds under the new token (Okta and Entra
   both have a "Test" button on the provisioning connector).
4. Revoke the old token.

## Lifecycle of provisioned users

### Provisioning

When Okta or Entra POSTs a new user, WeftID either:

* **Creates** a new user record bound to this IdP connection, OR
* **Merges** into an existing user, matched first by the upstream
  `externalId` (preferred), then by canonical email.

Merge-on-email is what lets a JIT-provisioned user (who signed in
before SCIM was wired up) become a SCIM-managed user without losing
audit history or grants.

Subsequent PUT and PATCH operations update the user. Attributes flow
through the existing IdP attribute mirroring pipeline: the IdP writes
to IdP-attribute rows, and tenant configuration decides whether to
mirror those into canonical user fields. This means SCIM and SAML
attributes share a single downstream path; no special-case mirroring.

### Deprovisioning (soft-delete)

When Okta or Entra sends DELETE (or sets `active: false`), WeftID
soft-deletes the user via the existing inactivate flow. The user is
no longer able to sign in, but the following are preserved:

* **MFA enrolment** (TOTP secret, backup codes). If the same user is
  later reactivated, their MFA enrolment is intact.
* **Audit history.** Every event the user was an actor on (or
  subject of) remains in the audit log.
* **Granted access.** Group memberships and SP grants are preserved
  so reactivation restores the same access posture without re-grant
  by an admin.

### Reactivation

When Okta or Entra later sets `active: true` (or POSTs the same
externalId again), WeftID reactivates the same user record. The MFA
enrolment, audit history, and access grants are all restored.

### Granted access preservation

This combination (soft-delete plus preservation plus reactivation) is
the key reason inbound SCIM differs from "delete and recreate" in
many SaaS apps. A WeftID user has the same identity across multiple
sign-ins, even if the upstream IdP has cycled their account through
disable and re-enable.

## Resource ID mapping

SCIM 2.0 says the receiver mints the canonical `id` for a resource
when the client POSTs it (RFC 7644 §3.3). WeftID returns its own UUID
as the SCIM `id`. The upstream IdP's id is preserved in the SCIM
`externalId` field and persisted internally under the reserved
`__external_id` attribute key for this IdP connection.

This means:

* **Okta or Entra sends its own user id as `externalId`.** WeftID
  stores it and resolves cross-references against it. Your upstream
  user id is preserved across sign-in, deprovisioning, and
  reactivation.
* **WeftID's `id` is its internal UUID.** SCIM clients should use
  this for subsequent PUT, PATCH, and DELETE calls. The Location
  header on every successful POST and read response carries the
  canonical URL.
* **Member references** in group `members[].value` may use either
  the WeftID id or the upstream `externalId`. WeftID resolves both,
  scoped to this IdP connection.

## Audit events

Every inbound SCIM write emits an audit event. The events visible
in the WeftID audit log are:

* `scim_inbound_token_created` -- a bearer token was minted (super
  admin action).
* `scim_inbound_token_revoked` -- a bearer token was revoked.
* `scim_user_received` -- a new user was created via SCIM POST.
* `scim_user_updated` -- a user was modified via SCIM PUT or PATCH.
* `scim_user_deactivated` -- a user was deactivated via SCIM DELETE
  or via PUT or PATCH that set `active` to false.
* `scim_group_received` -- a new IdP group was created via SCIM
  POST.
* `scim_group_updated` -- a group was modified via SCIM PUT or
  PATCH.
* `scim_group_deleted` -- a group was deleted via SCIM DELETE.
* Per-member events `idp_group_member_added` and
  `idp_group_member_removed` fire for every group membership
  change, the same as SAML-driven membership sync.

All events flow into outbound SCIM dispatch automatically. There is
no separate replay layer: an upstream change cascades to downstream
SPs through the same event-driven fan-out that admin-driven changes
use.

## Troubleshooting

### "Okta or Entra returns 401 Unauthorized on every push"

1. Confirm the bearer token has not been revoked. Open the SCIM
   Provisioning tab and verify the token's first characters match
   what's pasted into the upstream IdP.
2. Confirm the upstream IdP is sending `Authorization: Bearer <token>`
   with the exact value. Surrounding whitespace, missing prefix, or
   double-encoding all produce 401.
3. Confirm the SCIM base URL in the upstream IdP includes the
   correct IdP id. Tokens are scoped per IdP; pasting a token for
   IdP A into a connector pointed at IdP B returns 401.

WeftID returns a byte-identical 401 envelope for every authentication
failure mode (missing header, malformed header, empty token, unknown
token, revoked token, wrong IdP) to avoid leaking which case applies.
The envelope shape is the standard SCIM 2.0 Error response:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "401",
  "detail": "Unauthorized"
}
```

### "I need to rotate a token without downtime"

There is no overlap window. The safe procedure is:

1. Create a new token in WeftID. Copy the plaintext.
2. Paste the new token into the upstream IdP's connector and save.
3. Run the upstream IdP's "Test connection" (Okta) or "Test
   connection" then "Provision on demand" (Entra). Verify a 200
   response.
4. Revoke the old token in WeftID.

The window between steps 2 and 4 is brief; both tokens authenticate
during it.

### "A user provisioned via SAML JIT before SCIM should now be SCIM-managed"

This works automatically. On the first SCIM POST that arrives for the
same canonical email, WeftID merges into the existing user and binds
them to the IdP connection. The audit history, MFA enrolment, and
grants are preserved.

### "A user was unintentionally deactivated"

1. Open **Audit > Event Log** and filter to the IdP id to locate the
   triggering `scim_user_deactivated` event. The metadata records
   the IdP id and the SCIM payload.
2. The most common cause is an upstream group-membership change that
   removed the user from the SCIM scope in Okta or Entra. Restore
   the upstream membership; WeftID reactivates on the next SCIM
   push that flips `active` back to `true`.
3. The user's MFA enrolment and access grants are intact across the
   deactivation, so reactivation requires no further admin action.

### "Inbound SCIM is configured but no pushes are arriving"

1. Verify the upstream IdP's "SCIM provisioning enabled" toggle is
   on (Okta: Provisioning tab; Entra: Provisioning blade).
2. Verify the upstream IdP's connector reports "Last sync: succeeded"
   in its monitoring view.
3. Confirm at least one user or group is in the IdP's SCIM scope. A
   connector with no assigned users sends no pushes.
4. Open **Audit > Event Log** filtered to the IdP id. Successful
   pushes emit `scim_user_received` or `scim_group_received`
   events; their absence narrows the diagnosis to network or
   upstream configuration.
