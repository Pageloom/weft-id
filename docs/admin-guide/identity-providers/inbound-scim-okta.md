# Inbound SCIM Setup (Okta)

This guide walks through configuring Okta to push users and groups
into WeftID over SCIM 2.0. See the [Inbound SCIM
overview](inbound-scim.md) for what inbound SCIM does, prerequisites,
and lifecycle details.

## Prerequisites

* A SAML IdP connection between Okta and WeftID is already
  configured and tested (see [SAML Setup](saml-setup.md)).
* You have super-admin access to the WeftID tenant.
* You have Application Administrator (or Super Administrator) access
  to the Okta org.

## 1. Mint a bearer token in WeftID

1. In WeftID, open the Okta SAML IdP detail page.
2. Click the **SCIM Provisioning** tab.
3. Copy the **SCIM base URL** shown at the top of the tab. It has
   the form
   `https://<tenant-subdomain>.weftid.com/scim/v2/inbound/<idp-id>/`.
4. Click **Create token**. Give the token a name (e.g. "Okta
   production"). The plaintext bearer is displayed once in an amber
   box; copy it now.

!!! warning
    The token plaintext is shown only at creation time. WeftID
    stores only its SHA-256 hash. If you close the modal before
    pasting the token into Okta, revoke it and create a new one.

> TODO: screenshot - WeftID SCIM Provisioning tab with token plaintext box

## 2. Configure SCIM in the Okta application

Okta's SCIM client lives on the SAML application you already created
for WeftID. You do not need a separate app for SCIM provisioning.

1. Sign in to your Okta admin console.
2. Navigate to **Applications > Applications** and open the WeftID
   SAML app.
3. Click the **General** tab and click **Edit** next to **App
   Settings**.
4. Under **Provisioning**, select **SCIM**. Save.
5. A new **Provisioning** tab appears. Click it.
6. Under **SCIM Connection**, click **Edit** and fill in:

   * **SCIM connector base URL** -- paste the SCIM base URL from
     step 1 of the WeftID side (form
     `https://<tenant-subdomain>.weftid.com/scim/v2/inbound/<idp-id>/`).
   * **Unique identifier field for users** -- `userName`.
   * **Supported provisioning actions** -- check all four (Push New
     Users, Push Profile Updates, Push Groups, Import New Users and
     Profile Updates is optional; WeftID supports the read endpoints
     either way).
   * **Authentication Mode** -- `HTTP Header`.
   * **HTTP Header > Authorization** -- paste the plaintext bearer
     token from step 1.
7. Click **Test Connector Configuration**. Okta probes the SCIM
   endpoint; you should see a green check on each test. If any test
   fails with 401, recheck the bearer value (no surrounding
   whitespace, no `Bearer` prefix in the token field; Okta adds it).
8. Save.

> TODO: screenshot - Okta SCIM Connection edit dialog with WeftID base URL and bearer

## 3. Enable Users and Groups provisioning

1. Still on the **Provisioning** tab, click **To App** in the left
   panel.
2. Click **Edit** on **Provisioning to App**.
3. Enable:

   * **Create Users**
   * **Update User Attributes**
   * **Deactivate Users**
4. Save.
5. Open the **Push Groups** tab. Click **Push Groups** > **Find
   groups by name** and select the groups whose members should be
   provisioned into WeftID. For each group, choose **Create Group
   in target** (Okta will POST the group, then add memberships).

> TODO: screenshot - Okta Provisioning to App settings

## 4. Attribute mapping

WeftID's attribute mirroring is configured per tenant (see [User
Attributes](../security/user-attributes.md)). Inbound SCIM writes
flow through the same pipeline: Okta sends an attribute, WeftID
stores it on the user's IdP-attribute row, and tenant configuration
decides whether to mirror that attribute into the canonical user
field (e.g. canonical email, first name, last name).

Notes on Okta's defaults:

* Okta sends the standard SCIM 2.0 core User schema
  (`urn:ietf:params:scim:schemas:core:2.0:User`) plus the
  Enterprise User extension
  (`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`).
  WeftID supports both.
* Okta sends its own internal user id as `externalId`. WeftID
  preserves it and uses it as the primary merge key on subsequent
  POSTs. Your Okta user id is preserved across sign-in,
  deprovisioning, and reactivation.
* Okta's `userName` becomes the WeftID canonical username (subject
  to tenant mirroring config). The user's primary work email goes
  into `emails[type eq "work"].value`.

For most deployments the Okta defaults map cleanly to WeftID's
canonical fields. If your tenant has custom attributes (e.g.
employee number, department) you want mirrored, configure them in
both Okta's attribute editor and WeftID's attribute mirroring
config; the two systems share the SCIM attribute name as the join
key.

!!! tip
    If a user's canonical email changes upstream, Okta sends a PUT
    or PATCH. WeftID treats this as a profile update on the same
    user (matched by Okta's `externalId`), not as a new user. No
    duplicate accounts are created.

## 5. Assign users and groups to the app

Okta only pushes users it has been told to push. Assign the SAML app
to the users (or groups) that should be provisioned into WeftID:

1. On the WeftID app, click **Assignments**.
2. Click **Assign > Assign to People** (or **Assign to Groups**) and
   pick the users or groups.
3. Okta runs an initial provisioning pass on each assignment.

After a successful push, the user appears in WeftID's user list with
the IdP attribute rows populated, and **Audit > Event Log** shows a
`scim_user_received` event for each new user.

## 6. Verify

1. In WeftID, open **Audit > Event Log** filtered to the IdP id.
   Confirm a stream of `scim_user_received` (and `scim_group_received`
   for assigned groups) events.
2. Open the SCIM Provisioning tab on the IdP. The bearer token's
   **Last used** timestamp should be within the last few minutes.
3. Try assigning a new test user in Okta; within seconds the user
   should appear in WeftID.

## Troubleshooting

### Okta's Test Connector returns 401

* Recheck the SCIM base URL. The path must end with the IdP id and a
  trailing slash; the form is
  `https://<tenant-subdomain>.weftid.com/scim/v2/inbound/<idp-id>/`.
* Confirm the bearer is the exact plaintext from WeftID's amber box,
  with no surrounding whitespace and no `Bearer` prefix.
* Confirm the token has not been revoked in WeftID.

### A user is pushed but lands without expected attributes

Check WeftID's tenant attribute mirroring configuration. If an
attribute is not configured to mirror, it lives only on the IdP-row
side (visible on the user's IdP Attributes tab) and is not promoted
to a canonical user field. This is by design; see [User
Attributes](../security/user-attributes.md).

### A user is reactivated in Okta but stays inactive in WeftID

WeftID reactivates on the SCIM payload that flips `active` from
`false` to `true`. If Okta did not send the PUT or PATCH (sometimes
the case when reactivation happens via group reassignment rather
than direct status change), trigger a manual provisioning sync from
Okta's app: **Provisioning > Settings > Force Sync**.
