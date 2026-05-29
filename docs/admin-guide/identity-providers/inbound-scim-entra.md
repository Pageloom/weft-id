# Inbound SCIM Setup (Microsoft Entra ID)

This guide walks through configuring Microsoft Entra ID (formerly
Azure AD) to push users and groups into WeftID over SCIM 2.0. See
the [Inbound SCIM overview](inbound-scim.md) for what inbound SCIM
does, prerequisites, and lifecycle details.

## Prerequisites

* A SAML IdP connection between Entra and WeftID is already
  configured and tested (see [SAML Setup](saml-setup.md)). Entra's
  SCIM provisioning lives on the same Enterprise App as the SAML
  configuration.
* You have super-admin access to the WeftID tenant.
* You have at least Application Administrator (or Cloud Application
  Administrator) access to the Entra tenant.

## 1. Mint a bearer token in WeftID

1. In WeftID, open the Entra SAML IdP detail page.
2. Click the **SCIM Provisioning** tab.
3. Copy the **SCIM base URL** shown at the top of the tab. It has
   the form
   `https://<tenant-subdomain>.weftid.com/scim/v2/inbound/<idp-id>/`.
4. Click **Create token**. Give the token a name (e.g. "Entra
   production"). The plaintext bearer is displayed once; copy it
   now.

!!! warning
    The token plaintext is shown only at creation time. WeftID
    stores only its SHA-256 hash. If you close the modal before
    pasting the token into Entra, revoke it and create a new one.

> TODO: screenshot - WeftID SCIM Provisioning tab with token plaintext box

## 2. Enable provisioning on the Enterprise App

1. Sign in to the Entra admin centre at
   [entra.microsoft.com](https://entra.microsoft.com).
2. Navigate to **Identity > Applications > Enterprise applications**
   and open the WeftID Enterprise App you use for SAML SSO.
3. In the left navigation, click **Provisioning**.
4. Click **Get started**.
5. Set **Provisioning Mode** to **Automatic**.

> TODO: screenshot - Entra Enterprise App Provisioning blade

## 3. Configure the SCIM endpoint and bearer token

In the **Admin Credentials** section:

* **Tenant URL** -- paste the SCIM base URL from step 1 of the
  WeftID side (form
  `https://<tenant-subdomain>.weftid.com/scim/v2/inbound/<idp-id>/`).
* **Secret Token** -- paste the plaintext bearer token from step 1.

Click **Test Connection**. Entra runs a probe against the
ServiceProviderConfig and Users endpoints. You should see "The
supplied credentials are authorized to enable provisioning."

Click **Save**.

> TODO: screenshot - Entra Admin Credentials with Tenant URL and Secret Token

## 4. Configure attribute mappings

The default Entra-to-SCIM mappings work cleanly with WeftID. In most
cases no changes are required. WeftID's tenant attribute mirroring
config (see [User Attributes](../security/user-attributes.md))
controls which SCIM attributes are promoted to canonical user
fields.

In the **Mappings** section:

1. **Provision Microsoft Entra ID Users** -- click in. Verify:

   * `userPrincipalName` maps to `userName`.
   * `Switch([IsSoftDeleted], , "False", "True", "True", "False")`
     maps to `active`.
   * `objectId` maps to `externalId`. This is the key WeftID uses
     to dedupe pushes; do not unmap it.
   * Standard name, email, and Enterprise User extension attributes
     (`employeeId`, `department`, `manager`) map to their SCIM
     equivalents.
2. **Provision Microsoft Entra ID Groups** -- click in. Verify:

   * `displayName` maps to `displayName`.
   * `objectId` maps to `externalId`.
   * `members` maps to `members`.

!!! note
    Entra sends batched PATCH operations with URN-prefixed paths
    (e.g.
    `urn:ietf:params:scim:schemas:core:2.0:User:userName`) and
    stringified booleans for `active` ("True" / "False"). WeftID
    handles both shapes; no admin configuration needed.

!!! note
    Entra stores its own internal object id and sends it as
    `externalId`. WeftID preserves this id and uses it as the
    primary merge key. Your Entra object id is preserved across
    sign-in, deprovisioning, and reactivation.

## 5. Enable group provisioning

Group provisioning is on by default once you select **Provisioning
Microsoft Entra ID Groups** in the Mappings panel. Two things to
double-check:

* In the **Settings** section, **Scope** should be either **Sync
  only assigned users and groups** (recommended; Entra only
  provisions the users and groups assigned to the Enterprise App)
  or **Sync all users and groups** (use with caution, large
  tenants).
* Under the **Users and groups** blade of the Enterprise App,
  assign the groups whose membership should be provisioned. Each
  assigned group is POSTed as a SCIM Group, and its members are
  POSTed as SCIM Users (if not already assigned individually).

## 6. Start provisioning

1. Back on the **Provisioning** overview, set **Provisioning
   Status** to **On**.
2. Click **Save**.

Entra runs an initial cycle (which can take 10 to 40 minutes
depending on tenant size). Subsequent incremental syncs run every
40 minutes by default.

## 7. Verify

1. In WeftID, open **Audit > Event Log** filtered to the IdP id.
   Confirm a stream of `scim_user_received` and `scim_group_received`
   events as the initial sync progresses.
2. Open the SCIM Provisioning tab on the IdP. The bearer token's
   **Last used** timestamp should advance during each Entra sync
   cycle.
3. In Entra, the **Provisioning logs** blade shows per-user and
   per-group push results. A successful push reports "Provisioned"
   in green.

## Troubleshooting

### Entra's Test Connection fails with 401

* Recheck the **Tenant URL**. It must end with the IdP id and a
  trailing slash; the form is
  `https://<tenant-subdomain>.weftid.com/scim/v2/inbound/<idp-id>/`.
* Confirm the **Secret Token** is the exact plaintext from WeftID's
  amber box, with no surrounding whitespace. Entra adds the
  `Bearer` prefix itself.
* Confirm the token has not been revoked in WeftID.

### Provisioning logs show "skipped" for users

Entra skips users not in scope. Check the **Scope** setting and the
Enterprise App's **Users and groups** assignments. A user must be
assigned (directly or via an assigned group) to be in scope.

### A user is removed from a group in Entra but membership persists in WeftID

Entra's incremental sync runs every 40 minutes. Trigger an immediate
sync from the **Provisioning** overview blade with **Provision on
demand** (search for the user, then click **Provision**).

If the membership change still does not appear, check the
provisioning logs for an error against that user. A common cause is
the user being out of scope: removing them from a group also removes
them from the Enterprise App's assignment, which Entra reports as a
deactivation rather than a membership change.

### Entra reports "ConflictDetected" on a user

Entra raises this when the WeftID side reports that a `userName` is
already in use by a different `externalId`. The usual cause is two
Entra objects pointing at the same SCIM userName (sometimes after a
user account merge upstream). Resolve the conflict on the Entra side
(consolidate the duplicate objects), then re-provision.
