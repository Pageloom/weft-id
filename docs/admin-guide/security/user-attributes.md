# User attributes

WeftID supports a fixed catalog of 14 standard profile attributes beyond name and
email. Each tenant chooses which attributes to collect, how strictly to enforce them,
who can edit them, and which downstream service providers receive them.

Navigate to **Settings > User attributes** (super admin only).

## The attribute catalog

Attributes are grouped into four categories:

| Category | Attributes |
|----------|-----------|
| **Contact** | `phone_work`, `phone_mobile` |
| **Professional** | `display_name`, `job_title`, `department`, `organization`, `employee_id` |
| **Location** | `street_address`, `city`, `state`, `postal_code`, `country` |
| **Profile** | `preferred_language`, `description` |

The catalog is fixed. Custom attribute keys are not supported.

## The five flags

Each attribute has five independent flags. Each row saves on change (no Save button).

* **Enabled.** Collect this attribute for users in this tenant. When off, the attribute
  is hidden from profile pages, user creation, IdP mapping, and SP mapping. The other
  four flags are disabled until Enabled is on.
* **Required.** Users must provide a value. Missing values flag the user in
  **Todo > User attributes** and (when [force-completion](#force-profile-completion) is
  on) block sign-in until the field is filled.
* **Mirror from IdP.** When an upstream identity provider sends this attribute in a
  SAML assertion, copy the value into the user's profile on each sign-in. When off,
  the IdP value is still recorded as read-only audit data (visible on the user detail
  page) but the profile value is not updated.
* **Locked for users.** Users see the field as read-only on their profile page. Only
  admins can edit it (from the user detail page).
* **Send to new SPs.** Include this attribute in SAML assertions to newly-registered
  service providers by default. Existing SPs are unaffected; per-SP attribute mappings
  always override this default. See
  [attribute mapping](../service-providers/attribute-mapping.md) for per-SP control.

## Editing values

Where attributes can be edited depends on the locked-for-users flag and the
[edit-profile permission](permissions.md#allow-users-to-edit-their-profile):

| Field state | User can edit | Admin can edit |
|-------------|---------------|----------------|
| Unlocked, profile editing allowed | Yes | Yes |
| Unlocked, profile editing disabled | No | Yes |
| Locked | No | Yes |

Admins edit attributes on the user detail page (**Users > (user) > Profile**). Users
edit their own attributes on **Account > Profile**.

## Force profile completion

When required attributes go unfilled, admins can force users to complete their
profile before they can use the rest of the site.

1. Go to **Todo > User attributes**. Each row shows missing attributes split by
   whether they can be filled by the user (unlocked) or only by an admin (locked).
2. Select the users you want to gate. Users whose only missing values are locked
   cannot be selected (the gate would trap them; an admin must fill those fields
   directly).
3. Click **Force profile completion**.

Flagged users are redirected to their profile page on the next request. A banner
explains that an admin requires additional information. The required fields are
highlighted. Navigation to other pages is blocked until every unlocked-required
attribute has a value, after which the flag clears automatically.

The gate also applies to SAML SSO: an SP-initiated sign-in to a downstream
application waits for profile completion before issuing the assertion.

## How required attributes get values

There are several paths for an attribute to acquire a value:

1. **Pre-filled at user creation.** The user creation form lists enabled attributes;
   admins can populate any subset (including locked ones).
2. **Mirrored from an IdP at sign-in.** Configure the attribute on
   **Settings > Identity Providers > (IdP) > Attributes**. The first time the user
   signs in after the mapping is set, the value populates from the assertion.
3. **Filled by the user on their profile.** Subject to the locked flag and the
   tenant edit-profile permission.
4. **Filled by an admin on the user detail page.** Always allowed; locked attributes
   can only be filled here.

## Auditing IdP values

The user detail page shows a **Connected IdP attributes** section listing the
most recent values received from each identity provider, with a **Mirrored into
profile** badge on rows that were copied into the user's profile (per the mirror
flag). Use this to verify that an IdP is sending what you expect, even if you
choose not to mirror it.
