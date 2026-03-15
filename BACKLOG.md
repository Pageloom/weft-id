# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## Epic: Self-Hosting & Release Infrastructure

The items below form a connected initiative to make WeftId easy to self-host with good
security defaults, and to establish versioning, release, and upgrade practices. They are
listed in dependency order. Items 1-3 are foundational (do once before going public),
items 4-7 are the self-hosting deliverables, and item 8 is cleanup.

---

## ~~1. Version Management Policy~~ (Complete)

---

## ~~2. GHCR Publish Workflow~~ (Complete)

---

## ~~3. Changelog & Release Gate~~ (Complete)

---

## ~~4. Production Docker Compose for Self-Hosting~~ (Complete)

---

## ~~5. Self-Hosting Install Script~~ (Complete)

---

## ~~6. Tenant Provisioning CLI~~ (Complete)

---

## ~~7. Self-Hosting Upgrade & Operations Documentation~~ (Complete)

---

## 8. Remove Legacy Onprem Setup

**User Story:**
As a developer
I want to remove the old onprem files that are superseded by the new self-hosting setup
So that the repository is clean and there is one clear path for self-hosting

**Context:**

Once the production compose file (item 4) is in place, the following files are obsolete:
- `docker-compose.onprem.yml`
- `devscripts/onprem-setup.sh`
- `.env.onprem.example`
- `nginx/conf.d/app.onprem.conf.template`
- `nginx/conf.d/app.onprem.conf` (generated file)

The Makefile targets `up-onprem` and `migrate-onprem` should be updated to reference the
new production compose file, or removed if the self-hosting docs cover the commands directly.

**Acceptance Criteria:**

Files to remove:
- [ ] `docker-compose.onprem.yml`
- [ ] `devscripts/onprem-setup.sh`
- [ ] `.env.onprem.example`
- [ ] `nginx/conf.d/app.onprem.conf.template`
- [ ] `nginx/conf.d/app.onprem.conf` (generated file)

Makefile cleanup:
- [ ] Remove `up-onprem` target
- [ ] Remove `migrate-onprem` target
- [ ] Remove both from `.PHONY` declaration
- [ ] Add targets for the new production compose if useful (e.g., `up-prod`, `migrate-prod`), or omit if self-hosting docs cover the commands directly

Documentation updates:
- [ ] Update `CLAUDE.md` to remove all onprem references (development commands, migration section, etc.)
- [ ] Update `BACKLOG_ARCHIVE.md` and `ISSUES_ARCHIVE.md` if they reference onprem files (informational, no action needed if just historical context)
- [ ] Verify dev setup (`docker-compose.yml`, `make up`, `make dev`) is completely unaffected

**Effort:** S
**Value:** Low (Cleanup, depends on items 4-6 being complete)

---

---

---

## SAML: Group Assertion Transparency (Trunk-Only Mode + Consent Screen Visibility)

**User Story:**
As a super admin
I want to control whether full group memberships or only trunk groups are communicated in
SAML assertions, and as a user I want to see which groups will be shared during authentication
So that admins can minimize group exposure to service providers, and users understand what
identity information is being disclosed before they consent

**Context:**

Currently, SAML assertions include all of the user's group memberships. Two related gaps:

1. **Trunk-only mode:** A "trunk group" is any group the user belongs to that has no parent
   groups in the DAG. It represents the broadest, most concise outline of the user's group
   footprint without enumerating every nested membership. Communicating only trunk groups
   reduces how much internal group structure is leaked to service providers.

2. **Consent screen visibility:** The consent screen during SAML authentication does not show
   which groups will be shared with the SP. If group attributes are being asserted, the user
   should see exactly which groups are being disclosed before completing sign-in.

These are linked: if trunk-only mode is active, the consent screen should reflect the filtered
group set (not the full membership list).

**Acceptance Criteria:**

Trunk-only admin setting:
- [ ] New tenant-level setting in admin security settings: "Group assertion scope" with two
      options: "All groups" (share all group memberships) and "Trunk groups only" (share only
      groups with no parent groups in the DAG). Default: "Trunk groups only"
- [ ] "Trunk groups only" filters the group list included in any SAML assertion to those
      where the user has no parent group in the `group_lineage` table
- [ ] Setting is persisted with a migration; readable via the settings service
- [ ] Event logged (`group_assertion_scope_updated`) when the setting changes
- [ ] API endpoint exposes and allows updating the setting

Consent screen group disclosure:
- [ ] If the SP's attribute mapping includes a groups attribute, the consent screen displays
      the list of groups that will be shared in the assertion
- [ ] If trunk-only mode is active, the displayed groups reflect the filtered set
- [ ] If the SP does not request a groups attribute, this section is hidden
- [ ] Groups are listed by name; if the list is long (>10), show a count with a collapsible
      "show all" expansion

**Effort:** M
**Value:** Medium

---

## Create `/accessibility` Skill

**User Story:**
As a developer,
I want an `/accessibility` skill that audits the frontend for WCAG 2.1 AA compliance,
So that accessibility issues are identified and tracked systematically like security and compliance violations.

**Acceptance Criteria:**

- [ ] New skill file at `.claude/skills/accessibility/` following the pattern of existing skills
- [ ] Skill audits Jinja2 templates for WCAG 2.1 AA violations (missing alt text, insufficient contrast cues, missing form labels, ARIA misuse, keyboard navigation gaps, missing lang attributes, missing focus indicators)
- [ ] Skill logs findings to `ISSUES.md` in the same format as `/security` and `/compliance`
- [ ] Skill references a checklist in `.claude/references/wcag-patterns.md`
- [ ] Skill can be invoked with `/accessibility` from Claude Code

**Effort:** M
**Value:** Medium

---

## Dyslexic-Friendly Font User Preference

**User Story:**
As a user with dyslexia,
I want to enable a dyslexic-friendly font in my account settings,
So that the interface is more readable for me without affecting other users.

**Acceptance Criteria:**

- [ ] A font preference field is added to the user profile (boolean, default false)
- [ ] Database migration adds the column to the `users` table
- [ ] User can toggle the preference in their profile/settings page
- [ ] When enabled, the selected dyslexic-friendly font (e.g. OpenDyslexic or Atkinson Hyperlegible) is applied via a CSS class on the `<html>` or `<body>` element
- [ ] Font is served from static assets (not an external CDN) for privacy and reliability
- [ ] Preference persists across sessions (stored server-side)
- [ ] **No audit log** for this write (follows the `save_graph_layout()` pattern: it is UI preference state, not a business action). The service function docstring must note this explicitly.
- [ ] `track_activity()` is called (instead of `log_event()`) so the user's `last_activity_at` is still updated
- [ ] API endpoint exposes the preference for programmatic access

**Effort:** M
**Value:** Medium

---

## Admin: Super Admin Debug Impersonation

**User Story:**
As a super admin
I want to view what a specific user's application access looks like from their perspective
So that I can debug access and attribute issues without creating a real session as that user

**Context:**

This is a debug-only, read-only capability. The super admin sees the user's effective access
and the identity attributes that would be asserted for them, without performing a real
authentication to any SP. This is the "what would happen if they logged in?" companion to
the User-App Access Query item, which answers "does this user have access?".

**Acceptance Criteria:**

- [ ] Super admin only (not admin role)
- [ ] Accessible from the user detail page and/or the User-App Access view
- [ ] Shows the user's effective group memberships and the SPs accessible via those groups
- [ ] For a selected user + SP combination, shows a preview of the identity attributes
      (name, email, groups, any custom attribute mappings) that would be asserted
- [ ] Clearly labeled as a debug preview. No actual SP session or authentication occurs.
- [ ] Event logged in audit trail (`super_admin_debug_impersonation`) with actor, target user, and SP

**Effort:** M
**Value:** Low

---

## Contextual Documentation Links

**User Story:**
As an admin (or user) viewing any page in WeftId
I want a subtle documentation icon in the top-right area of the page
So that I can quickly jump to the relevant documentation without hunting through the docs site

**Context:**

Most pages in the application have a corresponding documentation page. A small
`information-circle` icon in the top-right of the page header would link directly to the
relevant docs section. The mapping is one link per page (entry point, not exhaustive).
Admin pages are the priority since those have the richest docs coverage, but user-facing
pages (dashboard, profile, two-step verification) should link to user-guide pages too.

**Implementation approach:**

Add an optional `docs_path` field to the `Page` dataclass in `app/pages.py`. This keeps
the page-to-docs mapping centralized in the same registry that drives navigation. The
template layer reads `docs_path` from the navigation context and renders the icon-link
when present. Pages without a `docs_path` simply show no icon.

**Proposed page-to-docs mapping:**

| Page / Section | Docs path |
|----------------|-----------|
| Dashboard | `/docs/user-guide/dashboard` |
| User list / detail | `/docs/admin-guide/users/` |
| Profile (account) | `/docs/user-guide/profile` |
| Two-step verification (account) | `/docs/user-guide/two-step-verification` |
| Background Jobs (account) | `/docs/user-guide/background-jobs` |
| Security settings | `/docs/admin-guide/security/` |
| Sessions | `/docs/admin-guide/security/sessions` |
| Certificates | `/docs/admin-guide/security/certificates` |
| Permissions | `/docs/admin-guide/security/permissions` |
| Privileged Domains | `/docs/admin-guide/identity-providers/privileged-domains` |
| Identity Providers | `/docs/admin-guide/identity-providers/` |
| IdP detail (all tabs) | `/docs/admin-guide/identity-providers/saml-setup` |
| Service Providers | `/docs/admin-guide/service-providers/` |
| SP detail: details | `/docs/admin-guide/service-providers/registering-an-sp` |
| SP detail: attributes | `/docs/admin-guide/service-providers/attribute-mapping` |
| SP detail: certificates | `/docs/admin-guide/service-providers/sp-certificates` |
| SP detail: metadata | `/docs/admin-guide/service-providers/registering-an-sp` |
| Branding | `/docs/admin-guide/branding/` |
| Groups list / detail | `/docs/admin-guide/groups/` |
| Group detail: membership | `/docs/admin-guide/groups/membership-management` |
| Group detail: relationships | `/docs/admin-guide/groups/group-hierarchy` |
| Group detail: applications | `/docs/admin-guide/groups/group-based-access` |
| Audit / Event Log | `/docs/admin-guide/audit/` |
| Integrations | `/docs/admin-guide/integrations/` |
| Reactivation | `/docs/admin-guide/users/user-lifecycle` |

**Acceptance Criteria:**

- [ ] `Page` dataclass gains an optional `docs_path: str | None` field (default `None`)
- [ ] `docs_path` is populated for all pages with a relevant documentation page (see mapping above)
- [ ] `docs_path` is passed through `get_navigation_context()` to templates
- [ ] Base template (or page header partial) renders an `information-circle` icon linked to `docs_path` in the top-right area of the page header, when `docs_path` is set
- [ ] Icon opens the docs page in a new tab (`target="_blank"`)
- [ ] Icon has a `title` tooltip (e.g., "View documentation")
- [ ] Icon is visually subtle (muted color, small size) so it does not compete with page content
- [ ] Pages without a `docs_path` show no icon (no empty placeholder)
- [ ] Child pages inherit their parent's `docs_path` if they don't define their own (so tab-level pages don't all need explicit entries unless a more specific doc exists)

**Effort:** S
**Value:** Medium

---

## Consolidate Tenant Name and Site Title

**User Story:**
As a platform operator
I want one name for my tenant, not two
So that the display name in the nav bar, emails, and everywhere else is always the organization name

**Context:**

Today the tenant has two name fields: `tenants.name` (the organization name, e.g., "Meridian
Health") and `tenant_branding.site_title` (a display name shown in the nav bar, max 30 chars,
defaults to "WeftId"). There is no good reason for these to differ. The split is an artifact
of branding settings being built separately from tenant creation.

Consolidation means removing `site_title` from `tenant_branding` and using `tenants.name`
everywhere. The nav bar shows the tenant name. Emails use the tenant name. The "WeftId"
default goes away. The `show_title_in_nav` toggle remains (controls whether to show the name
next to the logo, regardless of what the name is).

Admins can rename their tenant from the branding settings page (same place they currently
edit `site_title`), which updates `tenants.name`.

**Acceptance Criteria:**

Database:
- [ ] Migration removes `site_title` from `tenant_branding` (or marks it unused)
- [ ] Migration copies any non-default `site_title` values into `tenants.name` for tenants
      where `site_title` differs from the default "WeftId" (preserves admin customizations)
- [ ] `tenants.name` gains a `CHECK` constraint on length (max 30 chars, matching current
      `site_title` limit) if it doesn't already have one

Service layer:
- [ ] `get_branding_for_template()` returns `tenants.name` where it previously returned `site_title`
- [ ] `update_branding_settings()` updates `tenants.name` when the name field is changed
- [ ] `get_tenant_name()` utility continues to work (already reads from `tenants.name`)

Templates:
- [ ] Nav bar renders `tenants.name` where it previously rendered `site_title`
- [ ] Branding settings page edits `tenants.name` instead of `site_title`
- [ ] Any other template references to `site_title` are updated

API:
- [ ] Branding API endpoints reflect the change (no `site_title` field, name comes from tenant)

Tests:
- [ ] Existing branding tests updated to use tenant name
- [ ] Migration tested for correct data preservation

**Effort:** S
**Value:** Medium (Eliminates confusion, prerequisite for branded emails)

---

## Branded Email Headers

**User Story:**
As a user receiving an email from WeftId
I want the email to show my organization's logo and name
So that the email looks like it comes from my organization, not a generic system

**Context:**

All outbound emails (invitations, MFA codes, verification links, notifications) currently use
a plain HTML layout with no tenant branding. Each of the 12 email functions in `app/utils/email.py`
rebuilds its HTML from scratch with hardcoded styles.

This item adds a shared email header with the tenant's logo and name to all outbound emails.
The logo is the tenant's custom upload (light variant) or the generated mandala if no custom
logo exists. The name is the tenant name (after the consolidation item above removes the
`site_title` split).

For the logo in emails: the mandala is generated as SVG and can be rendered to a PNG for
email embedding (inline as a CID attachment or base64 data URI). Custom logos may be PNG or
SVG. Email clients have inconsistent SVG support, so SVG logos (both mandala and custom)
should be rasterized to PNG for the email context.

**Acceptance Criteria:**

Shared email structure:
- [ ] Extract a shared email header/footer builder used by all email functions
- [ ] Header includes tenant logo (left-aligned or centered) and tenant name
- [ ] Footer remains as-is (existing disclaimer text)
- [ ] All 12 email functions use the shared structure

Logo handling:
- [ ] Custom PNG logos embedded directly (CID attachment or base64 data URI)
- [ ] Custom SVG logos rasterized to PNG before embedding
- [ ] Mandala SVG generated and rasterized to PNG when no custom logo exists
- [ ] Logo sized appropriately for email context (e.g., 48px height, auto width)

Tenant context:
- [ ] Email functions receive `tenant_id` (or equivalent context) to fetch branding
- [ ] Tenant name displayed next to or below the logo
- [ ] Branding data cached per-send or passed in (no N+1 queries for batch operations)

Compatibility:
- [ ] Tested in major email clients (Gmail, Outlook, Apple Mail) for logo rendering
- [ ] Graceful fallback if images are blocked (alt text shows tenant name)
- [ ] Dark mode consideration: use light logo variant (most email backgrounds are white)

**Effort:** M
**Value:** Medium (Professional appearance, tenant identity in all communications)

---

## Onboarding Wizard for New Super Admins

> **Status: Needs grooming.** The shape is roughed out below but the details need more thought before implementation.

**User Story:**
As the first super admin of a new WeftID instance
I want a guided setup wizard that helps me get my identity layer running
So that I can reach a working configuration quickly without guessing what to do first

**Context:**

A brand new WeftID instance gives no guidance on where to start. The wizard meets the first super admin after onboarding and walks them through initial setup. It is dismissable forever (per-user flag) and only appears for super admins.

WeftID serves three primary deployment scenarios, and the wizard should adapt to whichever the admin is pursuing:

- **Identity Federation Hub:** Multiple upstream IdPs unified behind one identity layer
- **Standalone Identity Provider:** WeftID manages users directly (email/password, MFA)
- **SSO Gateway:** One IdP, but WeftID adds group-based access control and audit for downstream apps

**Rough Flow:**

1. **Welcome.** Friendly intro, explain what the wizard will help with.
2. **"How will your people sign in?"** Branching question: existing IdP, directly with WeftID, or both. Determines whether the next step is IdP setup or domain/user setup.
3. **Identity source setup.** If IdP: walk through connecting the first provider (Okta, Entra, Google, generic SAML). If direct: collect company email domain, create a privileged domain.
4. **"Let's organize your people."** Create the first group (suggest a name based on domain, e.g. "Acme Staff"). Link the domain to the group if applicable.
5. **"Connect an application."** Optional. Walk through registering the first SP, or skip for later.
6. **"Who should have access?"** Assign the group from step 4 to the SP from step 5. This is the "aha" moment.
7. **Quick security check.** MFA policy toggle, session timeout recommendation.
8. **Summary and next steps.** Show what was accomplished, link to key areas (audit logs, more apps, invite users).

**Open Design Questions:**

- Should step 3 (IdP setup) be a full inline walkthrough or just navigate to the existing config page with contextual guidance?
- For the "Both" path in step 2, run both flows sequentially or pick one as primary?
- Persistence model: wizard state as JSON on the tenant (checklist on dashboard) vs. a modal/sequential experience?
- Should "invite a co-admin" be a wizard step?
- Auto-assign-users-to-groups is now complete, so domain-to-group linking in step 4 is available.

**Acceptance Criteria:**

- [ ] Wizard appears for the first super admin on a new tenant (not for subsequent admins unless they haven't dismissed it)
- [ ] Dismissable forever via a per-user flag
- [ ] Adapts flow based on the admin's stated intent (federation, standalone, SSO gateway)
- [ ] Each step is skippable ("I'll do this later")
- [ ] Completing or dismissing the wizard never blocks access to the main UI
- [ ] Progress is persisted so the wizard can be resumed across sessions
- [ ] Summary step links to relevant admin pages for continued setup

**Effort:** XL
**Value:** High

---

## Standardize Product Name to "Weft ID"

**User Story:**
As a user or administrator
I want the product name to be consistently written as "Weft ID" everywhere I see it
So that the branding matches the official name and feels polished

**Context:**

The official product name on pageloom.com is "Weft ID" (two words, capital ID). The codebase currently drifts between several variants:

- "WeftId" (camelCase) in docs and most templates
- "WeftID" (capital ID, no space) in group type badges
- "Weft ID" (correct form) used inconsistently

Only user-facing prose needs updating. Code identifiers (variable names, enum values, localStorage keys, group type strings) should remain as-is since they are internal.

**Acceptance Criteria:**
- [ ] All documentation files in `docs/` use "Weft ID" in prose
- [ ] All template copy (page titles, labels, help text, badges) uses "Weft ID"
- [ ] `base.html` default title and branding placeholder use "Weft ID"
- [ ] Group type badges display "Weft ID" instead of "WeftID"
- [ ] Code identifiers (`weftid`, `WeftId`) are unchanged
- [ ] Documentation site is rebuilt (`make docs`)

**Effort:** S
**Value:** Medium

---

## Password Strength Policy

**User Story:**
As a super admin
I want strong, enforceable password requirements that go beyond simple length and character rules
So that every password-authenticated user in my tenant has a genuinely secure password

**Context:**

WeftId currently has no password strength validation beyond basic length. Passwords are set during
onboarding but never checked against known breaches or evaluated for real-world guessability.

NIST SP 800-63B recommends against character-composition rules (uppercase + number + symbol) because
they produce predictable patterns. Instead, modern password policy focuses on three pillars:

1. **Minimum length** (the single strongest factor in password entropy)
2. **Pattern detection** via zxcvbn, which catches dictionary words, keyboard patterns, repeated
   characters, l33t substitutions, and common password structures. A password like
   "password123password123" is long but scores 0.
3. **Breach checking** via the Have I Been Pwned Passwords API using k-anonymity: only the first
   5 hex characters of the SHA-1 hash are sent to the API, which returns ~500-800 matching
   suffixes. The full hash is compared locally. The server never sees the actual password hash.

**Password rotation is deliberately excluded.** NIST 800-63B recommends against periodic rotation
because it leads to weaker passwords (users append incrementing numbers, reuse patterns). Passwords
should only be changed on evidence of compromise (via admin-forced reset, a separate backlog item).

**Acceptance Criteria:**

Strength validation (applies to all password-setting flows: onboarding, change, reset):
- [ ] Minimum length configurable by super admin: 8, 10, 12, 14, 16, 18, or 20 characters. Default: 14
- [ ] Super admin accounts always require minimum 14 characters regardless of tenant setting
- [ ] zxcvbn minimum score: default 3 ("safely unguessable"), super admin can set to 4 ("very unguessable")
- [ ] HIBP k-anonymity breach check: reject passwords found in known breach databases
- [ ] If HIBP API is unreachable, fail open (allow the password, log a warning). Length and zxcvbn checks still apply.
- [ ] No password expiry. No rotation policy. No "password must differ from last N passwords." This is intentional and not configurable.

Client-side feedback:
- [ ] Real-time strength indicator as the user types (zxcvbn-ts or equivalent JS library)
- [ ] Clear messaging: show estimated crack time, flag specific weaknesses (e.g., "common word detected," "found in breach database")
- [ ] Encourage password manager use in help text (e.g., "We recommend using a password manager to generate and store a strong password")

Server-side enforcement:
- [ ] All client-side checks are repeated server-side (zxcvbn Python port + HIBP API call)
- [ ] Server is the authority. Client-side feedback is UX only.
- [ ] Validation errors return specific, actionable messages (not just "password too weak")

Admin configuration (security settings page):
- [ ] Minimum password length selector (dropdown: 8, 10, 12, 14, 16, 18, 20)
- [ ] Minimum zxcvbn score selector (3 or 4)
- [ ] Both settings persisted via migration, exposed via API
- [ ] Event logged when settings change (`password_policy_updated`)

Database:
- [ ] Migration adds password policy columns to tenant settings (minimum_password_length, minimum_zxcvbn_score)
- [ ] Sensible defaults (14, 3) so existing tenants get strong policy without action

**Effort:** M
**Value:** High

---

## Password Change and Admin-Forced Reset

**User Story:**
As a user who authenticates with a password
I want to change my password from my account page
So that I can update my credentials when needed

As an admin
I want to force a user to change their password on next login
So that I can respond to suspected credential compromise without rotating everyone's passwords

**Context:**

There is currently no way for users to change their password after initial setup during onboarding.
The only path is through admin intervention (which also doesn't exist yet).

The password change feature lives on a new "Password" tab on the account page, positioned after
the existing "Profile" tab. The account page already has four tabs (Profile, Email addresses,
Two-step verification, Background Jobs), so this adds a fifth.

Admin-forced password reset sets a flag on the user record. On next login, after successful
authentication, the user is redirected to a password change screen before they can proceed.
This is the only mechanism for forcing a password change. There is no periodic rotation.

**Acceptance Criteria:**

Password tab (account page):
- [ ] New "Password" tab on account page, positioned after "Profile"
- [ ] Only visible for users who authenticate with a password (not IdP-federated users)
- [ ] Requires current password to set a new password
- [ ] New password subject to the password strength policy (length, zxcvbn, HIBP)
- [ ] Client-side strength feedback (same component as onboarding)
- [ ] Success confirmation shown after password change
- [ ] Event logged: `password_changed`
- [ ] API endpoint for programmatic password change (`PUT /api/v1/account/password` or similar)

Admin-forced password reset:
- [ ] Admin action on user detail page: "Force password reset"
- [ ] Sets a flag on the user record (`password_reset_required` or similar)
- [ ] On next login, after successful authentication with current password, user is redirected to a password change screen
- [ ] User cannot navigate away until password is changed
- [ ] Flag is cleared after successful password change
- [ ] Permission model: admins can force reset on any user including super admins. Super admins can force reset on anyone.
- [ ] Event logged: `password_reset_forced` (actor = admin, target = user)
- [ ] Event logged: `password_reset_completed` when the user completes the forced change
- [ ] API endpoint for forcing reset (`POST /api/v1/users/{id}/force-password-reset` or similar)

Database:
- [ ] Migration adds `password_reset_required` boolean (default false) to users table
- [ ] Migration adds `password_changed_at` timestamp to users table (nullable, set on every password change)

**Effort:** M
**Value:** High

---

## Forgot Password (Self-Service Reset)

**User Story:**
As a user who has forgotten my password
I want to request a password reset link via email
So that I can regain access to my account without admin intervention

**Context:**

There is currently no self-service password recovery. A user who forgets their password has no
recourse other than contacting an admin. This is a basic identity platform capability.

The flow is standard: user enters their email on the login page, receives a time-limited reset
link, clicks it, and sets a new password (subject to the password strength policy). The critical
security concern is rate limiting. Password reset endpoints are prime targets for enumeration
attacks (discovering valid emails) and abuse (flooding a user's inbox).

**Acceptance Criteria:**

User flow:
- [ ] "Forgot password?" link on the login page
- [ ] User enters their email address
- [ ] If the email exists and belongs to a password-authenticated user, a reset email is sent
- [ ] If the email does not exist or belongs to an IdP-federated user, no email is sent but the same success message is shown (prevents enumeration)
- [ ] Reset email contains a single-use, time-limited token link
- [ ] Clicking the link opens a "set new password" page (subject to password strength policy)
- [ ] After successful reset, user is redirected to login with a confirmation message
- [ ] The reset token is invalidated after use or expiry (whichever comes first)

Security:
- [ ] Token expiry: 30 minutes (configurable by super admin if needed, but sensible default)
- [ ] Tokens are single-use (invalidated on first use)
- [ ] Token is cryptographically random, stored as a hash (not plaintext) in the database
- [ ] Rate limiting per email address: max 3 reset requests per hour per email
- [ ] Rate limiting per IP: max 10 reset requests per hour per IP
- [ ] Rate limiting is enforced server-side, not bypassable
- [ ] No information leakage: same response message whether email exists or not
- [ ] Reset link works only for the email it was issued for (token bound to email)
- [ ] All active sessions for the user are invalidated after a successful password reset (if they forgot their password, assume compromise)
- [ ] Event logged: `password_reset_requested` (with email, IP)
- [ ] Event logged: `password_reset_completed`

Database:
- [ ] Table or columns for reset tokens (user_id, token_hash, created_at, expires_at, used_at)
- [ ] Expired and used tokens cleaned up periodically (background job or on-query)

> **Note:** If the "Stateless Time-Windowed Token Generation" backlog item is implemented first,
> this item should use that infrastructure instead of database-stored tokens. The database
> acceptance criteria above would then be replaced by stateless token generation with
> `password_changed_at` as the state-based invalidation input.

**Effort:** M
**Value:** High

---

## Stateless Time-Windowed Token Generation

**User Story:**
As a platform operator
I want one-time codes and verification tokens to be derived deterministically from a secret
rather than stored in the database
So that token flows are simpler, require no storage or cleanup, and scale without database pressure

**Context:**

Several flows in WeftId generate one-time tokens and store them in the database: email
verification codes, MFA email codes, and (planned) forgot-password tokens. Each requires a
database table, insert-on-create, lookup-on-verify, and periodic cleanup of expired entries.

All of these can be replaced with deterministic, time-windowed token generation using the
same principle as TOTP (RFC 6238):

    code = HMAC(derived_secret, user_id + purpose + floor(time / step))

The verifier generates codes for the current time window and a few adjacent windows (e.g.,
current, -1, -2, +1 steps). If the submitted code matches any of them, it's valid. No
database lookup, no cleanup job, no table bloat.

The project already has HKDF key derivation in `app/utils/crypto.py` with purpose-scoped
keys (session, MFA, SAML, email). A new `"token"` purpose would derive the secret used for
all stateless token generation.

**Revocation without storage:** Where a token must become invalid after use (e.g., forgot-
password), include a piece of mutable user state in the derivation input. For password reset,
including `password_changed_at` means the derivation inputs change the moment the password
is reset, and the old code silently stops matching. The action itself invalidates the token.

**What stays in the database:** Nothing changes for TOTP (RFC 6238 with per-user secrets) or
session tokens (managed by the session store). This item targets only short-lived, single-
purpose codes that currently require their own storage.

**Acceptance Criteria:**

Core infrastructure:
- [ ] New derived key via HKDF with purpose `"token"` in `app/utils/crypto.py`
- [ ] Token generation function: `generate_code(user_id, purpose, step_seconds, state=None) -> str` that produces a deterministic code from the derived secret, user ID, purpose string, time window, and optional state input
- [ ] Token verification function: `verify_code(code, user_id, purpose, step_seconds, window=3, state=None) -> bool` that checks the submitted code against the current window and adjacent windows
- [ ] Purpose strings are explicit constants (e.g., `"email_verify"`, `"mfa_email"`, `"password_reset"`) to prevent cross-purpose token acceptance
- [ ] Step duration and window size are caller-specified (different flows have different timing needs)

Migration of existing flows:
- [ ] MFA email codes: migrate from database-stored codes to stateless generation
- [ ] Email verification tokens: migrate from database-stored tokens to stateless generation
- [ ] Forgot-password tokens (separate backlog item) should use this infrastructure from the start
- [ ] Document the pattern so future token needs default to stateless generation

State-based invalidation:
- [ ] Document which state field to include per purpose (e.g., `password_changed_at` for password reset, `email_verified_at` for email verification)
- [ ] When state is included, changing that state automatically invalidates outstanding tokens

**Effort:** M
**Value:** High (Infrastructure simplification, eliminates token storage and cleanup across multiple flows)

---

## Remove Legacy One-Time Token Storage

**User Story:**
As a developer
I want to remove the database tables and columns that previously stored one-time tokens
So that the schema is clean and there is no dead storage after migrating to stateless tokens

**Context:**

Once the "Stateless Time-Windowed Token Generation" item is complete and all token flows have
been migrated, the database tables/columns that stored email verification codes, MFA email
codes, and any other one-time tokens are no longer read or written. This item removes them.

This is a cleanup item with no user-facing impact. It depends on the stateless token item
being fully deployed and confirmed working.

**Acceptance Criteria:**

- [ ] Identify all tables/columns used for one-time token storage
- [ ] Verify no code paths read from or write to them (grep for table/column names)
- [ ] Migration drops the identified tables/columns
- [ ] Migration follows the multi-step safety pattern if needed (mark unused first, drop in a later migration)
- [ ] Associated cleanup jobs (if any) are removed from `app/jobs/`
- [ ] Tests updated to remove any references to the old token storage

**Effort:** S
**Value:** Low (Cleanup, depends on stateless token generation being complete)

---
