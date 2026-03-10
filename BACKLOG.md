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

## 1. Version Management Policy

**User Story:**
As a platform operator (and as the development team)
I want a documented versioning policy that defines what constitutes a patch, minor, and major release
So that self-hosters can assess upgrade risk and the team has clear rules for when to bump which number

**Context:**

WeftId has no version number today. Before the code goes public, we need to decide on a
starting version and document what each level of change means. Identity platforms carry
extra weight here: a "minor improvement" to SAML assertion format can silently break every
federated SP downstream.

**Decision points to resolve during implementation:**

- Starting version: `0.1.0` (signals early-but-usable, allows breaking changes before 1.0)
  vs `1.0.0` (signals production-ready). Recommendation: start at `1.0.0` since the platform
  is already running in production for the SaaS offering.
- Where to store the version: `pyproject.toml` is the canonical source. A `__version__` in
  `app/__init__.py` or `app/version.py` reads from it. The Docker image gets it as a label.

**Proposed definitions:**

| Level | What changes | Self-hoster impact |
|-------|-------------|-------------------|
| **Patch** (1.0.x) | Bug fixes, security patches. No schema migrations, no API changes, no SAML/OAuth behavior changes. | Drop-in safe. Pull and restart. |
| **Minor** (1.x.0) | New features, additive API endpoints, non-breaking schema migrations (new columns with defaults, new tables), new env vars with sensible defaults, UI improvements. | Pull, restart, auto-migration runs. Review changelog for new features. |
| **Major** (x.0.0) | Removed or changed API endpoints, required new env vars without defaults, SAML assertion format or attribute mapping behavior changes, SSO flow changes requiring SP/IdP reconfiguration, compose file structural changes (new required services, renamed volumes). | Read migration guide. May require SP/IdP reconfiguration. |

**Identity-specific rules:**
- Any change to SAML assertion structure, entityID format, or default attribute mappings is a **major** bump (these break federation trust silently).
- New optional SAML/OAuth features (e.g., a new optional attribute) are **minor**.
- Changes to the consent screen UI that don't alter what data is shared are **minor**.

**Acceptance Criteria:**

- [ ] Starting version chosen and set in `pyproject.toml`
- [ ] Version accessible at runtime (e.g., `app/version.py` reads from pyproject.toml or is set at build time)
- [ ] `VERSIONING.md` in repo root documents the policy (patch/minor/major definitions, identity-specific rules)
- [ ] Git tag convention documented: `v1.0.0` format, tags on main only
- [ ] Docker image labeled with version (`org.opencontainers.image.version`)

**Effort:** S
**Value:** High (Foundational for all release infrastructure)

---

## 2. GHCR Publish Workflow

**User Story:**
As the development team
I want a GitHub Actions workflow that builds and publishes Docker images to GHCR when a version tag is pushed
So that self-hosters can pull versioned images without needing the source code

**Context:**

Images are published to `ghcr.io/pageloom/weft-id`. The workflow triggers on tags matching
`v*.*.*`. It produces multi-tag images so self-hosters can choose their risk tolerance.

The existing Dockerfile builds everything needed (dependencies, Tailwind CSS, app code).
The production image should NOT include dev dependencies, dev scripts, or test files.

**Acceptance Criteria:**

- [ ] GitHub Actions workflow triggers on push of tags matching `v*.*.*`
- [ ] Builds the Docker image using the existing `app/Dockerfile` (or a production variant if needed)
- [ ] Pushes to `ghcr.io/pageloom/weft-id` with these tags:
  - Exact version: `1.2.3`
  - Minor: `1.2`
  - Major: `1`
  - `latest` (points to newest stable release)
- [ ] Image includes OCI labels: version, source URL, description, creation date
- [ ] Image does NOT include dev scripts, test files, or dev dependencies
- [ ] Workflow fails if the tag doesn't match the version in `pyproject.toml` (prevents mismatched tags)
- [ ] README or docs updated with the GHCR image URL and available tags

**Effort:** M
**Value:** High (Foundation for self-hosting)

---

## 3. Changelog & Release Gate

**User Story:**
As the development team
I want a helper that drafts changelog entries from git history, and a release workflow that
refuses to publish if the changelog hasn't been updated
So that every release ships with a human-reviewed changelog and none can slip through without one

**Context:**

Two pieces work together:

1. **Draft helper** (local script or Claude Code skill): scans commits on main since the
   last tag, categorizes them (features, fixes, breaking, security), and produces a draft
   changelog entry. The developer reviews, edits, and commits the updated `CHANGELOG.md`
   before tagging.

2. **Release gate** (GitHub Action): the GHCR publish workflow (item 2) checks that
   `CHANGELOG.md` contains a section header matching the tag being released (e.g.,
   `## [1.2.0]`). If the section is missing, the workflow fails before building or pushing
   anything. This makes it impossible to release without an up-to-date changelog.

The changelog is human-curated, not auto-generated. The helper reduces toil but a person
always reviews the final text. This matters because commit messages describe implementation
("fix RLS policy on group_lineage") while changelog entries describe impact ("Fixed a bug
where group hierarchy queries could return stale results").

**Acceptance Criteria:**

Draft helper:
- [ ] Script or skill that collects commits between the last tag and HEAD
- [ ] Categorizes commits into sections: Added, Changed, Fixed, Security, Breaking
- [ ] Produces a draft entry in Keep a Changelog format, ready for human editing
- [ ] Output can be appended to `CHANGELOG.md` or printed to stdout for review

Changelog format:
- [ ] `CHANGELOG.md` in repo root, following [Keep a Changelog](https://keepachangelog.com/) format
- [ ] Each release has a section header: `## [1.2.0] - 2026-03-15`
- [ ] Unreleased changes can accumulate under `## [Unreleased]`

Release gate:
- [ ] GHCR publish workflow (item 2) checks for a `## [x.y.z]` section matching the tag
- [ ] Workflow fails with a clear error message if the section is missing
- [ ] GitHub Release created automatically with the matching changelog section as release notes

**Effort:** M
**Value:** High (Transparency for self-hosters, enforced quality gate)

---

## 4. Production Docker Compose for Self-Hosting

**User Story:**
As a self-hoster
I want a standalone Docker Compose file that runs WeftId with good security defaults and automatic HTTPS
So that I can deploy WeftId on my own server without needing the source code or manual certificate management

**Context:**

The current onprem setup (`docker-compose.onprem.yml`) has significant gaps: it bind-mounts
source code, hardcodes database passwords in the compose file, requires manual certbot setup,
has no health checks, and no automatic secret generation.

The new production compose file should be a self-contained artifact that a self-hoster
downloads alongside a `.env.example`. It references the GHCR image (via `WEFT_VERSION` env
var) and uses Caddy for automatic HTTPS (Let's Encrypt via HTTP-01, zero config). Migrations
run automatically on startup.

**Acceptance Criteria:**

Compose file (`docker-compose.production.yml`):
- [ ] References GHCR image: `ghcr.io/pageloom/weft-id:${WEFT_VERSION:-latest}`
- [ ] Services: caddy (reverse proxy), app, worker, migrate, memcached, db
- [ ] Caddy handles HTTPS automatically (HTTP-01 challenge, auto-renewal, no setup scripts)
- [ ] Migrate service runs as a dependency before app starts (`condition: service_completed_successfully`)
- [ ] No source code bind mounts (app runs from the baked image)
- [ ] Storage volume for persistent data (uploads, etc.)
- [ ] DB password sourced from `.env` (not hardcoded in compose)
- [ ] Health checks on db, memcached, and app
- [ ] `restart: unless-stopped` on all long-running services
- [ ] Ports: only 80 and 443 exposed (everything else internal)

Environment (`.env.production.example`):
- [ ] `WEFT_VERSION` for image pinning (default: `latest`)
- [ ] `BASE_DOMAIN` (required, no default)
- [ ] `SECRET_KEY` with a placeholder and generation instructions
- [ ] `POSTGRES_PASSWORD` with a placeholder and generation instructions
- [ ] SMTP configuration section with clear comments
- [ ] `IS_DEV=False`, `BYPASS_OTP=false`, `ENABLE_OPENAPI_DOCS=false` as defaults
- [ ] No dev-only variables (`DEV_SUBDOMAIN`, `DEV_PASSWORD`)

Security defaults:
- [ ] No ports exposed to host except 80/443
- [ ] Database not accessible from host
- [ ] Memcached not accessible from host
- [ ] All secrets must be explicitly set (no insecure defaults that "work")

Caddy:
- [ ] `Caddyfile` included, parameterized by `BASE_DOMAIN` env var
- [ ] Handles `{$BASE_DOMAIN}` and `*.{$BASE_DOMAIN}` with automatic TLS
- [ ] Proxies to app service on port 8000
- [ ] Sets `X-Forwarded-Proto`, `X-Real-IP`, `X-Forwarded-For` headers

**Effort:** M
**Value:** High (Core self-hosting deliverable)

---

## 5. Self-Hosting Install Script

**User Story:**
As a self-hoster
I want a single command that downloads everything I need and walks me through initial configuration
So that I can go from zero to running WeftId in minutes

**Context:**

Optional convenience script. Downloads `docker-compose.production.yml`, `.env.production.example`,
and `Caddyfile` from the latest GitHub release. Generates `SECRET_KEY` and `POSTGRES_PASSWORD`
automatically. Prompts for domain and SMTP settings. Writes `.env` ready to go.

This is a nice-to-have on top of the compose file (which should also work with manual setup).

**Acceptance Criteria:**

- [ ] Single command to download and run: `curl -sSL https://raw.githubusercontent.com/pageloom/weft-id/main/install.sh | bash` (or similar)
- [ ] Downloads `docker-compose.production.yml`, `.env.production.example`, and `Caddyfile` from the latest GitHub release
- [ ] Auto-generates `SECRET_KEY` (44-char base64 via `openssl rand -base64 32` or Python equivalent)
- [ ] Auto-generates `POSTGRES_PASSWORD` (same method)
- [ ] Prompts for `BASE_DOMAIN` (required)
- [ ] Prompts for SMTP settings (optional, can be configured later)
- [ ] Writes `.env` with all values populated
- [ ] Prints next steps: `docker compose -f docker-compose.production.yml up -d`
- [ ] Idempotent: re-running detects existing `.env` and asks before overwriting
- [ ] Works on Linux (primary target) and macOS
- [ ] No dependencies beyond `curl`, `openssl`, and a POSIX shell

**Effort:** S
**Value:** Medium (Convenience, reduces friction for first-time setup)

---

## 6. Tenant Provisioning CLI

**User Story:**
As a platform operator with shell access
I want a CLI command that creates a new tenant and its first super admin
So that I can provision new tenants on a running instance without direct database manipulation

**Context:**

After the install script (item 5) gets the infrastructure running, the operator needs a way to
create the first tenant and super admin. Today this requires direct SQL or the dev seed script
(which is gated behind `IS_DEV=true`). This item provides a production-safe CLI command that
creates the tenant, creates the super admin user record, and sends the standard invitation
email so the super admin can verify their email, set a password, and complete MFA setup.

The command reuses existing infrastructure: `provision_tenant()` for tenant creation,
`users_service.create_user()` for the user, and `emails_service.add_email()` for the email
record. The super admin goes through the standard non-privileged-domain onboarding path
(verify email, set password, MFA), which also validates that email delivery is working
before the admin gains access.

The invitation email is distinct from the standard user invitation. A normal user gets
"You've been invited to join {org_name}." The provisioning super admin is setting up the
organization, not just joining it. The email should convey that they are the founding
administrator, that they will configure the identity layer for their organization, and
that the first step is to verify their email and set a password.

If the tenant already exists, the command adds a new super admin to it (allows provisioning
additional super admins or recovering from a failed first attempt).

**Acceptance Criteria:**

CLI interface:
- [ ] Management command runnable via `python -m app.cli.provision_tenant` (or similar)
- [ ] Required arguments: `--subdomain`, `--tenant-name`, `--email`, `--first-name`, `--last-name`
- [ ] All arguments validated before any database writes (subdomain format, email format, name length)
- [ ] Clear error messages for validation failures

Tenant creation:
- [ ] Creates tenant via existing `provision_tenant()` if subdomain does not exist
- [ ] If tenant with subdomain already exists, uses the existing tenant (logs that it was found)
- [ ] Prints tenant ID and subdomain on success

Super admin creation:
- [ ] Creates user with `role=super_admin`, no password
- [ ] Adds email as unverified (standard non-privileged flow)
- [ ] If a user with that email already exists in the tenant, aborts with a clear error
- [ ] Event logged: `user_created` with metadata indicating CLI provisioning

Invitation email:
- [ ] New email template distinct from the standard user invitation
- [ ] Subject conveys ownership, not just membership (e.g., "Set up your organization on WeftId")
- [ ] Body communicates that the recipient is the founding super admin, responsible for configuring the identity layer
- [ ] Includes the same verification link mechanism as the standard flow (verify email, then set password)
- [ ] If email delivery fails, prints error but does not roll back user creation (operator can retry or check SMTP config)
- [ ] Prints confirmation that invitation was sent, with the super admin's email

Safety:
- [ ] Works in production (no `IS_DEV` gate)
- [ ] Does not expose passwords, tokens, or activation links in CLI output
- [ ] Idempotent on tenant (safe to re-run with same subdomain)
- [ ] Not idempotent on user (duplicate email in same tenant is an error, not a silent skip)

**Effort:** S
**Value:** High (Required for self-hosting setup, blocks first-time use of any new instance)

---

## 7. Self-Hosting Upgrade & Operations Documentation

**User Story:**
As a self-hoster
I want clear documentation on how to upgrade, back up, and operate my WeftId instance
So that I can maintain my deployment confidently over time

**Context:**

Upgrade path is simple (change version in .env, pull, up) but needs to be documented along
with rollback considerations, backup strategy, and what to check in release notes.

**Acceptance Criteria:**

- [ ] `SELF-HOSTING.md` (or a docs section) covering:
  - Prerequisites (Docker, Docker Compose, a domain with DNS)
  - Quick start (referencing install script or manual setup)
  - Upgrade procedure: edit `WEFT_VERSION` in `.env`, `docker compose pull`, `docker compose up -d`
  - What happens on upgrade: migrate service runs automatically, new app starts after migration succeeds
  - Rollback considerations: forward-only migrations mean rolling back the image version only works if the new schema is backward-compatible with the old app code (true within a minor version, not guaranteed across major versions)
  - Backup strategy: database dump (`pg_dump`), storage volume, `.env` file
  - Monitoring: health check endpoints, log locations
  - SMTP configuration guide (including Resend/SendGrid alternatives for cloud providers that block port 25/587)
- [ ] Linked from the main README
- [ ] Version-specific migration guides for major version bumps (created as needed, not upfront)

**Effort:** M
**Value:** High (Trust and confidence for self-hosters)

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


## Groups: Customizable Acronym

**User Story:**
As an admin
I want to set a custom acronym (up to 4 characters) for a group
So that the group avatar displays a meaningful short label instead of the auto-generated initials

**Context:**

Group avatars currently show an auto-generated acronym derived from the group name (max 3
characters, first letter of each word). Some group names produce unhelpful or ambiguous initials.
A custom acronym lets the admin override this with something more recognizable (e.g., "HR",
"ENGR", "OPS", "IT").

The custom acronym appears wherever the auto-generated acronym would: group list, group detail,
group graph nodes, and any SP or dashboard views that show group avatars. If not set, the
existing auto-generation logic continues to apply.

**Acceptance Criteria:**

Database:
- [ ] Add `acronym` column to `groups` table (nullable, max 4 Unicode characters)
- [ ] Migration adds the column with a `CHECK` constraint on character count (`char_length <= 4`)
- [ ] Column included in group query results

Service and API:
- [ ] `GroupUpdate` schema accepts optional `acronym` field (max 4 Unicode chars, stripped)
- [ ] Setting acronym to empty string or null clears the override (reverts to auto-generated)
- [ ] Group create and update services handle the field
- [ ] API endpoints (`POST /api/v1/groups`, `PUT /api/v1/groups/{id}`) accept the field
- [ ] Event log metadata includes acronym when set or cleared
- [ ] IdP groups cannot have custom acronyms (read-only, same as name/description)

Frontend:
- [ ] Group Detail "Details" tab shows an acronym input field (max 4 chars) below the name field
- [ ] Field shows placeholder text indicating it is optional (e.g., "Auto-generated if blank")
- [ ] `generateGroupAcronym()` uses the custom acronym when `data-acronym-override` (or similar) is provided
- [ ] Acronym avatar font size adjusts for 4-character acronyms (smaller than 3-character)
- [ ] Group list, group graph, and any other avatar displays respect the custom acronym

Tests:
- [ ] Service tests for setting, updating, and clearing the acronym
- [ ] Validation tests for length and character constraints
- [ ] API integration tests for create and update with acronym
- [ ] Verify auto-generated acronym is used when custom is null/empty

**Effort:** S
**Value:** Medium (Visual clarity, admin control over group identity)

---

## Service Provider Logo / Avatar

**User Story:**
As an admin
I want to upload a logo for each service provider, with a generated acronym avatar as fallback
So that SPs are visually identifiable in lists, detail pages, and the user dashboard

**Context:**

Service providers currently have no visual identity. Group logos already support PNG and SVG
uploads with an acronym fallback. This item brings the same pattern to service providers,
reusing the existing validation and serving infrastructure.

Upload happens from the SP detail page. The acronym fallback uses the same generation logic
as groups (works with any UUID + name). Logos appear in the SP list, SP detail header,
dashboard "My Apps" cards, and the SSO consent screen.

**Acceptance Criteria:**

Database:
- [ ] New `sp_logos` table (parallel to `group_logos`): `sp_id`, `logo_data`, `content_type`,
      `created_at`, `updated_at`, tenant-scoped with RLS
- [ ] Migration adds the table with appropriate constraints
- [ ] Add `has_logo` and `logo_updated_at` fields to SP response schemas

Service:
- [ ] Reuse validation from `app/services/branding.py` (`_validate_png`, `_validate_svg_content`)
- [ ] Same constraints as group logos: PNG (square, >=48x48, <=256KB) or SVG
- [ ] Upload and delete service functions with event logging

Serving and API:
- [ ] `/branding/sp-logo/{sp_id}` endpoint (parallel to `/branding/group-logo/{group_id}`)
- [ ] Upload endpoint under SP admin routes
- [ ] Delete endpoint under SP admin routes
- [ ] API endpoints for upload and delete under `/api/v1/`

Templates:
- [ ] SP list (`saml_idp_sp_list.html`): show logo or acronym avatar
- [ ] SP detail header (`saml_idp_sp_tab_details.html`): show logo with upload/remove controls
- [ ] Dashboard "My Apps" cards (`dashboard.html`): show logo or acronym avatar
- [ ] SSO consent screen (`saml_idp_sso_consent.html`): show logo or acronym avatar

Frontend:
- [ ] Acronym generation reuses `generateGroupAcronym()` from `static/js/group-avatar.js`
      (works with any UUID + name)

Tests:
- [ ] Service layer tests for upload validation (PNG constraints, SVG sanitization)
- [ ] Service layer tests for upload and delete with event logging
- [ ] API integration tests for upload, serve, and delete endpoints
- [ ] Template rendering tests verify logo/acronym fallback behavior

**Effort:** M
**Value:** Medium

---

## Group Graph: Extended Selection Highlighting with Depth-Aware Edge Styles

**User Story:**
As an admin using the group graph view
I want the selected node's full ancestry and descendancy to be visually represented,
with solid edges for immediate neighbours and dashed edges for more distant relatives
So that I can understand the complete hierarchical context of a group at a glance

**Context:**

Currently, selecting a node highlights only its immediate children (solid arrows pointing in)
and immediate parents (orange arrows). Grandchildren, grandparents, and more remote relatives
are invisible in the selection state.

The new rule is: **dashed line = more than one step removed.** The direction of arrows and
colour conventions remain unchanged; only the reach and stroke style change.

**Acceptance Criteria:**

Descendant side (children, grandchildren, ...):
- [ ] When a node is selected, solid arrows are drawn from all **immediate children** to the
      selected node (existing behaviour, retained)
- [ ] Dashed arrows are drawn from all **grandchildren and more remote descendants** to the
      selected node
- [ ] Arrow direction is the same for all descendants (child -> selected)

Ancestor side (parents, grandparents, ...):
- [ ] Immediate parents continue to be highlighted with **solid orange arrows** pointing from
      the selected node to each parent (existing behaviour, retained)
- [ ] **Grandparents and more remote ancestors** are connected with **dashed arrows** (same
      direction: selected -> ancestor, same orange colour or a subdued variant that is clearly
      distinguishable from immediate parents)

General:
- [ ] Depth 1 neighbours (immediate parents and children) always use solid lines
- [ ] Depth 2+ neighbours (any relative more than one step away) always use dashed lines
- [ ] Unrelated nodes remain visually neutral (no highlight, no extra edges)
- [ ] The existing Cytoscape layout and node positions are unaffected by the style change
- [ ] De-selection resets all edges to their default appearance

**Effort:** S
**Value:** Medium

---

## Group Graph: Toolbar, New Group Modal, and Label Overlap

**User Story:**
As an admin using the group graph view
I want a cleaner toolbar, the ability to create groups directly from the graph, and non-overlapping edge labels
So that the graph feels polished, I can build the group hierarchy without leaving the canvas, and off-screen labels are readable

**Acceptance Criteria:**

Toolbar (icon-only buttons):
- [ ] "Add relationship", "Cut relationship", and "Edit layout" toolbar buttons show only an icon (no text label)
- [ ] Each button has a `title` tooltip that describes its function (visible on hover)
- [ ] Visual appearance and active/inactive states are preserved

New Group tool:
- [ ] A "New group" button is added to the graph toolbar (icon + tooltip, consistent with other toolbar items)
- [ ] Clicking it opens a modal with a "Name" field (required) and a "Description" field (optional), plus Cancel and Create buttons
- [ ] Submitting the modal creates the group via the existing group creation service and adds it to the graph
- [ ] The new node appears in the graph in a selected/highlighted state so the admin can immediately connect it
- [ ] Cancel closes the modal without creating anything
- [ ] Validation: name is required; shows inline error if empty on submit
- [ ] Creation failure (e.g. duplicate name) shows an error in the modal without closing it

Edge label de-overlap:
- [ ] When multiple off-screen edge labels (showing a connected group's name) would be rendered at overlapping or near-overlapping positions at the viewport boundary, they are spread out so no two labels overlap
- [ ] De-overlap logic is applied only to the off-screen labels (labels for visible nodes are unaffected)
- [ ] Labels remain close to the edge line's viewport intersection point where possible

**Effort:** M
**Value:** Medium

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

## SAML SP: Encrypted Assertion Support

**User Story:**
As a super admin
I want WeftId to support receiving encrypted SAML assertions from identity providers
So that assertion contents (PII, group memberships, entitlements) are protected end-to-end, not just by transport-level encryption

**Context:**

When WeftId acts as an SP, SAML responses travel through the user's browser via the POST
binding. Even over HTTPS, the assertion content is visible to the browser (and any extensions
or proxies). Encrypted assertions provide defense-in-depth: the IdP encrypts the assertion
payload with the SP's public encryption key, and only the SP can decrypt it with its private
key.

Currently, WeftId only publishes a signing certificate in its SP metadata
(`<md:KeyDescriptor use="signing">`). It does not publish an encryption certificate or
implement assertion decryption. Many IdPs (Entra ID, Okta, Google Workspace) support
encrypting assertions when the SP metadata advertises an encryption key.

This is optional per the SAML spec. Most SPs don't support it. But higher-security
environments and compliance frameworks may require it.

**Acceptance Criteria:**

Encryption certificate management:
- [ ] Generate a separate encryption certificate/key pair per IdP connection (same pattern as signing certificates)
- [ ] Store encryption private key securely (HKDF-derived or stored alongside signing keys)
- [ ] Key rotation support: new encryption key can be generated while the old one remains valid during a grace period

SP metadata:
- [ ] Publish an encryption `KeyDescriptor` (`use="encryption"`) in the per-IdP SP metadata XML
- [ ] During key rotation, publish both current and previous encryption certificates
- [ ] Signing `KeyDescriptor` remains unchanged

Assertion decryption:
- [ ] Detect encrypted assertions in SAML responses (`<EncryptedAssertion>` element)
- [ ] Decrypt using the SP's encryption private key (via xmlsec1 or lxml/xmlsec bindings)
- [ ] Support AES-128-CBC and AES-256-CBC content encryption (most common algorithms)
- [ ] Support RSA-OAEP and RSA-v1.5 key transport algorithms
- [ ] After decryption, process the assertion through the existing validation pipeline (signature verification, attribute extraction)
- [ ] Clear error messages when decryption fails (wrong key, unsupported algorithm, malformed ciphertext)

Configuration:
- [ ] Per-IdP connection toggle: "Accept encrypted assertions" (default: on for new IdP connections)
- [ ] When enabled, the encryption certificate is generated and included in metadata
- [ ] When disabled, no encryption KeyDescriptor in metadata, encrypted assertions are rejected with a clear error
- [ ] If the IdP does not encrypt assertions, plain assertions are accepted normally regardless of this setting (the encryption cert in metadata is advisory, not mandatory)

Event logging:
- [ ] Log encryption certificate generation and rotation events
- [ ] Log when encrypted assertion is successfully decrypted (metadata, not assertion content)

**Effort:** L
**Value:** Medium (Defense-in-depth security enhancement for higher-security deployments)

---

## SAML IdP: Encrypt Assertions for Downstream SPs

**User Story:**
As a super admin
I want WeftId to encrypt SAML assertions for downstream service providers that advertise an encryption certificate
So that assertion contents are protected end-to-end when WeftId acts as the identity provider

**Context:**

When WeftId acts as an IdP, it builds and signs SAML assertions for downstream SPs. These
assertions travel through the user's browser via the POST binding. If the SP advertises an
encryption certificate in its metadata (`<md:KeyDescriptor use="encryption">`), the IdP
should encrypt the assertion with that public key so only the SP can read it.

Currently, WeftId's SP metadata parser (`parse_sp_metadata_xml()`) grabs the first
`KeyDescriptor` it finds without distinguishing `use="signing"` from `use="encryption"`.
The assertion builder (`build_saml_response()`) only signs, never encrypts. Even if an SP
advertises an encryption certificate, WeftId ignores it.

This is the IdP-side complement to the "SAML SP: Encrypted Assertion Support" backlog item
(which covers the SP side, where WeftId receives encrypted assertions). They share some
infrastructure (xmlsec encryption primitives) but the data flow is reversed and they can be
implemented independently.

**Acceptance Criteria:**

SP metadata parsing:
- [ ] `parse_sp_metadata_xml()` distinguishes `use="signing"` and `use="encryption"` KeyDescriptors
- [ ] When `use` is omitted, the certificate is treated as valid for both purposes (per SAML spec)
- [ ] Encryption certificate stored separately from signing certificate in the SP record
- [ ] SP import and update flows handle the encryption certificate

Database:
- [ ] Store SP encryption certificate (new column or table alongside existing SP data)
- [ ] Migration adds the field with appropriate constraints

Assertion encryption:
- [ ] When the SP has an encryption certificate, wrap the signed assertion in an `<EncryptedAssertion>` element
- [ ] Use the SP's encryption public key for key transport (RSA-OAEP preferred, RSA-v1.5 as fallback)
- [ ] Use AES-256-CBC or AES-128-CBC for content encryption
- [ ] The assertion is signed first, then encrypted (sign-then-encrypt, per SAML best practice)
- [ ] When the SP has no encryption certificate, send plain signed assertions as today

Configuration:
- [ ] Per-SP toggle: "Encrypt assertions" (default: auto, meaning encrypt if the SP provides an encryption certificate)
- [ ] Override option to force plain assertions even if the SP advertises an encryption cert (for debugging or compatibility)
- [ ] Setting visible on the SP detail/configuration page

Event logging:
- [ ] Log whether assertion was encrypted in SSO event metadata
- [ ] Log encryption certificate changes when SP metadata is re-imported

Tests:
- [ ] Metadata parsing correctly extracts separate signing and encryption certificates
- [ ] Metadata parsing handles KeyDescriptors with no `use` attribute (dual-purpose)
- [ ] Assertion encryption produces valid `<EncryptedAssertion>` XML
- [ ] Plain assertions still work when SP has no encryption certificate
- [ ] Per-SP toggle overrides auto-encryption behavior

E2E tests (once both SP and IdP encryption items are complete):
- [ ] End-to-end test where WeftId encrypts assertions as IdP and decrypts them as SP (both sides of the equation in the same test environment)
- [ ] E2E test verifying SSO still works when encryption is disabled on either side
- [ ] E2E test verifying SSO works when the SP has no encryption certificate

**Effort:** L
**Value:** Medium (Completes end-to-end assertion encryption support across both IdP and SP roles)

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
