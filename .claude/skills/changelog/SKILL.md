---
name: changelog
description: Changelog Drafter - Generate changelog entries from git history for human review
---

# Changelog Drafter

Draft a changelog entry from git history, categorize changes, and write human-readable
descriptions for the next release.

## Quick Reference

- **Reads:** Git log, CHANGELOG.md, pyproject.toml, docs/VERSIONING.md
- **Writes:** CHANGELOG.md
- **Can commit:** No (user reviews and commits)

## Workflow

### 1. Determine the range

Find the latest version tag:

```bash
git tag --list 'v*' --sort=-version:refname | head -1
```

If no tags exist, use the initial commit. The range is `<tag>..HEAD`.

### 2. Read the current version

```bash
python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['tool']['poetry']['version'])"
```

Record the current version. Do NOT treat a match with the latest tag as a problem — this skill
proposes the next version, so an unbumped `pyproject.toml` is the expected state. Only stop if
`pyproject.toml` is already ahead of the latest tag with a version that has no commits since
that tag.

### 3. Collect commits

```bash
git log --oneline <tag>..HEAD
```

If there are no commits since the last tag, inform the user and stop.

### 4. Categorize and rewrite

Categorize each commit into Keep a Changelog sections:

- **Added** -- new features, new capabilities
- **Changed** -- changes in existing functionality
- **Fixed** -- bug fixes
- **Security** -- vulnerability fixes
- **Breaking** -- backwards-incompatible changes (listed under Changed with a "BREAKING:" prefix)
- **Removed** -- removed features
- **Deprecated** -- soon-to-be-removed features

**Omit empty categories.** Do not include section headers with no entries.

**Rewrite commit messages as user-facing descriptions.** Commit messages describe implementation
("fix RLS policy on group_lineage"). Changelog entries describe impact ("Fixed a bug where
group hierarchy queries could return stale results"). Write from the perspective of a
self-hoster or operator reading the changelog.

**Flag SAML/identity changes.** If any commits touch SAML assertions, attribute mappings,
entityID format, or SSO flows, flag them prominently. Per `docs/VERSIONING.md`, these changes
require a major version bump.

**Exclude from the changelog:**
- Commits that only modify CLAUDE.md, skill files, or other Claude Code configuration
- Commits that only modify .claude/BACKLOG.md, .claude/BACKLOG_ARCHIVE.md, .claude/ISSUES.md, or .claude/ISSUES_ARCHIVE.md
- Merge commits with no substantive changes

### 5. Propose the next version

Based on the categorized changes, propose the next semver version per `docs/VERSIONING.md`:

- **Major** — SAML assertion structure / entityID format / default attribute mapping changes,
  removed or changed API endpoints, required new env vars without defaults, SSO flow changes
  requiring SP/IdP reconfiguration, compose file structural changes.
- **Minor** — new features, additive API endpoints, non-breaking migrations, new optional
  SAML/OAuth features, new env vars with defaults, UI improvements.
- **Patch** — bug fixes and security patches only, no schema migrations, no API changes, no
  SAML/OAuth behavior changes.

State the proposed bump explicitly with a one-paragraph motivation citing the specific
commits/features that drive the level. Example:

> Proposed bump: **1.4.1 → 1.5.0 (minor)**. Adds passkey authentication (new feature, additive
> API, new schema tables) and a tenant auth strength policy. No SAML assertion/entityID/attribute
> changes, so a major bump is not required. Security fixes are rolled into the minor.

If the SAML/identity rule triggers, call it out in the motivation and bump major even when the
rest of the changes look minor.

### 6. Present the draft

Show the proposed version + motivation, followed by the complete `## [x.y.z] - YYYY-MM-DD`
section using today's date and the proposed version. Ask the user to (a) approve the version
bump and (b) approve the entry, or request edits to either.

### 7. Write to CHANGELOG.md

On approval, insert the new section into `CHANGELOG.md` immediately after the
`## [Unreleased]` header (and any content under it). Clear the `[Unreleased]` section
contents (move them into the new versioned section if applicable).

Remind the user to bump `pyproject.toml` to the same version before tagging. Do NOT edit
`pyproject.toml` automatically — the user owns the version bump.

Do NOT commit. Tell the user to review the file and commit when ready.

## Output Format

```markdown
## [1.1.0] - 2026-04-01

### Added

- Service provider single logout (SLO) support for SAML IdP connections
- Bulk user import via CSV upload

### Fixed

- Fixed a bug where group hierarchy queries could return stale results after relationship deletion

### Security

- Updated cryptography to 44.0.0 to address CVE-2026-XXXXX
```

## Start Here

Run git commands to determine the range and collect commits, then draft the entry.
