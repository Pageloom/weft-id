---
name: changelog
description: Changelog Drafter - Generate changelog entries from git history for human review
---

# Changelog Drafter

Draft a changelog entry from git history, categorize changes, and write human-readable
descriptions for the next release.

## Quick Reference

- **Reads:** Git log, CHANGELOG.md, pyproject.toml, VERSIONING.md
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

If this version matches the latest tag (minus the `v` prefix), warn the user that the version
in `pyproject.toml` hasn't been bumped yet and ask whether to proceed.

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
entityID format, or SSO flows, flag them prominently. Per `VERSIONING.md`, these changes
require a major version bump.

**Exclude from the changelog:**
- Commits that only modify CLAUDE.md, skill files, or other Claude Code configuration
- Commits that only modify BACKLOG.md, BACKLOG_ARCHIVE.md, ISSUES.md, or ISSUES_ARCHIVE.md
- Merge commits with no substantive changes

### 5. Present the draft

Show the complete `## [x.y.z] - YYYY-MM-DD` section to the user for review. Use today's
date. Ask the user to review and approve, or request edits.

### 6. Write to CHANGELOG.md

On approval, insert the new section into `CHANGELOG.md` immediately after the
`## [Unreleased]` header (and any content under it). Clear the `[Unreleased]` section
contents (move them into the new versioned section if applicable).

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
