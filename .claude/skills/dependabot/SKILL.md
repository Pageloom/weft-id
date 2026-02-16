---
name: dependabot
description: Dependabot Agent - Review, evaluate, and batch-merge dependabot PRs
---

# Dependabot Agent - Dependency Update Review

Review open dependabot PRs, evaluate risk, and batch-merge the safe ones.

## Quick Reference

- **Reads:** GitHub PRs, pyproject.toml, poetry.lock, changelogs
- **Writes:** Code (pyproject.toml, poetry.lock), PR
- **Can commit:** Yes

## Before You Start

Read `.claude/THOUGHT_ERRORS.md` to avoid past mistakes.

## Workflow

1. **List dependabot PRs** using `gh pr list --author "app/dependabot"`
   - Filter by date if the user specifies (e.g., `--search "created:YYYY-MM-DD"`)
   - Otherwise list all open dependabot PRs
2. **Evaluate each PR** against the risk criteria below
3. **Present findings** as a table with verdict and reasoning. Ask user to confirm.
4. **Apply selected updates** to pyproject.toml, regenerate the lock file, install
5. **Run all checks** (`./code-quality` and `./test`). Both must pass.
6. **Commit, push, and open a single consolidated PR**

## Risk Evaluation Criteria

For each dependabot PR, assess:

| Factor | Lower Risk | Higher Risk |
|--------|-----------|-------------|
| **Version jump** | Patch (x.x.1 -> x.x.2) | Minor/Major (x.1 -> x.2, 1.x -> 2.x) |
| **Security** | Has CVE fix | No security relevance |
| **Scope** | Dev dependency (ruff, pytest) | Runtime dependency (psycopg, fastapi) |
| **Changelog** | Bug fixes, docs | API changes, deprecations, new behavior |
| **Breaking changes** | None listed | Drops Python versions, changes defaults |

### Default verdicts

- **Patch releases** of any dependency: include (low risk)
- **Security fixes** at any version level: include (necessary)
- **Minor bumps** of dev-only tools (ruff, mypy, pytest-*): include (no runtime impact)
- **Minor bumps** of runtime deps: evaluate changelog carefully, include if no breaking changes affect us
- **Major version bumps**: skip by default, recommend separate evaluation

### Priority packages (extra scrutiny)

These are security-sensitive. Always include security patches, but be careful with feature releases:

- `cryptography`, `argon2-cffi`, `python3-saml`, `itsdangerous`, `pyotp`
- `fastapi`, `pydantic`, `jinja2`, `psycopg`

## Applying Updates

Do NOT cherry-pick dependabot commits (poetry.lock conflicts are inevitable when combining multiple updates). Instead:

1. Create a new branch from main: `deps/batch-update-YYYY-MM-DD`
2. Edit `pyproject.toml` directly with the version bumps
3. Regenerate lock file: `poetry lock`
4. Install: `poetry install`

## Before Committing

```bash
./code-quality --fix                    # Lint, format, type check, compliance
./test                                  # Tests
```

Both must pass.

## PR Format

The consolidated PR should:

- Title: list the updated packages (e.g., "Bump cryptography, fastapi, and ruff")
- Body: summarize each update with version range and why it was included
- Body: list skipped PRs with reasoning so they are not forgotten
- Do NOT use `closes #N` for dependabot PRs. They autoclose on their own when their branch conflicts with main.

## Commit Message Format

```
Bump [package1], [package2], and [package3]

Update [package] X.Y.Z -> X.Y.W ([reason]),
[package] X.Y.Z -> X.Y.W, and [package] X.Y.Z -> X.Y.W.
```

## What This Skill Does NOT Do

- Does not read ISSUES.md or BACKLOG.md (this is not backlog work)
- Does not close dependabot PRs via `gh` (they autoclose when their branch conflicts)
- Does not modify application code (only pyproject.toml and poetry.lock)

## Architectural Principles

Follow the same standards as `/dev` for any code that is touched:

- **Routers:** HTTP only, never import database modules
- **Services:** Business logic and authorization
- **Database:** SQL with tenant scoping
- All writes go through service layer
- Every service write must emit an event log
- All `str` fields in Pydantic input schemas must have `max_length`

## Start Here

List open dependabot PRs and present evaluation table.
