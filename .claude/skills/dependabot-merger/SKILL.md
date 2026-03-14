---
name: dependabot-merger
description: Dependabot Agent - Review, evaluate, and batch-merge dependabot PRs
---

# Dependabot Merger

Review open dependabot PRs, classify each for value and risk, consolidate the worthwhile
ones onto a single branch via iterative cherry-pick, open a PR for review, and close the
ones we're deliberately skipping.

## Prerequisites

- `gh` must be authenticated (`gh auth status`)
- Working tree must be clean (`git status`)

## Quick Reference

- **Reads:** GitHub PRs, pyproject.toml, poetry.lock, changelogs
- **Writes:** Git branch, pyproject.toml, poetry.lock, GitHub PR, closed PRs
- **Can commit:** Yes

## Before You Start

Read `.claude/THOUGHT_ERRORS.md` to avoid past mistakes.

---

## Workflow

### Phase 1: Evaluate

1. List open dependabot PRs:
   ```bash
   gh pr list --author "app/dependabot" --state open --json number,title,headRefName,labels
   ```
2. For each PR, classify as **Include**, **Skip**, or **Close** using the criteria below.
3. Present a summary table and ask the user to confirm before touching anything.

### Phase 2: Build the consolidation branch

Work through the **Include** PRs in order (patch releases before minor bumps, CVE fixes
first within each tier).

For each PR:

1. On the first PR, create the consolidation branch:
   ```bash
   git checkout main && git pull
   git checkout -b deps/batch-YYYY-MM-DD
   ```
2. Fetch the PR's branch and cherry-pick its commits:
   ```bash
   gh pr checkout <number> --detach       # puts HEAD at the PR tip
   git log --oneline main..HEAD           # note the commits to cherry-pick
   git checkout deps/batch-YYYY-MM-DD
   git cherry-pick <sha> [<sha> ...]
   ```
3. **`poetry.lock` will conflict on every cherry-pick after the first** — each dependabot
   commit fully regenerates `poetry.lock` from `main`, so it always conflicts once the
   consolidation branch has any prior bump. Treat the manual-regenerate path as the norm:
   ```bash
   git cherry-pick --abort
   # Get the pyproject.toml version change from the PR:
   gh pr diff <number> | grep "^[+-]" | grep "<package>"
   # Apply the version bump manually to pyproject.toml, then:
   poetry lock && poetry install
   git add pyproject.toml poetry.lock
   git commit -m "<original dependabot commit message>"
   ```
   Note: `gh pr diff <number> -- <file>` does NOT work (accepts at most 1 arg). Use the
   pipe-and-grep form above to extract pyproject.toml changes from the diff.
4. Verify the package updated correctly:
   ```bash
   poetry show <package>
   ```
5. Continue to the next PR.

### Phase 3: Quality check

```bash
make check         # Must pass
make test          # Must pass
```

If either fails: investigate root cause. If the failure is caused by a breaking change
in one of the included packages, either fix the application code or downgrade that package
to Skip and remove it from the branch.

### Phase 4: Open PR

Push the branch and open a PR:

```bash
git push -u origin deps/batch-YYYY-MM-DD
gh pr create \
  --title "Bump <pkg1>, <pkg2>, ..." \
  --body "$(cat <<'EOF'
<body — see template below>
EOF
)"
gh pr edit --add-label "run-e2e"
```

The `run-e2e` label triggers the E2E test suite in CI. Do not merge; wait for the user to
review CI results and merge with rebase-and-merge.

### Phase 5: Close rejects

For each **Close** PR, leave a brief comment and close it:

```bash
gh pr comment <number> --body "Closing: <one-line reason>. Happy to revisit if a CVE or breaking change surfaces."
gh pr close <number>
```

Leave **Skip** PRs open. Do NOT close PRs that dependabot will auto-close (those are PRs
for packages we've already merged a newer version of — dependabot detects the conflict and
closes them itself).

---

## Evaluation Criteria

### Value

A PR has value if it:
- Fixes a CVE or closes a known security advisory (**always include**)
- Bumps a dependency that `pip-audit` / `scripts/deps_check.py` has flagged
- Is a patch release (low-risk freshness)
- Is a minor bump of a dev-only tool (no runtime impact)

Version freshness alone is **not** sufficient to include a minor or major runtime bump.

### Default Verdicts

| Version jump | Scope | Default verdict |
|---|---|---|
| Patch | Any | **Include** |
| Minor | Dev-only (ruff, mypy, pytest-\*) | **Include** |
| Minor | Runtime | Evaluate changelog; include if no breaking changes affect us |
| Major | Any | **Skip** (recommend separate targeted evaluation) |
| Any level | CVE fix | **Include** |

### Packages Requiring Extra Scrutiny

Always include security patches. Evaluate feature releases carefully before including:

- `cryptography`, `argon2-cffi`, `python3-saml`, `itsdangerous`, `pyotp`
- `fastapi`, `pydantic`, `jinja2`, `psycopg`

### When to Close (vs Skip)

**Close** when all of the following are true:
- No CVE, no security advisory
- The changelog is docs/CI/style-only — no functional change
- We have recently merged a newer version anyway

**Skip** (leave open) when:
- It's a major version bump worth revisiting later
- The changelog has meaningful changes that need deeper review
- You're unsure

When in doubt, skip rather than close.

---

## PR Description Template

```
Batch dependency update YYYY-MM-DD.

## Included

| Package | From | To | Reason |
|---|---|---|---|
| cryptography | 43.0.0 | 43.0.3 | CVE-2024-XXXX |
| ruff | 0.8.0 | 0.9.1 | Minor dev-tool bump, no runtime impact |

## Excluded

| Package | From | To | Action | Reason |
|---|---|---|---|---|
| fastapi | 0.115.0 | 0.116.0 | Skipped | Minor bump, changelog has routing behavior changes — needs review |
| black | 24.0.0 | 24.1.0 | Closed | Docs-only release, no functional change |
```

---

## Commit Message Format

Use the original dependabot commit message when cherry-picking cleanly.

When a conflict required manual resolution:

```
Bump <package> from X.Y.Z to X.Y.W

Resolved poetry.lock conflict by regenerating after cherry-pick.
```

---

## What This Skill Does NOT Do

- Does not merge the PR (that is a human action after CI passes)
- Does not modify application code beyond `pyproject.toml` and `poetry.lock` (unless a
  breaking change forces an adjustment, which should be called out explicitly)
- Does not close PRs that dependabot will auto-close (already-merged ones)
- Does not read ISSUES.md or BACKLOG.md
- There are two Docker ecosystem entries in `.github/dependabot.yml` (dev at `/app`, production at `/`). Base image bumps may arrive as pairs.

---

## Start Here

Check `gh auth status`, then list open dependabot PRs and present the classification table.
