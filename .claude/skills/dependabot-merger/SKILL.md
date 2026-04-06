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
- **Writes:** Git branch, pyproject.toml, poetry.lock, deploy/prod_requirements.lock.txt, GitHub PR
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
2. For each PR, classify as **Include** or **Skip** using the criteria below.
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

### Phase 5: Leave dependabot PRs for auto-close

**Do NOT manually close any dependabot PRs.** Dependabot auto-closes its own PRs when it
detects the target version (or a newer one) is already on main. This applies to all PRs:
included, skipped, and superseded. Let dependabot handle the lifecycle.

---

## Evaluation Criteria

### Value

A PR has value if it:
- Fixes a CVE or closes a known security advisory (**always include**)
- Bumps a dependency that `pip-audit` / `dev/deps_check.py` has flagged
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

### When to Skip

**Skip** (leave open) when:
- It's a major version bump worth revisiting later
- The changelog has meaningful changes that need deeper review
- You're unsure

When in doubt, skip rather than include. Dependabot will auto-close skipped PRs if a
newer version is merged via a future batch.

---

## PR Description Template

```
Batch dependency update YYYY-MM-DD.

## Included

| Package | From | To | Reason |
|---|---|---|---|
| cryptography | 43.0.0 | 43.0.3 | CVE-2024-XXXX |
| ruff | 0.8.0 | 0.9.1 | Minor dev-tool bump, no runtime impact |

## Skipped

| Package | From | To | Reason |
|---|---|---|---|
| fastapi | 0.115.0 | 0.116.0 | Minor bump, changelog has routing behavior changes — needs review |
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

## Transitive Dependencies

Some dependabot PRs only modify `deploy/prod_requirements.lock.txt` (a generated file). These are
transitive dependencies not directly pinned in `pyproject.toml`. The canonical source for
transitive dep versions is `poetry.lock`. `deploy/prod_requirements.lock.txt` is derived from it
via `poetry export` (automated by the `sync-prod-requirements` workflow).

**Do not cherry-pick these PRs.** Instead, after applying direct dep bumps, update transitive
deps through poetry:

```bash
poetry update <pkg1> <pkg2> ...
poetry export --only main --without-hashes -f requirements.txt -o deploy/prod_requirements.lock.txt
```

Commit the updated `pyproject.toml`, `poetry.lock`, and `deploy/prod_requirements.lock.txt` together.

---

## What This Skill Does NOT Do

- Does not merge the PR (that is a human action after CI passes)
- Does not modify application code beyond `pyproject.toml`, `poetry.lock`, and
  `deploy/prod_requirements.lock.txt` (unless a breaking change forces an adjustment, which
  should be called out explicitly)
- Does not manually close any dependabot PRs (dependabot auto-closes them)
- Does not read ISSUES.md or BACKLOG.md
- There are two Docker ecosystem entries in `.github/dependabot.yml` (dev at `/app`, production at `/`). Base image bumps may arrive as pairs.

---

## Start Here

Check `gh auth status`, then list open dependabot PRs and present the classification table.
