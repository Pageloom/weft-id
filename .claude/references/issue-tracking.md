# Issue Tracking

Open work is tracked on GitHub (`Pageloom/weft-id`), not in `.claude/ISSUES.md`.
The repository is **public**, so where a finding goes depends on what it is.

| Finding | Where it goes |
|---------|---------------|
| Vulnerability in our own code (`/security`, or anything found along the way) | Private **draft security advisory** |
| Known CVE in a dependency (`/deps`) | Public issue (the CVE is already public) |
| Everything else (bugs, compliance violations, refactors, copy problems) | Public issue |

Never put an unfixed vulnerability in our own code in a public issue, a commit
message, a PR body, or a file under `.claude/`. Describe it only in the advisory.

## Labels

Every issue takes one type label and one level label.

| Type | Level (exactly one) | Used by |
|------|---------------------|---------|
| `bug` | `severity-low`, `severity-medium`, `severity-high`, `severity-critical` | `/test`, `/compliance`, `/tech-writer`, `/lead` |
| `security` | `severity-low`, `severity-medium`, `severity-high`, `severity-critical` | `/deps` (add `dependencies` too) |
| `enhancement` | `prio-low`, `prio-medium`, `prio-high`, `prio-crucial` | `/refactor` |

`documentation` may be added to a copy or docs issue.

## Creating an issue

Write the body to a file in the scratchpad (the skill's issue format, without
its `## [TAG] ...` heading, which becomes the title), then:

```bash
gh issue list --search "<key words> in:title" --state all   # check for a duplicate first
gh issue create --title "<title>" --label bug --label severity-medium --body-file <file>
```

Titles are plain sentences without a `[TAG]` prefix; the labels carry the type.
Report the issue number and URL to the user.

## Creating a draft security advisory

```bash
gh api -X POST repos/Pageloom/weft-id/security-advisories --input <payload.json> \
  --jq '[.ghsa_id,.state,.severity,.html_url]|@tsv'
```

Payload:

```json
{
  "summary": "<title>",
  "description": "<markdown body: the /security issue format>",
  "severity": "low | medium | high | critical",
  "cwe_ids": ["CWE-400"],
  "vulnerabilities": [
    {"package": {"ecosystem": "other", "name": "weft-id"},
     "vulnerable_version_range": "<= 1.12.0"}
  ]
}
```

Advisories are created in `draft` state, visible to repository admins only.
They take no labels; `severity` is a field. Set `vulnerable_version_range` to
the released versions that carry the flaw (for code that is only on `main`,
say so in the description). Report the GHSA id and URL to the user.

## Reading open work

```bash
gh issue list --label security --state open
gh issue list --label bug --state open
gh issue list --label enhancement --state open
gh api "repos/Pageloom/weft-id/security-advisories?state=draft" \
  --jq '.[] | [.ghsa_id,.severity,.summary] | @tsv'
gh issue view <number>
gh api repos/Pageloom/weft-id/security-advisories/<ghsa_id> --jq .description
```

Order of work: draft advisories and `security` issues first, then `bug`, each by
severity (critical first), then `enhancement` by priority.

## Resolving

- **Issue:** put `Fixes #<number>` in the commit message body, so the issue
  closes when the commit reaches `main`. The fix detail lives in the commit
  message; add a closing comment only when something is worth recording that the
  commit does not say (`gh issue comment <number> --body-file <file>`). To close
  without a fix: `gh issue close <number> --reason "not planned" --comment "<why>"`.
- **Draft advisory:** keep the commit message neutral (what changed, not how to
  exploit what was there) and do not reference the GHSA id. Tell the user the
  fix has landed and give them the GHSA id. Publishing or closing an advisory
  is the user's decision; never do it yourself.

## History

`.claude/ISSUES_ARCHIVE.md` is the frozen record of issues resolved before
2026-10-03. Nothing new is added to it. For past issues, read it together with:

```bash
gh issue list --state closed --label security --limit 100
gh api "repos/Pageloom/weft-id/security-advisories?state=published"
gh api "repos/Pageloom/weft-id/security-advisories?state=closed"
```
