# Roadmap and Backlog

The roadmap and product backlog live on GitHub, not in `.claude/BACKLOG.md`.

| What | Where |
|------|-------|
| Backlog items (issues) | `Pageloom/weft-id-roadmap` (https://github.com/Pageloom/weft-id-roadmap) |
| Board, ordering, fields, strategy README | WeftID project, `Pageloom` project 2 (https://github.com/orgs/Pageloom/projects/2) |
| Bugs, dependency CVEs, refactors | `Pageloom/weft-id` issues (see `issue-tracking.md`) |

Both the repository and the project are **public** and read-only for anyone outside
Pageloom (see "Access" below).

## What may be written there

Everything in the roadmap is public. Never write:

- PII, or the name of a customer, prospect or any private individual
- Anything that puts a customer, competitor or vendor in a bad light. Naming a product
  as the model being followed is fine; characterising its quality is not
- An unfixed vulnerability in our own code (that goes to a private draft security
  advisory, see `issue-tracking.md`)

Issue edit history is public too, so get the wording right before creating the issue.

## Structure

```
Stage (top-level issue, ordered manually in the project)
└── Backlog item (sub-issue of the stage, in priority order)
    └── Iteration (sub-issue of the item, in execution order; only for groomed items)
```

- Stages are plain issues with no "phase" wording or numbering. The top stage is what
  comes next. "Product depth" and "Engineering quality" are standing stages for work
  outside the main sequence.
- The order of sub-issues under a parent is the priority order. First is next.
- The strategy behind the sequence is in the project README (`gh project view 2 --owner Pageloom`).

Project fields on backlog items: `Status` (Todo, In Progress, Done), `Effort` (S, M, L, XL),
`Value` (High, Medium, Low). Stages and iterations carry `Status` only.

## Reading

```bash
R=Pageloom/weft-id-roadmap

# Everything, with fields (stages come back in project order)
gh project item-list 2 --owner Pageloom --limit 200 --format json \
  --jq '.items[] | [.content.number, .status, .effort // "-", .value // "-", .title] | @tsv'

# The items of one stage (or the iterations of one item), in priority order
gh api repos/$R/issues/<parent>/sub_issues --jq '.[] | [.number, .state, .title] | @tsv'

# One item in full
gh issue view <number> -R $R
gh issue list -R $R --search "<key words> in:title" --state all
```

A stage is an issue whose `gh api repos/$R/issues/<n> --jq .sub_issues_summary.total`
is non-zero and that has no parent (`gh api repos/$R/issues/<n>/parent` returns 404).

## Adding a backlog item

Write the body to a file in the scratchpad (the `/pm` item format without its heading,
which becomes the title), then:

```bash
R=Pageloom/weft-id-roadmap
url=$(gh issue create -R $R --title "<title>" --body-file <file> | tail -1)
num=${url##*/}

# Attach to its stage (appends at the end; pass the issue's database id, not its number)
gh api -X POST repos/$R/issues/<stage>/sub_issues -F sub_issue_id=$(gh api repos/$R/issues/$num --jq .id)
```

A workflow in the roadmap repo locks every new issue, and the project adds sub-issues
automatically with `Status` Todo. Then set the fields:

```bash
P=PVT_kwDODYnXdM4BllJm
item=$(gh project item-list 2 --owner Pageloom --limit 200 --format json \
  --jq ".items[] | select(.content.number == $num) | .id")
gh project item-edit --project-id $P --id $item \
  --field-id PVTSSF_lADODYnXdM4BllJmzhkRecU --single-select-option-id <effort option>
gh project item-edit --project-id $P --id $item \
  --field-id PVTSSF_lADODYnXdM4BllJmzhkRecY --single-select-option-id <value option>
```

| Field | Field id | Options |
|-------|----------|---------|
| Status | `PVTSSF_lADODYnXdM4BllJmzhkRdD0` | Todo `f75ad846`, In Progress `47fc9ee4`, Done `98236657` |
| Effort | `PVTSSF_lADODYnXdM4BllJmzhkRecU` | S `c56b0a87`, M `adf0e2f2`, L `d967d236`, XL `9d2e08d4` |
| Value | `PVTSSF_lADODYnXdM4BllJmzhkRecY` | High `93458c2f`, Medium `e21c4f75`, Low `3bf3ce37` |

If an item is missing from the project, add it with
`gh project item-add 2 --owner Pageloom --url <issue url>`.

A new stage is an issue with no parent. It lands at the bottom of the project; its
position among the stages is a decision for the user.

## Prioritising

A new sub-issue goes to the end of its parent's list. To move it:

```bash
# Place <num> directly after <other> (or use before_id to place it before)
gh api -X PATCH repos/$R/issues/<parent>/sub_issues/priority \
  -F sub_issue_id=$(gh api repos/$R/issues/<num> --jq .id) \
  -F after_id=$(gh api repos/$R/issues/<other> --jq .id)
```

To move an item to another stage, remove it
(`gh api -X DELETE repos/$R/issues/<stage>/sub_issue -F sub_issue_id=<id>`) and attach
it to the new one.

## Working an item

- **Starting:** set `Status` to In Progress (`item-edit` with the Status field above).
- **Finishing:** put `Fixes Pageloom/weft-id-roadmap#<number>` in the body of the commit
  that completes it. The issue closes when the commit reaches `main` in weft-id, and the
  project moves it to Done. To close by hand: `gh issue close <number> -R $R`.
- **What shipped:** when the result differs from the item as written (scope cut, design
  change, follow-ups split out), record it in a comment on the issue before it closes
  (`gh issue comment <number> -R $R --body-file <file>`). The commit and CHANGELOG carry
  the rest.
- **Iterations:** `/lead` creates one sub-issue per planned iteration and closes each as
  it completes. The parent item closes with the last one.
- **Dropping an item:** `gh issue close <number> -R $R --reason "not planned" --comment "<why>"`.

Do not copy completed items into `.claude/BACKLOG_ARCHIVE.md`.

## Access

Outsiders can read everything and change nothing:

- The project is editable by organization members only.
- The repo has an interaction limit of collaborators only. It **expires on 2027-04-03**
  (six months is the maximum) and must be renewed:
  `gh api -X PUT repos/Pageloom/weft-id-roadmap/interaction-limits -f limit=collaborators_only -f expiry=six_months`
- As a backstop, `.github/workflows/restrict-issues.yml` in the roadmap repo locks every
  new issue and closes any opened by someone without write access.

## History

`.claude/BACKLOG_ARCHIVE.md` is the frozen record of items completed before 2026-10-03.
Nothing new is added to it. For what shipped since, read it together with:

```bash
gh issue list -R Pageloom/weft-id-roadmap --state closed --limit 100
```
