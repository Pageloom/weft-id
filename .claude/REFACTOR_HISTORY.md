# Refactor Agent History

This file tracks refactoring analysis sessions to help the agent make better recommendations over time.

## How to Use This File

- **Before scanning**: Review recent history to avoid redundant analysis
- **After scanning**: Add a new entry summarizing the session
- **When issues are fixed**: Update the relevant entry to mark findings as resolved

## Session Log

<!-- Add new entries at the top, most recent first -->

### Template for New Entries

```
### YYYY-MM-DD - [Scope]

**Scan type:** Quick / Standard / Deep
**Areas analyzed:** [list of modules/directories]
**Categories focused:** [All / Duplication / Complexity / etc.]

**Key findings:**
- [Issue 1 - brief description] - Status: Open/Resolved
- [Issue 2 - brief description] - Status: Open/Resolved

**Recommendations for next scan:**
- [Any patterns noticed or areas to revisit]

**Issues logged:** [count] new issues added to ISSUES.md
**Issues resolved since last scan:** [count]
```

---

## Analysis Coverage Tracker

Track when each area was last analyzed to identify gaps:

| Area | Last Scanned | Last Deep Scan | Notes |
|------|--------------|----------------|-------|
| `app/services/` | 2026-02-01 | 2026-02-01 | 3 issues found |
| `app/database/` | Never | Never | |
| `app/routers/` | Never | Never | |
| `app/routers/api/` | Never | Never | |
| `app/schemas/` | Never | Never | |
| `app/middleware/` | Never | Never | |
| `app/jobs/` | Never | Never | |
| `tests/` | Never | Never | |

## Recurring Patterns

Track issues that keep appearing to identify systemic problems:

| Pattern | Occurrences | Areas Affected | Root Cause Hypothesis |
|---------|-------------|----------------|----------------------|
| Authorization helpers duplicated | 12 (9 `_require_admin`, 3 `_require_super_admin`) | 9 service files | No shared auth module; each service defines its own helpers |
| Growing god modules | 1 (saml.py at 2658 lines) | services | Feature additions without refactoring; no sub-module pattern established |

---

## Session History

<!-- New entries go here, below this line -->

### 2026-02-01 - Services Layer

**Scan type:** Deep
**Areas analyzed:** `app/services/` (15 Python files, 9026 total lines)
**Categories focused:** All categories

**Key findings:**

1. **Authorization helper duplication (High)** - `_require_admin()` duplicated 9 times across service files with 3 inconsistent variants. `_require_super_admin()` duplicated 3 times with 2 variants. Status: Open

2. **God module: saml.py (High)** - 2658 lines, 45 functions handling 12+ distinct responsibilities. Should be split into sub-modules. Status: Open

3. **Long functions (Medium)** - `update_user()` (~130 lines), `process_saml_response()` (~130 lines), `sync_user_idp_groups()` (~121 lines). Status: Open

**What was NOT found:**
- Dead code (ruff found no unused imports)
- Tight coupling issues (layered architecture followed well)
- Over-engineering (appropriate complexity for domain)
- Major naming issues (conventions followed consistently)

**Recommendations for next scan:**
- Scan `app/database/` to check if similar authorization patterns exist there
- After fixing authorization duplication, check if similar patterns exist in routers
- Consider scanning `app/routers/` for complexity issues (likely mirrors service complexity)

**Issues logged:** 3 new issues added to ISSUES.md
**Issues resolved since last scan:** N/A (first scan)
