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
| `app/services/` | 2026-02-27 | 2026-02-01 | service_providers/ split into package; crud.py at 1168 lines (new issue logged) |
| `app/database/` | 2026-02-06 | 2026-02-01 | RESOLVED - all files now <360 lines (split into packages) |
| `app/routers/` | 2026-02-06 | 2026-02-01 | RESOLVED - 4 large files split into packages; log_event calls documented as intentional |
| `app/routers/api/` | 2026-02-06 | 2026-02-01 | RESOLVED - dead code removed in router split |
| `app/schemas/` | 2026-02-01 | 2026-02-01 | Clean - all files <500 lines |
| `app/middleware/` | 2026-02-01 | 2026-02-01 | Clean - all files <220 lines |
| `app/jobs/` | 2026-02-01 | 2026-02-01 | Clean - well-structured |
| `app/utils/` | 2026-02-12 | 2026-02-07 | Clean - largest file 649 lines (email.py) |
| `app/worker.py` | 2026-02-12 | 2026-02-07 | RESOLVED - refactored to PeriodicJob class, 200 lines |
| `app/services/branding.py` | 2026-02-27 | 2026-02-27 | 696 lines, 5 concerns (validation, CRUD, mandala, group logos, serving) — borderline, monitor |
| `app/routers/api/v1/groups.py` | 2026-02-27 | 2026-02-27 | 704 lines, 7 concerns including new group logo endpoints — monitor |
| `app/database/branding.py` | 2026-02-27 | 2026-02-27 | 242 lines, clean |
| `app/routers/settings.py` | 2026-02-27 | 2026-02-27 | 584 lines, growing with branding routes — monitor |
| `tests/` | 2026-02-06 | 2026-02-06 | Parametrization applied (commit 979c5f4), large files mirror app structure (accepted) |
| `tests/services/test_branding.py` | 2026-02-27 | 2026-02-27 | 814 lines, mirrors production complexity (accepted); _make_png() duplication logged |

## Recurring Patterns

Track issues that keep appearing to identify systemic problems:

| Pattern | Occurrences | Areas Affected | Root Cause Hypothesis |
|---------|-------------|----------------|----------------------|
| Authorization helpers duplicated | ~~12~~ → RESOLVED | services | FIXED: Centralized in `app/services/auth.py` |
| Growing god modules | ~~1 (saml.py at 2658 lines)~~ → 1 (crud.py at 1168 lines) | services | service_providers.py split into package but crud.py became new god module |
| Large files (>500 lines) | ~~8 files~~ → ~~14 files~~ → ~~15~~ → 17 app files | services, routers, utils | 1 critical: crud.py at 1168 lines; branding.py (696), groups API (704), settings (584) borderline |

---

## Session History

<!-- New entries go here, below this line -->

### 2026-02-27 - New Code (Branding Module) Deep Scan

**Scan type:** Deep
**Areas analyzed:** New code since 2026-02-12: `app/services/branding.py`, `app/database/branding.py`, `app/routers/branding.py`, `app/routers/settings.py` (branding routes), `app/routers/api/v1/groups.py` (group logo endpoints), `tests/services/test_branding.py`, `tests/api/test_branding.py`, `app/services/service_providers/` (post-split state)
**Categories focused:** All (file structure, duplication, complexity, architecture, dead code)

**Prior open items:**
- REFACT-001 (dropdown pagination): Captured in ISSUES.md as "[BUG] Pagination: Page size selector missing..." — still open
- REFACT-002 (service_providers.py at 1129 lines): Resolved by package split (2026-02-13), but `crud.py` is now 1168 lines — new issue logged

**New findings:**

1. **`service_providers/crud.py` at 1168 lines, 23 functions (Medium)** — Package split from REFACT-002 created a new god module. Status: Open

2. **`update_branding_settings()` two DB reads before writing (Medium)** — `get_branding()` called twice at lines 410 and 435 before the write at 439. Easily fixed by a single read at function start. Status: Open

3. **`_make_png()` duplicated across branding test files (Low)** — Identical helper in `tests/services/test_branding.py:33` and `tests/api/test_branding.py:19`. Status: Open

**What was clean in new branding code:**
- Architecture: Router → service → database layering maintained; no router-to-database imports
- Event logging: All branding writes log events (`branding_logo_uploaded`, `branding_logo_deleted`, `branding_settings_updated`, etc.)
- Activity tracking: `get_branding_settings()` and `randomize_mandala()` both call `track_activity()`
- Authorization: `require_admin()` called at the top of every write function
- Test coverage: ~100% on service layer (service tests), adequate coverage on API layer (API tests)
- No dead code found
- `app/database/branding.py` is clean (242 lines)
- ETag serving logic in `app/routers/branding.py` is a minor cosmetic duplication (87-line file), not logged

**Monitor items (not logged):**
- `app/services/branding.py`: 696 lines, borderline. 5 concerns with clear section headers — acceptable for now
- `app/routers/api/v1/groups.py`: 704 lines, growing. Group logo endpoints added to groups router (conceptually orthogonal, but acceptable)
- `app/routers/settings.py`: 584 lines, growing with new branding routes — watch

**Recommendations for next scan:**
- After `crud.py` is split, verify test mock targets updated in `test_services_service_providers.py`
- If `settings.py` grows past 650 lines, consider extracting branding routes to a dedicated settings-branding router
- If `branding.py` service grows past 750 lines, consider splitting serving helpers and validation into sub-modules

**Issues logged:** 3 new issues (1 medium file structure, 1 medium complexity, 1 low duplication)
**Issues resolved since last scan:** REFACT-002 (service_providers.py split — per commit 2026-02-13)

---

### 2026-02-12 - Standard Full Scan

**Scan type:** Standard
**Areas analyzed:** Full codebase (app/, file sizes, architecture, new Phase 3 code)
**Categories focused:** All (file structure, duplication, complexity, architecture)

**Prior open items (all 4 resolved):**

1. Super-admin count check uses wrong query - **RESOLVED** (now uses `count_active_super_admins()`)
2. Worker periodic task boilerplate - **RESOLVED** (refactored to `PeriodicJob` class)
3. Backwards-compat re-export in worker.py - **RESOLVED** (removed)
4. Missing event log for export download - **RESOLVED** (now calls `log_event()`)

**New findings:**

1. **Dropdown pagination limits silently truncate results (High)** - `selection.py:52-56` uses `page_size=100` for users and `page_size=1000` for members. Silent data loss for larger tenants. Status: Open (REFACT-001)

2. **service_providers.py exceeds 1100 lines (Medium)** - 1129 lines, 26 functions, 5 concerns. Contains duplicate code in metadata import and metadata generation functions. Status: Open (REFACT-002)

**Architecture check (all pass):**
- Router-to-database imports: 0 violations
- Missing track_activity(): 0 violations
- Missing log_event(): 0 violations

**File size summary:** 15 files >500 lines (1 critical at 1129). No file except service_providers.py exceeds 660 lines.

**Recommendations for next scan:**
- After service_providers.py split, verify test mock targets updated
- After selection.py fix, add test with >100 users to validate pagination behavior
- Monitor if any other service files approach 700+ lines

**Issues logged:** 2 new issues added to ISSUES.md (1 high, 1 medium)
**Issues resolved since last scan:** 4 (all prior open items)

---

### 2026-02-07 - Full Codebase Standard Scan

**Scan type:** Standard
**Areas analyzed:** Full codebase (app/, tests/, worker.py)
**Categories focused:** All (file structure, duplication, complexity, architecture, dead code)

**Key findings:**

1. **Super-admin count check uses wrong query (Medium)** - `_validation.py:53-68` uses `list_users(page_size=100)` and counts in Python instead of `count_active_super_admins()`. Potential correctness bug with >100 users. Status: Open

2. **Worker periodic task boilerplate (Medium)** - 3 identical `_maybe_run_*`/`_run_*` pairs in `worker.py` (68 lines). Could be ~20 with a generic helper. Status: Open

3. **Backwards-compat re-export in worker.py (Low)** - `register_handler()` re-exported but may be dead code. Status: Open

4. **Missing event log for export download (Low)** - `exports.py:91` writes `mark_downloaded()` without `log_event()`. Status: Open

**What was clean:**
- Architecture: No router-to-database imports, layered architecture fully maintained
- Error handling: All services use ServiceError subclasses consistently
- Event logging: Comprehensive (72 calls across 22 files, 1 exception noted)
- Activity tracking: All read functions call track_activity()
- Authorization: Centralized in auth.py, no duplicated helpers
- No circular imports, no dead code, no deep nesting issues in production code
- File structure: No file exceeds 660 lines (down from 2 files >1000 lines)

**Recommendations for next scan:**
- After fixing _validation.py, verify test coverage for >100 user scenarios
- After worker refactor, verify all periodic tasks still run correctly
- Consider deep scan of app/utils/ (email.py at 649 lines may grow)

**Issues logged:** 4 new issues added to ISSUES.md (2 medium, 2 low)
**Issues resolved since last scan:** 2 (users.py and groups.py >1000 lines now split)

---

### 2026-02-06 - Verification Scan

**Scan type:** Quick
**Areas analyzed:** Full codebase file size verification
**Categories focused:** File Structure

**Key findings:**

1. **Large database files** - Status: RESOLVED. All files now <360 lines (largest: mfa.py at 360).

2. **Large router files** - Status: RESOLVED. All 4 large routers split into packages (saml/, auth/, users/, api/v1/users/).

3. **Dead code (unused converters)** - Status: RESOLVED. File deleted as part of router split.

4. **log_event in routers** - Status: ACCEPTED. Each call has "Architectural Note" comment documenting intent for auth flows.

5. **New critical files found (High)** - 2 service files exceed 1000 lines:
   - `app/services/users.py`: 1334 lines
   - `app/services/groups.py`: 1295 lines
   Status: Open (logged to ISSUES.md)

**Current large file count:** 14 files >500 lines (2 critical >1000)

**Issues logged:** 1 new issue (2 critical service files)
**Issues resolved since last scan:** 4 (database files, router files, dead code, log_event accepted)

---

### 2026-02-06 - Test Suite

**Scan type:** Standard
**Areas analyzed:** `tests/` (97 test files, 51,477 total lines)
**Categories focused:** All categories

**Key findings:**

1. **Parametrization opportunities (Medium)** - 4 groups of similar tests could use `pytest.mark.parametrize` to reduce duplication by 50-70%. Status: Open

2. **Large test files (Accepted)** - 38 files exceed 500 lines (largest: test_services_saml.py at 5,380 lines). These mirror correspondingly large/complex production modules. Splitting would create artificial separation. Status: Accepted

**What was NOT found:**
- Nested patch pyramids (prior cleanup in commit 618aa2c resolved these)
- Missing docstrings (100% coverage in sampled files)
- Duplicated setup code (well-factored into fixtures and factory functions)

**Recommendations for next scan:**
- After parametrization is applied, verify test count and coverage unchanged
- Monitor if any new large test files emerge that don't mirror app structure

**Issues logged:** 1 new issue added to ISSUES.md
**Issues resolved since last scan:** 0

---

### 2026-02-01 - Full Codebase (Session 2)

**Scan type:** Deep
**Areas analyzed:** `app/database/`, `app/routers/`, `app/routers/api/`, `app/schemas/`, `app/middleware/`, `app/jobs/`
**Categories focused:** All categories

**Key findings:**

1. **File structure - Large database files (High)** - 4 database modules exceed 500 lines (saml.py 1112, users.py 1003, groups.py 936, oauth2.py 842). Recommend splitting into sub-modules like services/saml/. Status: RESOLVED (all files now <360 lines)

2. **File structure - Large router files (High)** - 4 router modules exceed 500 lines (routers/saml.py 1241, auth.py 987, users.py 747, api/v1/users.py 1025). Status: RESOLVED (split into packages, archived 2026-02-06)

3. **Dead code (Medium)** - 4 unused converter functions in `app/routers/api/v1/users.py` (~60 lines). Services now return schemas directly. Status: RESOLVED (file deleted in router split)

4. **Architecture (Low)** - 5 direct log_event() calls in routers (auth.py, mfa.py) instead of services. May be acceptable for auth flows. Status: ACCEPTED (each has Architectural Note documenting intent)

**Resolved since last scan:**
- Authorization helper duplication: RESOLVED - centralized in `app/services/auth.py`
- God module saml.py: RESOLVED - split into `app/services/saml/` with 10 sub-modules

**What was NOT found:**
- Duplication in schemas, middleware, jobs (all clean)
- Tight coupling issues (layered architecture well-maintained)
- Dead imports (ruff would catch these)

**Recommendations for next scan:**
- After database layer split, verify no new duplication introduced
- Consider scanning `tests/` for coverage gaps
- Monitor if large router files cause issues in practice

**Issues logged:** 4 new issues added to ISSUES.md
**Issues resolved since last scan:** 2 (auth helpers, saml god module)

---

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
