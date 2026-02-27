# List View Patterns: WeftUtils.listManager()

`WeftUtils.listManager(config)` consolidates the repeated patterns found across list view
pages: localStorage persistence for page size and filters, a collapsible filter panel, a
page size selector, and multiselect with a sticky bulk action bar.

All config keys are optional. The utility activates only the features whose config section
is present.

---

## Full config shape

```js
WeftUtils.listManager({
  // localStorage persistence + on-load redirect to restore saved state
  storage: {
    filtersKey: 'weftid_filters_<id>',        // localStorage key for filter state JSON
    pageSizeKey: 'weftid_page_size_<id>',      // localStorage key for page size string
    collapseKey: 'weftid_filters_collapsed_<id>', // localStorage key for panel collapse state
    defaultPageSize: 25,                       // used in needsSizeRestore check
    validPageSizes: [10, 25, 50, 100],         // accepted page size values
    currentSize: 25,                           // page size from server (current request)
    filtersActive: false,                      // true if filter params are in current URL
  },

  // CSS selector for the page size <select> element(s)
  pageSizeSelector: '#page-size',

  // Collapsible filter panel
  filterPanel: {
    toggleBtn: '#toggle-filters-btn',          // button that opens/closes the panel
    panel: '#filter-panel',                    // the panel element to show/hide
    chevron: '#filter-chevron',                // chevron icon rotated 180deg when open
    applyBtn: '#apply-filters-btn',            // button that applies current filter state
    clearSelectors: '.clear-filters-action, #clear-filters-link', // optional clear links
    getState: () => ({ roles: [], statuses: [] }),  // reads current checkbox state
    buildUrl: (state, pageSize) => '/path?...',     // constructs navigation URL
  },

  // Multiselect rows with sticky bulk action bar
  multiselect: {
    selectAll: '#select-all',                  // select-all checkbox
    rowCheckboxSelector: '.row-checkbox',      // per-row checkbox selector
    actionBar: '#bulk-action-bar',             // bulk action bar element
    countDisplay: '#selected-count',           // element showing selected count
    actions: [
      {
        selector: '#action-btn',               // button selector
        destructive: true,                     // true: red confirm button
        confirmMessage: 'Are you sure?',       // triggers confirm modal before callback
        callback: (selectedIds) => { /* ... */ }, // called after optional confirmation
      },
    ],
  },
});
```

### How storage/redirect works

On page load (before wiring any UI), if `storage` is configured:

1. Compute `effectiveSize`: URL `size` param if present, else localStorage `pageSizeKey`,
   else `currentSize`.
2. If `filtersActive` is false, load `savedFilters` from `filtersKey`.
3. `needsSizeRestore` = size not in URL AND `effectiveSize !== String(defaultPageSize)`.
4. `needsFilterRestore` = `savedFilters` has any non-empty array values.
5. If either is true: redirect to the restored URL, then `return` (skip all UI wiring).
   - If `filterPanel` is configured: use `filterPanel.buildUrl(savedFilters || {}, effectiveSize)`.
   - Otherwise: update `size` and `page=1` on the current URL via `new URL(location.href)`.

---

## Example 1: Page size only (admin_events pattern)

No localStorage, no filter panel, no multiselect. Just navigate on size change while
preserving all existing URL params (`page`, filters, etc.).

```js
WeftUtils.listManager({ pageSizeSelector: '#page-size' });
```

---

## Example 2: Filter panel + storage (users_list pattern)

```js
const { tenantId, filtersActive, search, sortField, sortOrder, pageSize } = JSON.parse(
    document.getElementById('page-data').textContent
);
WeftUtils.listManager({
    storage: {
        filtersKey: `weftid_filters_${tenantId}`,
        pageSizeKey: `weftid_page_size_${tenantId}`,
        collapseKey: `weftid_filters_collapsed_${tenantId}`,
        defaultPageSize: 25,
        validPageSizes: [10, 25, 50, 100],
        currentSize: pageSize,
        filtersActive,
    },
    pageSizeSelector: '#page-size',
    filterPanel: {
        toggleBtn: '#toggle-filters-btn',
        panel: '#filter-panel',
        chevron: '#filter-chevron',
        applyBtn: '#apply-filters-btn',
        clearSelectors: '.clear-filters-action, #clear-filters-link',
        getState: () => ({
            roles: ['filter-member', 'filter-admin', 'filter-super_admin']
                .filter(id => document.getElementById(id)?.checked)
                .map(id => document.getElementById(id).value),
            statuses: ['filter-active', 'filter-inactivated', 'filter-anonymized']
                .filter(id => document.getElementById(id)?.checked)
                .map(id => document.getElementById(id).value),
            auth_methods: Array.from(document.querySelectorAll('.filter-auth-method:checked'))
                .map(el => el.value),
        }),
        buildUrl: (state, size) => {
            let url = `/users/list?page=1&size=${size}&sort=${sortField}&order=${sortOrder}`;
            if (search) url += `&search=${encodeURIComponent(search)}`;
            if (state.roles?.length) url += `&role=${state.roles.join(',')}`;
            if (state.statuses?.length) url += `&status=${state.statuses.join(',')}`;
            if (state.auth_methods?.length) url += `&auth_method=${state.auth_methods.join(',')}`;
            return url;
        },
    },
});
```

---

## Example 3: Multiselect + action bar (groups_members pattern)

```js
const { tenantId, groupId, baseUrl, filtersActive, search, sortField, sortOrder, pageSize, confirmMessage } = JSON.parse(
    document.getElementById('page-data').textContent
);
WeftUtils.listManager({
    storage: {
        filtersKey: `weftid_grp_members_filters_${tenantId}_${groupId}`,
        pageSizeKey: `weftid_grp_members_size_${tenantId}_${groupId}`,
        collapseKey: `weftid_grp_members_collapsed_${tenantId}_${groupId}`,
        defaultPageSize: 25,
        validPageSizes: [10, 25, 50, 100],
        currentSize: pageSize,
        filtersActive,
    },
    pageSizeSelector: '#page-size',
    filterPanel: {
        toggleBtn: '#toggle-filters-btn',
        panel: '#filter-panel',
        chevron: '#filter-chevron',
        applyBtn: '#apply-filters-btn',
        clearSelectors: '.clear-filters-action, #clear-filters-link',
        getState: () => ({
            roles: ['filter-member', 'filter-admin', 'filter-super_admin']
                .filter(id => document.getElementById(id)?.checked)
                .map(id => document.getElementById(id).value),
            statuses: ['filter-active', 'filter-inactivated', 'filter-anonymized']
                .filter(id => document.getElementById(id)?.checked)
                .map(id => document.getElementById(id).value),
        }),
        buildUrl: (state, size) => {
            let url = `${baseUrl}?page=1&size=${size}&sort=${sortField}&order=${sortOrder}`;
            if (search) url += `&search=${encodeURIComponent(search)}`;
            if (state.roles?.length) url += `&role=${state.roles.join(',')}`;
            if (state.statuses?.length) url += `&status=${state.statuses.join(',')}`;
            return url;
        },
    },
    multiselect: {
        selectAll: '#select-all',
        rowCheckboxSelector: '.member-checkbox',
        actionBar: '#bulk-action-bar',
        countDisplay: '#selected-count',
        actions: [{
            selector: '#bulk-remove-btn',
            destructive: true,
            confirmMessage,
            callback: () => document.getElementById('bulk-remove-form').submit(),
        }],
    },
});
```

---

## Notes

- **`stickyActionBar` is called automatically** inside `listManager` when `multiselect`
  is configured. Do not call it separately in `{% block extra_scripts %}`.
- **Row click-to-toggle** is wired automatically. Clicks on `a`, `input`, or `button`
  elements within the row are excluded. Rows without a matching checkbox are skipped.
- **`action.callback` receives `selectedIds`** (array of checkbox `.value` strings) but
  for form-submit patterns you typically ignore it and call `form.submit()` directly.
- **Filter panel collapse state** defaults to collapsed unless `filtersActive` is true.
  Pass `collapseKey` in storage to persist the user's preference across page loads.
- **`clearSelectors`**: the links handle navigation themselves (they are plain `<a>` tags).
  The listManager only attaches a `click` listener to clear the `filtersKey` from
  localStorage before the navigation happens.
