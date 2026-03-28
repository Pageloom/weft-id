/**
 * WeftID JavaScript Utilities
 *
 * This file contains reusable JavaScript patterns for the application.
 * Keep this minimal. Server-side rendering is preferred.
 *
 * Usage: WeftUtils.functionName(args)
 */

const WeftUtils = {
    /**
     * Copy text to clipboard with visual feedback.
     *
     * @param {string} text - Text to copy
     * @param {HTMLElement} [feedbackEl] - Element to show feedback on (changes text to "Copied!")
     * @returns {Promise<boolean>} - True if successful
     */
    copyToClipboard(text, feedbackEl) {
        return navigator.clipboard.writeText(text).then(() => {
            if (feedbackEl) {
                const original = feedbackEl.textContent;
                feedbackEl.textContent = 'Copied!';
                setTimeout(() => { feedbackEl.textContent = original; }, 2000);
            }
            return true;
        }).catch(() => {
            // Show error in modal instead of alert
            WeftUtils.confirm('Failed to copy. Please copy manually.', null, { okOnly: true });
            return false;
        });
    },

    /**
     * Show a modal by ID.
     *
     * @param {string} id - Modal element ID
     */
    showModal(id) {
        const modal = document.getElementById(id);
        if (modal) {
            modal.classList.remove('hidden');
            modal.classList.add('flex');
            // Focus first focusable element
            const focusable = modal.querySelector('input, button, select, textarea, [tabindex]:not([tabindex="-1"])');
            if (focusable) focusable.focus();
        }
    },

    /**
     * Hide a modal by ID.
     *
     * @param {string} id - Modal element ID
     */
    hideModal(id) {
        const modal = document.getElementById(id);
        if (modal) {
            modal.classList.add('hidden');
            modal.classList.remove('flex');
        }
    },

    /**
     * Show a confirmation modal (replaces native confirm()).
     *
     * @param {string} message - Message to display
     * @param {Function} onConfirm - Callback when confirmed (null for info-only)
     * @param {Object} [options] - Configuration options
     * @param {boolean} [options.destructive=false] - Use red button for dangerous actions
     * @param {boolean} [options.okOnly=false] - Only show OK button (for alerts)
     */
    confirm(message, onConfirm, options = {}) {
        const modal = document.getElementById('weft-confirm-modal');
        const messageEl = document.getElementById('weft-confirm-message');
        const cancelBtn = document.getElementById('weft-confirm-cancel');
        const okBtn = document.getElementById('weft-confirm-ok');

        if (!modal || !messageEl || !okBtn) {
            // Fallback to native if modal not present
            if (options.okOnly) {
                alert(message);
                return;
            }
            if (confirm(message) && onConfirm) onConfirm();
            return;
        }

        messageEl.textContent = message;

        // Show/hide cancel button
        if (options.okOnly) {
            cancelBtn.classList.add('hidden');
        } else {
            cancelBtn.classList.remove('hidden');
        }

        // Apply destructive styling
        if (options.destructive) {
            okBtn.classList.remove('bg-blue-600', 'hover:bg-blue-700');
            okBtn.classList.add('bg-red-600', 'hover:bg-red-700');
        } else {
            okBtn.classList.remove('bg-red-600', 'hover:bg-red-700');
            okBtn.classList.add('bg-blue-600', 'hover:bg-blue-700');
        }

        // Store callback for use in handlers
        WeftUtils._confirmCallback = onConfirm;

        WeftUtils.showModal('weft-confirm-modal');
    },

    /**
     * Detect user's timezone.
     *
     * @returns {string} - IANA timezone identifier (e.g., "America/New_York")
     */
    detectTimezone() {
        return Intl.DateTimeFormat().resolvedOptions().timeZone;
    },

    /**
     * Detect user's locale.
     *
     * @returns {string} - Locale with underscores (e.g., "en_US")
     */
    detectLocale() {
        const locale = new Intl.DateTimeFormat().resolvedOptions().locale;
        return locale.replace('-', '_');
    },

    /**
     * Make a bulk action bar sticky at the bottom of the viewport when visible.
     *
     * The bar sits in its natural flow position. CSS `position: sticky; bottom: 0`
     * makes it stick to the viewport bottom only when scrolled past its natural
     * position. An IntersectionObserver on a sentinel div detects stuck state and
     * adds a shadow when stuck. A MutationObserver handles show/hide toggling.
     *
     * @param {string|HTMLElement} elementOrId - Element or element ID
     */
    stickyActionBar(elementOrId) {
        const el = typeof elementOrId === 'string'
            ? document.getElementById(elementOrId)
            : elementOrId;
        if (!el) return;

        // Sentinel element placed right after the bar to detect stuck state
        const sentinel = document.createElement('div');
        sentinel.style.height = '1px';
        sentinel.style.visibility = 'hidden';
        sentinel.style.pointerEvents = 'none';
        sentinel.style.display = 'none';
        el.parentNode.insertBefore(sentinel, el.nextSibling);

        const applySticky = () => {
            requestAnimationFrame(() => {
                if (el.classList.contains('hidden')) return;
                el.style.position = 'sticky';
                el.style.bottom = '0';
                el.style.zIndex = '40';
                sentinel.style.display = '';
            });
        };

        const removeSticky = () => {
            el.style.position = '';
            el.style.bottom = '';
            el.style.zIndex = '';
            el.style.boxShadow = '';
            sentinel.style.display = 'none';
        };

        // IntersectionObserver detects when sentinel scrolls out of view,
        // meaning the bar is stuck at the viewport bottom
        const io = new IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (el.classList.contains('hidden')) return;
                if (entry.isIntersecting) {
                    // Sentinel visible: bar is in natural position
                    el.style.boxShadow = '';
                } else {
                    // Sentinel not visible: bar is stuck
                    el.style.boxShadow = '0 -2px 8px rgba(0,0,0,0.15)';
                }
            });
        }, { threshold: 0 });
        io.observe(sentinel);

        // Observe class changes to detect show/hide
        const observer = new MutationObserver(() => {
            if (el.classList.contains('hidden')) {
                removeSticky();
            } else {
                applySticky();
            }
        });
        observer.observe(el, { attributes: true, attributeFilter: ['class'] });

        // Apply immediately if already visible
        if (!el.classList.contains('hidden')) {
            applySticky();
        }
    },

    /**
     * Fetch wrapper that automatically injects the CSRF token header for
     * state-changing requests (POST, PUT, PATCH, DELETE) authenticated via
     * session cookie. Always sets credentials: 'same-origin'.
     *
     * Use this instead of bare fetch() for all state-changing API calls.
     *
     * @param {string} url - URL to fetch
     * @param {Object} [options] - fetch() options (same as native fetch)
     * @returns {Promise<Response>}
     */
    apiFetch(url, options = {}) {
        const method = (options.method || 'GET').toUpperCase();
        const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
        if (!safeMethods.includes(method)) {
            const meta = document.querySelector('meta[name="csrf-token"]');
            if (meta) {
                options.headers = options.headers || {};
                options.headers['X-CSRF-Token'] = meta.getAttribute('content');
            }
        }
        options.credentials = options.credentials || 'same-origin';
        return fetch(url, options);
    },

    /**
     * Universal list view manager: localStorage persistence, collapsible
     * filter panel, page size selector, and multiselect with sticky bulk
     * action bar. All config keys are optional; each feature activates only
     * when its config section is present.
     *
     * @param {Object} config
     * @param {Object} [config.storage] - localStorage + redirect-on-load
     * @param {string} [config.pageSizeSelector] - CSS selector for page size <select>
     * @param {Object} [config.filterPanel] - Filter panel wiring
     * @param {Object} [config.multiselect] - Multiselect + sticky action bar
     */
    listManager(config) {
        // --- Storage / redirect-on-load ---
        if (config.storage) {
            const s = config.storage;
            const urlParams = new URLSearchParams(window.location.search);
            let effectiveSize = String(s.currentSize ?? s.defaultPageSize ?? 25);

            if (urlParams.has('size')) {
                effectiveSize = urlParams.get('size');
            } else if (s.pageSizeKey) {
                try {
                    const saved = localStorage.getItem(s.pageSizeKey);
                    if (saved && (s.validPageSizes ?? [10, 25, 50, 100]).map(String).includes(saved)) {
                        effectiveSize = saved;
                    }
                } catch(e) {}
            }

            const needsSizeRestore = !urlParams.has('size')
                && effectiveSize !== String(s.defaultPageSize ?? 25);

            let savedFilters = null;
            if (!s.filtersActive && s.filtersKey) {
                try {
                    const raw = localStorage.getItem(s.filtersKey);
                    if (raw) savedFilters = JSON.parse(raw);
                } catch(e) {}
            }
            const needsFilterRestore = savedFilters
                && Object.values(savedFilters).some(v => Array.isArray(v) && v.length > 0);

            if (needsSizeRestore || needsFilterRestore) {
                let url;
                if (config.filterPanel?.buildUrl) {
                    url = config.filterPanel.buildUrl(savedFilters || {}, effectiveSize);
                } else {
                    const u = new URL(window.location.href);
                    u.searchParams.set('size', effectiveSize);
                    u.searchParams.set('page', '1');
                    url = u.toString();
                }
                window.location.href = url;
                return;
            }
        }

        // --- Filter panel ---
        if (config.filterPanel) {
            const fp = config.filterPanel;
            const toggleEl = fp.toggleBtn ? document.querySelector(fp.toggleBtn) : null;
            const panelEl = fp.panel ? document.querySelector(fp.panel) : null;
            const chevronEl = fp.chevron ? document.querySelector(fp.chevron) : null;

            let collapsed = !(config.storage?.filtersActive);
            if (config.storage?.collapseKey) {
                try {
                    const saved = localStorage.getItem(config.storage.collapseKey);
                    if (saved !== null) collapsed = saved === '1';
                } catch(e) {}
            }

            if (panelEl && chevronEl) {
                panelEl.classList.toggle('hidden', collapsed);
                chevronEl.style.transform = collapsed ? '' : 'rotate(180deg)';
            }

            if (toggleEl && panelEl && chevronEl) {
                toggleEl.addEventListener('click', () => {
                    const isHidden = panelEl.classList.contains('hidden');
                    panelEl.classList.toggle('hidden', !isHidden);
                    chevronEl.style.transform = isHidden ? 'rotate(180deg)' : '';
                    if (config.storage?.collapseKey) {
                        try {
                            localStorage.setItem(config.storage.collapseKey, isHidden ? '0' : '1');
                        } catch(e) {}
                    }
                });
            }

            const applyEl = fp.applyBtn ? document.querySelector(fp.applyBtn) : null;
            if (applyEl && fp.getState && fp.buildUrl) {
                applyEl.addEventListener('click', () => {
                    const state = fp.getState();
                    const size = config.storage?.currentSize ?? config.storage?.defaultPageSize ?? 25;
                    const url = fp.buildUrl(state, size);
                    if (config.storage?.filtersKey) {
                        try { localStorage.setItem(config.storage.filtersKey, JSON.stringify(state)); } catch(e) {}
                    }
                    window.location.href = url;
                });
            }

            if (fp.clearSelectors && config.storage?.filtersKey) {
                document.querySelectorAll(fp.clearSelectors).forEach((el) => {
                    el.addEventListener('click', () => {
                        try { localStorage.removeItem(config.storage.filtersKey); } catch(e) {}
                    });
                });
            }
        }

        // --- Page size selector ---
        if (config.pageSizeSelector) {
            document.querySelectorAll(config.pageSizeSelector).forEach((select) => {
                select.addEventListener('change', function() {
                    const val = this.value;
                    if (config.storage?.pageSizeKey) {
                        try { localStorage.setItem(config.storage.pageSizeKey, val); } catch(e) {}
                    }
                    let url;
                    if (config.filterPanel?.buildUrl && config.filterPanel?.getState) {
                        url = config.filterPanel.buildUrl(config.filterPanel.getState(), val);
                    } else {
                        const u = new URL(window.location.href);
                        u.searchParams.set('size', val);
                        u.searchParams.set('page', '1');
                        url = u.toString();
                    }
                    window.location.href = url;
                });
            });
        }

        // --- Multiselect ---
        if (config.multiselect) {
            const ms = config.multiselect;
            const barEl = ms.actionBar ? document.querySelector(ms.actionBar) : null;
            const countEl = ms.countDisplay ? document.querySelector(ms.countDisplay) : null;
            const selectAllEl = ms.selectAll ? document.querySelector(ms.selectAll) : null;

            const updateActionBar = () => {
                if (!barEl) return;
                const checked = document.querySelectorAll(`${ms.rowCheckboxSelector}:checked`);
                barEl.classList.toggle('hidden', checked.length === 0);
                if (countEl) countEl.textContent = checked.length;
            };

            if (selectAllEl) {
                selectAllEl.addEventListener('change', function() {
                    document.querySelectorAll(ms.rowCheckboxSelector).forEach((cb) => {
                        cb.checked = this.checked;
                    });
                    updateActionBar();
                });
            }

            document.querySelectorAll(ms.rowCheckboxSelector).forEach((cb) => {
                cb.addEventListener('change', updateActionBar);
            });

            document.querySelectorAll('tbody tr').forEach((row) => {
                const cb = row.querySelector(ms.rowCheckboxSelector);
                if (!cb) return;
                row.style.cursor = 'pointer';
                row.addEventListener('click', (e) => {
                    if (e.target.closest('a, input, button')) return;
                    cb.checked = !cb.checked;
                    updateActionBar();
                });
            });

            if (barEl) WeftUtils.stickyActionBar(barEl);

            if (ms.actions) {
                ms.actions.forEach((action) => {
                    const btnEl = action.selector ? document.querySelector(action.selector) : null;
                    if (!btnEl) return;
                    btnEl.addEventListener('click', (e) => {
                        e.preventDefault();
                        const selectedIds = Array.from(
                            document.querySelectorAll(`${ms.rowCheckboxSelector}:checked`)
                        ).map(cb => cb.value);
                        if (action.destructive || action.confirmMessage) {
                            WeftUtils.confirm(
                                action.confirmMessage || 'Are you sure?',
                                () => action.callback(selectedIds),
                                { destructive: !!action.destructive }
                            );
                        } else {
                            action.callback(selectedIds);
                        }
                    });
                });
            }

            // --- Select All Matching ---
            if (ms.selectAllMatching) {
                const sam = ms.selectAllMatching;
                const samBtn = sam.btn ? document.querySelector(sam.btn) : null;
                const samIndicator = sam.indicator ? document.querySelector(sam.indicator) : null;
                const modeField = sam.modeField ? document.querySelector(sam.modeField) : null;
                const criteriaField = sam.criteriaField ? document.querySelector(sam.criteriaField) : null;
                let allMatchingActive = false;

                const resetSelectAllMatching = () => {
                    allMatchingActive = false;
                    if (samBtn) samBtn.classList.add('hidden');
                    if (samIndicator) samIndicator.classList.add('hidden');
                    if (modeField) modeField.value = 'ids';
                    if (criteriaField) criteriaField.value = '';
                };

                const showSelectAllMatchingPrompt = () => {
                    if (!sam.filtersActive && !sam.filterCriteria?.search) return;
                    if (sam.totalCount <= sam.pageCount) return;
                    const allChecked = document.querySelectorAll(ms.rowCheckboxSelector);
                    const allCheckedCount = document.querySelectorAll(`${ms.rowCheckboxSelector}:checked`).length;
                    if (allCheckedCount > 0 && allCheckedCount === allChecked.length && !allMatchingActive) {
                        if (samBtn) samBtn.classList.remove('hidden');
                    } else if (!allMatchingActive) {
                        if (samBtn) samBtn.classList.add('hidden');
                    }
                };

                // Override updateActionBar to also handle select-all-matching
                const origUpdate = updateActionBar;
                const enhancedUpdate = () => {
                    if (allMatchingActive) return;
                    origUpdate();
                    showSelectAllMatchingPrompt();
                };

                // Re-bind checkbox events with enhanced handler
                if (selectAllEl) {
                    selectAllEl.addEventListener('change', () => {
                        if (!selectAllEl.checked) resetSelectAllMatching();
                        enhancedUpdate();
                    });
                }
                document.querySelectorAll(ms.rowCheckboxSelector).forEach((cb) => {
                    cb.addEventListener('change', () => {
                        resetSelectAllMatching();
                        enhancedUpdate();
                    });
                });

                if (samBtn) {
                    samBtn.addEventListener('click', () => {
                        allMatchingActive = true;
                        samBtn.classList.add('hidden');
                        if (samIndicator) samIndicator.classList.remove('hidden');
                        if (countEl) countEl.textContent = sam.totalCount;
                        if (modeField) modeField.value = 'filter';
                        if (criteriaField) criteriaField.value = JSON.stringify(sam.filterCriteria);
                    });
                }
            }
        }
    },

    // Internal: callback storage for confirm modal
    _confirmCallback: null,

    /**
     * Initialize confirm modal event handlers.
     * Called automatically when DOM is ready.
     */
    _initConfirmModal() {
        const modal = document.getElementById('weft-confirm-modal');
        const cancelBtn = document.getElementById('weft-confirm-cancel');
        const okBtn = document.getElementById('weft-confirm-ok');

        if (!modal) return;

        const closeModal = () => {
            WeftUtils.hideModal('weft-confirm-modal');
            WeftUtils._confirmCallback = null;
        };

        const handleConfirm = () => {
            const callback = WeftUtils._confirmCallback;
            closeModal();
            if (callback) callback();
        };

        if (cancelBtn) cancelBtn.addEventListener('click', closeModal);
        if (okBtn) okBtn.addEventListener('click', handleConfirm);

        // Close on ESC
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && !modal.classList.contains('hidden')) closeModal();
        });

        // Close on backdrop click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal();
        });
    }
};

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', WeftUtils._initConfirmModal);
} else {
    WeftUtils._initConfirmModal();
}
