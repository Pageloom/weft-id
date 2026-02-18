/**
 * Weft-ID JavaScript Utilities
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
    copyToClipboard: function(text, feedbackEl) {
        return navigator.clipboard.writeText(text).then(function() {
            if (feedbackEl) {
                var original = feedbackEl.textContent;
                feedbackEl.textContent = 'Copied!';
                setTimeout(function() {
                    feedbackEl.textContent = original;
                }, 2000);
            }
            return true;
        }).catch(function() {
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
    showModal: function(id) {
        var modal = document.getElementById(id);
        if (modal) {
            modal.classList.remove('hidden');
            modal.classList.add('flex');
            // Focus first focusable element
            var focusable = modal.querySelector('input, button, select, textarea, [tabindex]:not([tabindex="-1"])');
            if (focusable) {
                focusable.focus();
            }
        }
    },

    /**
     * Hide a modal by ID.
     *
     * @param {string} id - Modal element ID
     */
    hideModal: function(id) {
        var modal = document.getElementById(id);
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
    confirm: function(message, onConfirm, options) {
        options = options || {};
        var modal = document.getElementById('weft-confirm-modal');
        var messageEl = document.getElementById('weft-confirm-message');
        var cancelBtn = document.getElementById('weft-confirm-cancel');
        var okBtn = document.getElementById('weft-confirm-ok');

        if (!modal || !messageEl || !okBtn) {
            // Fallback to native if modal not present
            if (options.okOnly) {
                alert(message);
                return;
            }
            if (confirm(message) && onConfirm) {
                onConfirm();
            }
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
    detectTimezone: function() {
        return Intl.DateTimeFormat().resolvedOptions().timeZone;
    },

    /**
     * Detect user's locale.
     *
     * @returns {string} - Locale with underscores (e.g., "en_US")
     */
    detectLocale: function() {
        var locale = new Intl.DateTimeFormat().resolvedOptions().locale;
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
    stickyActionBar: function(elementOrId) {
        var el = typeof elementOrId === 'string'
            ? document.getElementById(elementOrId)
            : elementOrId;
        if (!el) return;

        // Sentinel element placed right after the bar to detect stuck state
        var sentinel = document.createElement('div');
        sentinel.style.height = '1px';
        sentinel.style.visibility = 'hidden';
        sentinel.style.pointerEvents = 'none';
        sentinel.style.display = 'none';
        el.parentNode.insertBefore(sentinel, el.nextSibling);

        function applySticky() {
            requestAnimationFrame(function() {
                if (el.classList.contains('hidden')) return;
                el.style.position = 'sticky';
                el.style.bottom = '0';
                el.style.zIndex = '40';
                sentinel.style.display = '';
            });
        }

        function removeSticky() {
            el.style.position = '';
            el.style.bottom = '';
            el.style.zIndex = '';
            el.style.boxShadow = '';
            sentinel.style.display = 'none';
        }

        // IntersectionObserver detects when sentinel scrolls out of view,
        // meaning the bar is stuck at the viewport bottom
        var io = new IntersectionObserver(function(entries) {
            entries.forEach(function(entry) {
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
        var observer = new MutationObserver(function() {
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

    // Internal: callback storage for confirm modal
    _confirmCallback: null,

    /**
     * Initialize confirm modal event handlers.
     * Called automatically when DOM is ready.
     */
    _initConfirmModal: function() {
        var modal = document.getElementById('weft-confirm-modal');
        var cancelBtn = document.getElementById('weft-confirm-cancel');
        var okBtn = document.getElementById('weft-confirm-ok');

        if (!modal) return;

        function closeModal() {
            WeftUtils.hideModal('weft-confirm-modal');
            WeftUtils._confirmCallback = null;
        }

        function handleConfirm() {
            var callback = WeftUtils._confirmCallback;
            closeModal();
            if (callback) {
                callback();
            }
        }

        if (cancelBtn) {
            cancelBtn.addEventListener('click', closeModal);
        }

        if (okBtn) {
            okBtn.addEventListener('click', handleConfirm);
        }

        // Close on ESC
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && !modal.classList.contains('hidden')) {
                closeModal();
            }
        });

        // Close on backdrop click
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                closeModal();
            }
        });
    }
};

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', WeftUtils._initConfirmModal);
} else {
    WeftUtils._initConfirmModal();
}
