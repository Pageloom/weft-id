"""Tests for CSP nonce implementation.

This module tests:
1. CSP nonce generation and idempotency
2. CSP header contains nonce (not unsafe-inline)
3. Backstop test ensuring all template script tags have nonce attributes
"""

import os
import re
from pathlib import Path

import pytest

from utils.csp_nonce import generate_csp_nonce, get_csp_nonce


@pytest.fixture(autouse=True)
def setup_app_directory():
    """Change to app directory so templates can be found."""
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


class TestCspNonceGeneration:
    """Tests for the CSP nonce utility functions."""

    def test_generate_csp_nonce_returns_string(self):
        """Nonce generation returns a non-empty string."""
        nonce = generate_csp_nonce()
        assert isinstance(nonce, str)
        assert len(nonce) > 0

    def test_generate_csp_nonce_is_unique(self):
        """Each call to generate_csp_nonce returns a unique value."""
        nonce1 = generate_csp_nonce()
        nonce2 = generate_csp_nonce()
        assert nonce1 != nonce2

    def test_generate_csp_nonce_is_url_safe(self):
        """Nonce is URL-safe (no special characters that need escaping)."""
        nonce = generate_csp_nonce()
        # URL-safe base64 uses only alphanumeric, hyphen, and underscore
        assert re.match(r"^[A-Za-z0-9_-]+$", nonce)

    def test_get_csp_nonce_creates_nonce_on_request(self):
        """get_csp_nonce creates a nonce and attaches it to request.state."""
        from unittest.mock import MagicMock

        # Create a mock request with empty state
        mock_request = MagicMock()
        mock_request.state = MagicMock(spec=[])

        # First call should create nonce
        nonce = get_csp_nonce(mock_request)
        assert isinstance(nonce, str)
        assert len(nonce) > 0

    def test_get_csp_nonce_is_idempotent(self):
        """Multiple calls with same request return same nonce."""
        from unittest.mock import MagicMock

        # Create a mock request with state that persists
        mock_request = MagicMock()
        mock_request.state = MagicMock(spec=[])

        # First call creates nonce
        nonce1 = get_csp_nonce(mock_request)

        # Now the state has csp_nonce, simulate this
        mock_request.state.csp_nonce = nonce1

        # Second call should return same nonce
        nonce2 = get_csp_nonce(mock_request)
        assert nonce1 == nonce2


class TestCspHeaderInResponse:
    """Tests for CSP header in HTTP responses."""

    def test_login_page_has_csp_with_nonce(self, client, test_tenant_host):
        """Login page CSP header uses nonce, not unsafe-inline."""
        response = client.get("/login", headers={"Host": test_tenant_host})

        # Check CSP header exists
        csp = response.headers.get("Content-Security-Policy")
        assert csp is not None

        # Check nonce is present in script-src
        assert "'nonce-" in csp
        assert "script-src" in csp

        # Extract nonce from CSP
        nonce_match = re.search(r"'nonce-([A-Za-z0-9_-]+)'", csp)
        assert nonce_match is not None
        nonce = nonce_match.group(1)

        # Check nonce is in the HTML
        assert f'nonce="{nonce}"' in response.text

    def test_csp_does_not_have_unsafe_inline_for_scripts(self, client, test_tenant_host):
        """CSP script-src should not contain unsafe-inline when nonce is used."""
        response = client.get("/login", headers={"Host": test_tenant_host})
        csp = response.headers.get("Content-Security-Policy")

        # Parse script-src directive
        script_src_match = re.search(r"script-src\s+([^;]+)", csp)
        assert script_src_match is not None
        script_src = script_src_match.group(1)

        # Should have nonce, not unsafe-inline
        assert "'nonce-" in script_src
        assert "'unsafe-inline'" not in script_src


class TestTemplateScriptNonceBackstop:
    """Backstop test to ensure all template script tags have nonce attributes.

    This test scans all HTML templates and verifies that every <script> tag
    has a nonce="{{ csp_nonce }}" attribute. This prevents regressions where
    new inline scripts are added without CSP nonce protection.
    """

    TEMPLATES_DIR = Path(__file__).parent.parent / "app" / "templates"

    # Pattern to match <script> tags without nonce attribute
    SCRIPT_WITHOUT_NONCE = re.compile(r"<script(?![^>]*\bnonce=)[^>]*>", re.IGNORECASE)

    # Pattern to match <script> tags with nonce attribute
    SCRIPT_WITH_NONCE = re.compile(
        r'<script\s+nonce="\{\{\s*csp_nonce\s*\}\}"[^>]*>', re.IGNORECASE
    )

    def test_all_script_tags_have_nonce(self):
        """All <script> tags in templates must have nonce="{{ csp_nonce }}"."""
        violations = []

        for template_path in self.TEMPLATES_DIR.glob("**/*.html"):
            content = template_path.read_text()

            # Find all script tags without nonce
            for match in self.SCRIPT_WITHOUT_NONCE.finditer(content):
                # Get line number for better error messages
                line_num = content[: match.start()].count("\n") + 1
                violations.append(
                    f"{template_path.relative_to(self.TEMPLATES_DIR)}:{line_num}: "
                    f"Script tag missing nonce attribute: {match.group()[:50]}..."
                )

        if violations:
            pytest.fail(
                f"Found {len(violations)} script tag(s) without nonce attribute:\n"
                + "\n".join(violations)
            )

    def test_script_tags_use_correct_nonce_variable(self):
        """All script nonce attributes use the csp_nonce template variable."""
        violations = []

        for template_path in self.TEMPLATES_DIR.glob("**/*.html"):
            content = template_path.read_text()

            # Find script tags with nonce but wrong variable
            nonce_pattern = re.compile(r'<script\s+nonce="([^"]*)"', re.IGNORECASE)
            for match in nonce_pattern.finditer(content):
                nonce_value = match.group(1)
                # Should be {{ csp_nonce }} with possible whitespace variations
                if not re.match(r"\{\{\s*csp_nonce\s*\}\}", nonce_value):
                    line_num = content[: match.start()].count("\n") + 1
                    violations.append(
                        f"{template_path.relative_to(self.TEMPLATES_DIR)}:{line_num}: "
                        f"Script nonce uses wrong variable: {nonce_value}"
                    )

        if violations:
            pytest.fail(
                f"Found {len(violations)} script tag(s) with incorrect nonce variable:\n"
                + "\n".join(violations)
            )

    def test_templates_directory_exists(self):
        """Sanity check that templates directory exists."""
        assert self.TEMPLATES_DIR.exists(), f"Templates directory not found: {self.TEMPLATES_DIR}"
        assert self.TEMPLATES_DIR.is_dir()

    def test_templates_have_script_tags(self):
        """Sanity check that we're actually finding script tags."""
        script_count = 0
        for template_path in self.TEMPLATES_DIR.glob("**/*.html"):
            content = template_path.read_text()
            script_count += len(self.SCRIPT_WITH_NONCE.findall(content))

        # We know there are at least 17 script tags across templates
        assert script_count >= 17, f"Expected at least 17 script tags, found {script_count}"
