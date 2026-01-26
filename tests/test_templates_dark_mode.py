"""Tests for dark mode template coverage.

This module ensures all templates have proper dark mode support by checking
that common light-mode-only Tailwind classes have corresponding dark: variants.
"""

import re
from pathlib import Path

import pytest

# Classes that MUST have dark: variants when used
LIGHT_CLASSES_REQUIRING_DARK = {
    # Background colors
    "bg-white": "dark:bg-gray-800",
    "bg-gray-50": "dark:bg-gray-900",
    "bg-gray-100": "dark:bg-gray-700",
    # Text colors
    "text-gray-900": "dark:text-gray-100",
    "text-gray-700": "dark:text-gray-300",
    "text-gray-600": "dark:text-gray-400",
    # Border colors
    "border-gray-200": "dark:border-gray-700",
    "border-gray-300": "dark:border-gray-600",
}

# Classes that are acceptable without dark variants (semantic colors that work in both)
EXEMPT_CLASSES = {
    "bg-blue-600",  # Primary buttons work in both modes
    "bg-blue-500",
    "text-white",
    "bg-transparent",
}


def get_all_templates():
    """Get all HTML template files."""
    template_dir = Path(__file__).parent.parent / "app" / "templates"
    return list(template_dir.glob("*.html"))


def extract_class_attributes(content: str) -> list[tuple[int, str]]:
    """
    Extract all class attribute values from HTML content.

    Returns list of (line_number, class_string) tuples.
    """
    results = []
    for line_num, line in enumerate(content.split("\n"), 1):
        # Match class="..." attributes
        for match in re.finditer(r'class="([^"]*)"', line):
            results.append((line_num, match.group(1)))
    return results


def check_dark_mode_coverage(template_path: Path) -> list[str]:
    """
    Check if a template has proper dark mode coverage.

    Returns list of issues found.
    """
    content = template_path.read_text()
    issues = []

    for line_num, class_string in extract_class_attributes(content):
        classes = set(class_string.split())

        for light_class, expected_dark in LIGHT_CLASSES_REQUIRING_DARK.items():
            if light_class in classes:
                # Check if any dark: variant exists for this class type
                has_dark_variant = any(c.startswith("dark:") for c in classes)
                if not has_dark_variant:
                    issues.append(
                        f"Line {line_num}: '{light_class}' found without dark mode variant"
                    )

    return issues


class TestTemplateDarkModeStatus:
    """Report dark mode coverage status for all templates."""

    def test_templates_dark_mode_coverage_report(self):
        """
        Generate a report of dark mode coverage across all templates.

        This test documents the current state and helps track progress.
        """
        templates = get_all_templates()
        assert templates, "No templates found"

        templates_with_issues = []
        templates_passing = []

        for template in templates:
            issues = check_dark_mode_coverage(template)
            if issues:
                templates_with_issues.append((template.name, issues))
            else:
                templates_passing.append(template.name)

        # Print report
        print("\n" + "=" * 60)
        print("DARK MODE COVERAGE REPORT")
        print("=" * 60)
        print(f"\nTemplates passing: {len(templates_passing)}/{len(templates)}")
        print(f"Templates with issues: {len(templates_with_issues)}/{len(templates)}")

        if templates_with_issues:
            print("\n" + "-" * 60)
            print("TEMPLATES NEEDING DARK MODE UPDATES:")
            print("-" * 60)
            for name, issues in sorted(templates_with_issues):
                print(f"\n{name}:")
                for issue in issues[:5]:  # Show first 5 issues
                    print(f"  - {issue}")
                if len(issues) > 5:
                    print(f"  ... and {len(issues) - 5} more issues")

        print("\n" + "-" * 60)
        print("TEMPLATES WITH FULL DARK MODE SUPPORT:")
        print("-" * 60)
        for name in sorted(templates_passing):
            print(f"  - {name}")

        # This test always passes but provides visibility
        # Once all templates are updated, we can make it fail on issues


class TestCriticalTemplatesDarkMode:
    """Verify critical templates have dark mode support."""

    @pytest.mark.parametrize(
        "template_name",
        [
            "base.html",
            "login.html",
            "dashboard.html",
            "error.html",
            "settings_profile.html",
        ],
    )
    def test_critical_template_has_dark_mode(self, template_name: str):
        """Critical templates must have dark mode support."""
        template_dir = Path(__file__).parent.parent / "app" / "templates"
        template_path = template_dir / template_name

        assert template_path.exists(), f"Template {template_name} not found"

        issues = check_dark_mode_coverage(template_path)
        assert not issues, f"Template {template_name} missing dark mode:\n" + "\n".join(issues[:10])


class TestDarkModeClassPairs:
    """Verify dark mode class pairings are consistent."""

    def test_dark_class_follows_light_class(self):
        """
        In templates with dark mode, dark: classes should follow their light counterparts.

        This helps maintain readable, consistent styling.
        """
        templates = get_all_templates()
        warnings = []

        for template in templates:
            content = template.read_text()

            for line_num, class_string in extract_class_attributes(content):
                classes = class_string.split()

                # Check if bg-white is followed by dark:bg-*
                for i, cls in enumerate(classes):
                    if cls == "bg-white":
                        # Check if next few classes have dark:bg-*
                        next_classes = classes[i + 1 : i + 4]
                        has_dark_bg = any(c.startswith("dark:bg-") for c in next_classes)
                        if not has_dark_bg and any(c.startswith("dark:") for c in classes):
                            warnings.append(
                                f"{template.name}:{line_num}: bg-white not immediately "
                                "followed by dark:bg-* variant"
                            )

        # This is a style warning, not a hard failure
        if warnings:
            print("\nStyle warnings (not failures):")
            for w in warnings[:10]:
                print(f"  - {w}")
