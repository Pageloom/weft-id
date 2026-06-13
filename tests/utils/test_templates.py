"""Tests for utils.templates display helpers."""

from utils.templates import display_status


def test_display_status_maps_inactivated_to_deactivated():
    """The stored 'inactivated' enum value renders as the lifecycle term."""
    assert display_status("inactivated") == "Deactivated"


def test_display_status_capitalizes_unmapped_values():
    """Unmapped statuses fall back to a capitalized label."""
    assert display_status("active") == "Active"
    assert display_status("promoted") == "Promoted"
    assert display_status("reactivated") == "Reactivated"


def test_display_status_handles_underscores():
    """Underscored values become spaced, capitalized labels."""
    assert display_status("dead_letter") == "Dead letter"
