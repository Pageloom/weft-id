"""Tests for datetime formatting utilities."""

from datetime import date, datetime
from zoneinfo import ZoneInfo

from app.utils.datetime_format import (
    create_datetime_formatter,
    create_relative_date_formatter,
    format_datetime,
    format_relative_date,
)


def test_format_datetime_basic():
    """Test basic datetime formatting."""
    dt = datetime(2025, 10, 19, 14, 30, 0, tzinfo=ZoneInfo("UTC"))
    result = format_datetime(dt)

    # Should return a formatted string
    assert isinstance(result, str)
    assert len(result) > 0
    # Should contain date components
    assert "2025" in result or "25" in result


def test_format_datetime_with_timezone_conversion():
    """Test datetime formatting with timezone conversion."""
    # Create UTC datetime
    dt = datetime(2025, 10, 19, 14, 30, 0, tzinfo=ZoneInfo("UTC"))

    # Format in New York time (UTC-5 in October)
    result = format_datetime(dt, timezone="America/New_York")

    # Should contain formatted datetime
    assert isinstance(result, str)
    assert len(result) > 0


def test_format_datetime_with_different_locales():
    """Test datetime formatting with different locales."""
    dt = datetime(2025, 10, 19, 14, 30, 0, tzinfo=ZoneInfo("UTC"))

    result_us = format_datetime(dt, locale="en_US")
    result_sv = format_datetime(dt, locale="sv_SE")

    # Both should be strings but potentially formatted differently
    assert isinstance(result_us, str)
    assert isinstance(result_sv, str)
    assert len(result_us) > 0
    assert len(result_sv) > 0


def test_format_datetime_naive_datetime():
    """Test formatting naive datetime (assumes UTC)."""
    dt_naive = datetime(2025, 10, 19, 14, 30, 0)  # noqa: DTZ001 - Testing naive datetime handling

    result = format_datetime(dt_naive)

    # Should still format successfully
    assert isinstance(result, str)
    assert len(result) > 0


def test_format_datetime_none():
    """Test formatting None returns empty string."""
    result = format_datetime(None)
    assert result == ""


def test_format_datetime_invalid_timezone():
    """Test that invalid timezone falls back gracefully."""
    dt = datetime(2025, 10, 19, 14, 30, 0, tzinfo=ZoneInfo("UTC"))

    # Invalid timezone should fall back to UTC
    result = format_datetime(dt, timezone="Invalid/Timezone")

    # Should still return a formatted string
    assert isinstance(result, str)
    assert len(result) > 0


def test_format_datetime_invalid_locale():
    """Test that invalid locale falls back to ISO format."""
    dt = datetime(2025, 10, 19, 14, 30, 0, tzinfo=ZoneInfo("UTC"))

    # Invalid locale should fall back to ISO format
    result = format_datetime(dt, locale="invalid_LOCALE")

    # Should return ISO format: YYYY-MM-DD HH:MM:SS
    assert isinstance(result, str)
    assert "2025" in result
    assert "10" in result
    assert "19" in result


def test_create_datetime_formatter():
    """Test datetime formatter factory."""
    formatter = create_datetime_formatter("America/New_York", "en_US")

    # Should return a callable
    assert callable(formatter)

    # Should format datetimes
    dt = datetime(2025, 10, 19, 14, 30, 0, tzinfo=ZoneInfo("UTC"))
    result = formatter(dt)

    assert isinstance(result, str)
    assert len(result) > 0


def test_create_datetime_formatter_no_timezone():
    """Test datetime formatter factory with no timezone."""
    formatter = create_datetime_formatter(None, "en_US")

    assert callable(formatter)

    dt = datetime(2025, 10, 19, 14, 30, 0, tzinfo=ZoneInfo("UTC"))
    result = formatter(dt)

    assert isinstance(result, str)
    assert len(result) > 0


def test_create_datetime_formatter_default_locale():
    """Test datetime formatter factory with default locale."""
    formatter = create_datetime_formatter("UTC")

    assert callable(formatter)

    dt = datetime(2025, 10, 19, 14, 30, 0, tzinfo=ZoneInfo("UTC"))
    result = formatter(dt)

    assert isinstance(result, str)
    assert len(result) > 0


def test_format_datetime_timezone_with_dst():
    """Test formatting with timezone that has DST."""
    # Winter datetime (EST, UTC-5)
    dt_winter = datetime(2025, 1, 15, 12, 0, 0, tzinfo=ZoneInfo("UTC"))
    result_winter = format_datetime(dt_winter, timezone="America/New_York")

    # Summer datetime (EDT, UTC-4)
    dt_summer = datetime(2025, 7, 15, 12, 0, 0, tzinfo=ZoneInfo("UTC"))
    result_summer = format_datetime(dt_summer, timezone="America/New_York")

    # Both should format successfully
    assert isinstance(result_winter, str)
    assert isinstance(result_summer, str)
    assert len(result_winter) > 0
    assert len(result_summer) > 0


def test_format_datetime_different_timezones():
    """Test formatting the same datetime in different timezones."""
    dt = datetime(2025, 10, 19, 12, 0, 0, tzinfo=ZoneInfo("UTC"))

    result_utc = format_datetime(dt, timezone="UTC")
    result_tokyo = format_datetime(dt, timezone="Asia/Tokyo")
    result_la = format_datetime(dt, timezone="America/Los_Angeles")

    # All should format successfully
    assert isinstance(result_utc, str)
    assert isinstance(result_tokyo, str)
    assert isinstance(result_la, str)


# ============================================================================
# Relative date formatting tests
# ============================================================================


class TestFormatRelativeDate:
    """Tests for format_relative_date()."""

    def test_none_returns_never(self):
        result = format_relative_date(None)
        assert result == ("Never", "")

    def test_today(self):
        ref = date(2025, 6, 15)
        dt = datetime(2025, 6, 15, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, exact = format_relative_date(dt, reference=ref)
        assert rel == "Today"
        assert len(exact) > 0

    def test_yesterday(self):
        ref = date(2025, 6, 15)
        dt = datetime(2025, 6, 14, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, exact = format_relative_date(dt, reference=ref)
        assert rel == "Yesterday"

    def test_days_ago(self):
        ref = date(2025, 6, 15)
        dt = datetime(2025, 6, 12, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "3 days ago"

    def test_boundary_13_days(self):
        ref = date(2025, 6, 15)
        dt = datetime(2025, 6, 2, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "13 days ago"

    def test_boundary_14_days_switches_to_weeks(self):
        ref = date(2025, 6, 15)
        dt = datetime(2025, 6, 1, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "2 weeks ago"

    def test_weeks_ago(self):
        ref = date(2025, 6, 15)
        dt = datetime(2025, 5, 25, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "3 weeks ago"

    def test_boundary_60_days_switches_to_months(self):
        ref = date(2025, 6, 15)
        dt = datetime(2025, 4, 16, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "2 months ago"

    def test_months_ago(self):
        ref = date(2025, 6, 15)
        dt = datetime(2025, 2, 15, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "4 months ago"

    def test_boundary_365_days_switches_to_years(self):
        ref = date(2025, 6, 15)
        dt = datetime(2024, 6, 14, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "1 year ago"

    def test_years_ago(self):
        ref = date(2025, 6, 15)
        dt = datetime(2023, 1, 1, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "2 years ago"

    def test_future_tomorrow(self):
        ref = date(2025, 6, 15)
        dt = datetime(2025, 6, 16, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "Tomorrow"

    def test_future_days(self):
        ref = date(2025, 6, 15)
        dt = datetime(2025, 6, 20, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "in 5 days"

    def test_future_boundary_13_days(self):
        ref = date(2025, 6, 15)
        dt = datetime(2025, 6, 28, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "in 13 days"

    def test_future_boundary_14_days_switches_to_weeks(self):
        ref = date(2025, 6, 15)
        dt = datetime(2025, 6, 29, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "in 2 weeks"

    def test_future_weeks(self):
        ref = date(2025, 6, 15)
        dt = datetime(2025, 7, 6, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "in 3 weeks"

    def test_future_boundary_60_days_switches_to_months(self):
        ref = date(2025, 6, 15)
        dt = datetime(2025, 8, 14, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "in 2 months"

    def test_future_months(self):
        ref = date(2025, 6, 15)
        dt = datetime(2025, 10, 15, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "in 4 months"

    def test_future_boundary_365_days_switches_to_years(self):
        ref = date(2025, 6, 15)
        dt = datetime(2026, 6, 16, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "in 1 year"

    def test_future_years(self):
        ref = date(2025, 6, 15)
        dt = datetime(2027, 12, 1, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "in 2 years"

    def test_timezone_edge_case(self):
        """A datetime that is 'yesterday' in UTC but 'today' in a +12 timezone."""
        ref = date(2025, 6, 15)
        # 23:30 UTC on June 14 = 11:30 June 15 in Pacific/Auckland (+12)
        dt = datetime(2025, 6, 14, 23, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel_utc, _ = format_relative_date(dt, reference=ref)
        rel_nz, _ = format_relative_date(dt, timezone="Pacific/Auckland", reference=ref)
        assert rel_utc == "Yesterday"
        assert rel_nz == "Today"

    def test_exact_text_uses_babel_format(self):
        ref = date(2025, 6, 15)
        dt = datetime(2025, 6, 15, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        _, exact = format_relative_date(dt, locale="en_US", reference=ref)
        assert "2025" in exact or "25" in exact

    def test_1_week_singular(self):
        ref = date(2025, 6, 15)
        # Exactly 14 days ago = 2 weeks, so test 7 days = still days range
        dt = datetime(2025, 6, 8, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, _ = format_relative_date(dt, reference=ref)
        assert rel == "7 days ago"


class TestCreateRelativeDateFormatter:
    """Tests for create_relative_date_formatter()."""

    def test_returns_callable(self):
        formatter = create_relative_date_formatter("UTC", "en_US")
        assert callable(formatter)

    def test_formats_none(self):
        formatter = create_relative_date_formatter("UTC", "en_US")
        rel, exact = formatter(None)
        assert rel == "Never"
        assert exact == ""

    def test_formats_datetime(self):
        formatter = create_relative_date_formatter("UTC", "en_US")
        dt = datetime(2025, 6, 15, 10, 30, 0, tzinfo=ZoneInfo("UTC"))
        rel, exact = formatter(dt)
        assert isinstance(rel, str)
        assert isinstance(exact, str)
        assert len(exact) > 0
