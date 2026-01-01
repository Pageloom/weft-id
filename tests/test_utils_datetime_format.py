"""Tests for datetime formatting utilities."""

from datetime import datetime
from zoneinfo import ZoneInfo

from app.utils.datetime_format import create_datetime_formatter, format_datetime


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
