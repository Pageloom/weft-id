"""Tests for event type definitions and lockfile validation.

These tests ensure:
1. All event types in the lockfile exist in EVENT_TYPE_DESCRIPTIONS (no deletions)
2. All EVENT_TYPE_DESCRIPTIONS keys exist in the lockfile (explicit acknowledgment)
3. The log_event function rejects unknown event types
"""

from pathlib import Path
from unittest.mock import patch

import pytest
from constants.event_types import EVENT_TYPE_DESCRIPTIONS, get_event_description
from services.event_log import log_event

# Path to the lockfile
LOCKFILE_PATH = Path(__file__).parent.parent / "app" / "constants" / "event_types.lock"


def _read_lockfile() -> set[str]:
    """Read all event types from the lockfile."""
    with open(LOCKFILE_PATH) as f:
        return {line.strip() for line in f if line.strip()}


class TestEventTypeDescriptions:
    """Tests for the EVENT_TYPE_DESCRIPTIONS constant."""

    def test_all_event_types_have_descriptions(self):
        """Every event type should have a non-empty description."""
        for event_type, description in EVENT_TYPE_DESCRIPTIONS.items():
            assert description, f"Event type '{event_type}' has empty description"
            assert isinstance(description, str), (
                f"Event type '{event_type}' description is not a string"
            )

    def test_get_event_description_returns_description(self):
        """get_event_description should return the description for known types."""
        assert get_event_description("user_created") == "User account created"
        assert get_event_description("login_failed") == "Login attempt failed"

    def test_get_event_description_returns_none_for_unknown(self):
        """get_event_description should return None for unknown types."""
        assert get_event_description("unknown_event_type") is None
        assert get_event_description("") is None


class TestLockfileValidation:
    """Tests that ensure the lockfile stays in sync with EVENT_TYPE_DESCRIPTIONS."""

    def test_lockfile_exists(self):
        """The lockfile should exist."""
        assert LOCKFILE_PATH.exists(), f"Lockfile not found at {LOCKFILE_PATH}"

    def test_lockfile_entries_exist_in_descriptions(self):
        """All lockfile entries must exist in EVENT_TYPE_DESCRIPTIONS.

        This prevents accidental deletion of event types. Event types must never
        be deleted or renamed once added.
        """
        lockfile_types = _read_lockfile()
        description_types = set(EVENT_TYPE_DESCRIPTIONS.keys())

        missing_from_descriptions = lockfile_types - description_types
        assert not missing_from_descriptions, (
            f"Event types in lockfile but missing from EVENT_TYPE_DESCRIPTIONS "
            f"(event types must never be deleted): {sorted(missing_from_descriptions)}"
        )

    def test_all_descriptions_in_lockfile(self):
        """All EVENT_TYPE_DESCRIPTIONS keys must exist in lockfile.

        This forces explicit acknowledgment when adding new event types.
        To add a new event type:
        1. Add it to EVENT_TYPE_DESCRIPTIONS with a description
        2. Add it to event_types.lock (run this test to see what's missing)
        """
        lockfile_types = _read_lockfile()
        description_types = set(EVENT_TYPE_DESCRIPTIONS.keys())

        missing_from_lockfile = description_types - lockfile_types
        assert not missing_from_lockfile, (
            f"Event types in EVENT_TYPE_DESCRIPTIONS but missing from lockfile "
            f"(add these to app/constants/event_types.lock): {sorted(missing_from_lockfile)}"
        )

    def test_lockfile_is_sorted(self):
        """Lockfile should be sorted alphabetically for easy maintenance."""
        with open(LOCKFILE_PATH) as f:
            lines = [line.strip() for line in f if line.strip()]

        sorted_lines = sorted(lines)
        assert lines == sorted_lines, (
            "Lockfile should be sorted alphabetically. "
            f"First unsorted line: {next(a for a, b in zip(lines, sorted_lines) if a != b)}"
        )


class TestLogEventValidation:
    """Tests for log_event event type validation."""

    def test_log_event_rejects_unknown_event_type(self):
        """log_event should raise ValueError for unknown event types."""
        with pytest.raises(ValueError) as exc_info:
            log_event(
                tenant_id="test-tenant",
                actor_user_id="test-user",
                artifact_type="user",
                artifact_id="test-artifact",
                event_type="this_event_type_does_not_exist",
            )

        assert "Unknown event type" in str(exc_info.value)
        assert "this_event_type_does_not_exist" in str(exc_info.value)
        assert "app/constants/event_types.py" in str(exc_info.value)

    def test_log_event_accepts_known_event_type(self):
        """log_event should accept known event types (validation passes).

        Note: This test mocks the database and context to isolate the validation.
        """
        with (
            patch("services.event_log.get_request_context") as mock_ctx,
            patch("services.event_log.database.event_log.create_event") as mock_create,
            patch("services.event_log.track_activity"),
        ):
            mock_ctx.return_value = {
                "remote_address": "127.0.0.1",
                "user_agent": "test",
                "device": "desktop",
                "session_id_hash": "abc123",
            }

            # Should not raise
            log_event(
                tenant_id="test-tenant",
                actor_user_id="test-user",
                artifact_type="user",
                artifact_id="test-artifact",
                event_type="user_created",
            )

            # Verify the event was passed to the database
            mock_create.assert_called_once()
            call_kwargs = mock_create.call_args.kwargs
            assert call_kwargs["event_type"] == "user_created"
