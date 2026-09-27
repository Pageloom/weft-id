"""Tests for session regeneration utility."""

import time
from unittest.mock import MagicMock

from utils.session import SESSION_ID_KEY, ensure_session_id, regenerate_session


class TestRegenerateSession:
    """Tests for the regenerate_session function."""

    def test_clears_all_pre_auth_data(self):
        """Test that all pre-authentication data is cleared."""
        mock_request = MagicMock()
        mock_session = MagicMock()
        mock_request.session = mock_session

        regenerate_session(mock_request, "user-123", 3600)

        mock_session.clear.assert_called_once()

    def test_sets_required_session_keys(self):
        """Test that user_id, session_start, and _max_age are set."""
        mock_request = MagicMock()
        mock_session = {}
        mock_request.session = mock_session

        regenerate_session(mock_request, "user-456", 7200)

        assert mock_session["user_id"] == "user-456"
        assert "session_start" in mock_session
        assert mock_session["_max_age"] == 7200

    def test_session_start_is_current_time(self):
        """Test that session_start is approximately current time."""
        mock_request = MagicMock()
        mock_session = {}
        mock_request.session = mock_session

        before = int(time.time())
        regenerate_session(mock_request, "user-789", None)
        after = int(time.time())

        assert before <= mock_session["session_start"] <= after

    def test_max_age_none_for_session_cookie(self):
        """Test that max_age=None is properly set for session cookies."""
        mock_request = MagicMock()
        mock_session = {}
        mock_request.session = mock_session

        regenerate_session(mock_request, "user-123", None)

        assert mock_session["_max_age"] is None

    def test_max_age_integer_for_persistent_session(self):
        """Test that max_age is properly set for persistent sessions."""
        mock_request = MagicMock()
        mock_session = {}
        mock_request.session = mock_session

        regenerate_session(mock_request, "user-123", 86400)

        assert mock_session["_max_age"] == 86400

    def test_additional_data_is_added(self):
        """Test that additional_data is added to session."""
        mock_request = MagicMock()
        mock_session = {}
        mock_request.session = mock_session

        regenerate_session(
            mock_request,
            "user-123",
            3600,
            additional_data={"custom_key": "custom_value", "another": 42},
        )

        assert mock_session["custom_key"] == "custom_value"
        assert mock_session["another"] == 42

    def test_additional_data_cannot_override_user_id(self):
        """Test that additional_data cannot override user_id."""
        mock_request = MagicMock()
        mock_session = {}
        mock_request.session = mock_session

        regenerate_session(
            mock_request,
            "user-123",
            3600,
            additional_data={"user_id": "attacker-id"},
        )

        assert mock_session["user_id"] == "user-123"

    def test_additional_data_cannot_override_session_start(self):
        """Test that additional_data cannot override session_start."""
        mock_request = MagicMock()
        mock_session = {}
        mock_request.session = mock_session

        regenerate_session(
            mock_request,
            "user-123",
            3600,
            additional_data={"session_start": 0},
        )

        assert mock_session["session_start"] != 0

    def test_additional_data_cannot_override_max_age(self):
        """Test that additional_data cannot override _max_age."""
        mock_request = MagicMock()
        mock_session = {}
        mock_request.session = mock_session

        regenerate_session(
            mock_request,
            "user-123",
            3600,
            additional_data={"_max_age": 999999},
        )

        assert mock_session["_max_age"] == 3600

    def test_empty_additional_data(self):
        """Test with empty additional_data dict."""
        mock_request = MagicMock()
        mock_session = {}
        mock_request.session = mock_session

        regenerate_session(mock_request, "user-123", 3600, additional_data={})

        # Should only have core keys
        assert set(mock_session.keys()) == {"user_id", "session_start", "_max_age", "sid"}

    def test_none_additional_data(self):
        """Test with None additional_data (default)."""
        mock_request = MagicMock()
        mock_session = {}
        mock_request.session = mock_session

        regenerate_session(mock_request, "user-123", 3600, additional_data=None)

        # Should only have core keys
        assert set(mock_session.keys()) == {"user_id", "session_start", "_max_age", "sid"}


class TestSessionFixationPrevention:
    """Tests verifying session fixation attack prevention."""

    def test_pre_auth_session_data_not_preserved(self):
        """Verify that pre-authentication session data is cleared."""
        mock_request = MagicMock()
        mock_session = MagicMock()
        mock_request.session = mock_session

        # Simulate attacker-controlled pre-auth session
        mock_session.__contains__ = lambda self, key: (
            key
            in [
                "pending_mfa_user_id",
                "evil_key",
            ]
        )

        regenerate_session(mock_request, "legitimate-user", 3600)

        # Session clear must have been called
        mock_session.clear.assert_called_once()

    def test_safe_additional_data_added_after_clear(self):
        """Verify additional data is added after clearing, not before."""
        mock_request = MagicMock()
        call_order = []

        class OrderTrackingSession(dict):
            def clear(self):
                call_order.append("clear")
                super().clear()

            def __setitem__(self, key, value):
                call_order.append(f"set:{key}")
                super().__setitem__(key, value)

        mock_request.session = OrderTrackingSession()

        regenerate_session(
            mock_request,
            "user-123",
            3600,
            additional_data={"safe_key": "value"},
        )

        # Verify clear happens before any sets
        clear_index = call_order.index("clear")
        for item in call_order[clear_index + 1 :]:
            assert item.startswith("set:"), f"Unexpected call after clear: {item}"


class TestSessionId:
    """The opaque session identifier behind the OIDC ``sid`` claim."""

    def _regenerate(self, session: dict, additional_data: dict | None = None) -> dict:
        request = MagicMock()
        request.session = session
        regenerate_session(request, "user-1", 3600, additional_data=additional_data)
        return session

    def test_regeneration_mints_a_random_identifier(self):
        session = self._regenerate({})
        sid = session[SESSION_ID_KEY]
        assert isinstance(sid, str) and len(sid) >= 32

    def test_every_login_gets_a_new_identifier(self):
        """A sid known before login (fixation) never names the new session."""
        session = self._regenerate({SESSION_ID_KEY: "attacker-known"})
        first = session[SESSION_ID_KEY]
        assert first != "attacker-known"
        assert self._regenerate(session)[SESSION_ID_KEY] != first

    def test_additional_data_cannot_set_the_identifier(self):
        session = self._regenerate({}, additional_data={SESSION_ID_KEY: "carried-over"})
        assert session[SESSION_ID_KEY] != "carried-over"

    def test_ensure_mints_for_a_session_without_one(self):
        session: dict = {"user_id": "user-1"}
        sid = ensure_session_id(session)
        assert sid and session[SESSION_ID_KEY] == sid

    def test_ensure_keeps_an_existing_identifier(self):
        session = {SESSION_ID_KEY: "existing-sid"}
        assert ensure_session_id(session) == "existing-sid"
        assert session[SESSION_ID_KEY] == "existing-sid"

    def test_ensure_replaces_a_malformed_identifier(self):
        for bad in ("", None, 123):
            session = {SESSION_ID_KEY: bad}
            sid = ensure_session_id(session)
            assert isinstance(sid, str) and sid and session[SESSION_ID_KEY] == sid
