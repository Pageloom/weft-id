"""Tests for stateless time-windowed token generation."""

from unittest.mock import patch

from app.utils.tokens import (
    PURPOSE_MFA_EMAIL,
    PURPOSE_PASSWORD_RESET,
    _compute_code,
    extract_user_id_from_url_token,
    generate_code,
    generate_url_token,
    verify_code,
    verify_url_token,
)


def test_generate_code_returns_6_digit_string():
    """Code is a zero-padded 6-digit numeric string."""
    code = generate_code("user-1", PURPOSE_MFA_EMAIL, step_seconds=300)

    assert isinstance(code, str)
    assert len(code) == 6
    assert code.isdigit()


def test_generate_code_deterministic():
    """Same inputs in the same time window produce the same code."""
    code1 = generate_code("user-1", PURPOSE_MFA_EMAIL, step_seconds=300)
    code2 = generate_code("user-1", PURPOSE_MFA_EMAIL, step_seconds=300)

    assert code1 == code2


def test_generate_code_different_users():
    """Different user IDs produce different codes."""
    code1 = generate_code("user-1", PURPOSE_MFA_EMAIL, step_seconds=300)
    code2 = generate_code("user-2", PURPOSE_MFA_EMAIL, step_seconds=300)

    assert code1 != code2


def test_generate_code_different_purposes():
    """Different purposes produce different codes (cross-purpose rejection)."""
    code1 = generate_code("user-1", PURPOSE_MFA_EMAIL, step_seconds=300)
    code2 = generate_code("user-1", PURPOSE_PASSWORD_RESET, step_seconds=300)

    assert code1 != code2


def test_generate_code_different_time_steps():
    """Different time steps produce different codes."""
    code1 = _compute_code("user-1", PURPOSE_MFA_EMAIL, time_step=100, state=None)
    code2 = _compute_code("user-1", PURPOSE_MFA_EMAIL, time_step=101, state=None)

    assert code1 != code2


def test_generate_code_with_state():
    """Including state changes the code."""
    code_no_state = _compute_code("user-1", PURPOSE_MFA_EMAIL, time_step=100, state=None)
    code_with_state = _compute_code("user-1", PURPOSE_MFA_EMAIL, time_step=100, state="2026-01-01")

    assert code_no_state != code_with_state


def test_state_change_invalidates_code():
    """Changing the state value produces a different code."""
    code_old = _compute_code(
        "user-1", PURPOSE_PASSWORD_RESET, time_step=100, state="2026-01-01T00:00:00"
    )
    code_new = _compute_code(
        "user-1", PURPOSE_PASSWORD_RESET, time_step=100, state="2026-03-20T12:00:00"
    )

    assert code_old != code_new


def test_verify_code_current_window():
    """Code verifies successfully in the current time window."""
    code = generate_code("user-1", PURPOSE_MFA_EMAIL, step_seconds=300)
    assert verify_code(code, "user-1", PURPOSE_MFA_EMAIL, step_seconds=300, window=1) is True


def test_verify_code_wrong_code():
    """Invalid code is rejected."""
    assert (
        verify_code("000000", "user-1", PURPOSE_MFA_EMAIL, step_seconds=300, window=1) is False
    ) or (
        # If 000000 happens to be valid for this time window, try another
        verify_code("999999", "user-1", PURPOSE_MFA_EMAIL, step_seconds=300, window=1) is False
    )


def test_verify_code_wrong_user():
    """Code generated for one user is rejected for another."""
    code = generate_code("user-1", PURPOSE_MFA_EMAIL, step_seconds=300)
    assert verify_code(code, "user-2", PURPOSE_MFA_EMAIL, step_seconds=300, window=1) is False


def test_verify_code_wrong_purpose():
    """Code generated for one purpose is rejected for another."""
    code = generate_code("user-1", PURPOSE_MFA_EMAIL, step_seconds=300)
    assert verify_code(code, "user-1", PURPOSE_PASSWORD_RESET, step_seconds=300, window=1) is False


def test_verify_code_adjacent_window():
    """Code from an adjacent time step is accepted within the window."""
    # Generate a code for the previous time step
    import time as time_mod

    current_step = int(time_mod.time()) // 300
    prev_code = _compute_code("user-1", PURPOSE_MFA_EMAIL, current_step - 1, state=None)

    # Should still verify with window=1
    assert verify_code(prev_code, "user-1", PURPOSE_MFA_EMAIL, step_seconds=300, window=1) is True


def test_verify_code_outside_window():
    """Code from far outside the window is rejected."""
    import time as time_mod

    current_step = int(time_mod.time()) // 300
    old_code = _compute_code("user-1", PURPOSE_MFA_EMAIL, current_step - 10, state=None)

    assert verify_code(old_code, "user-1", PURPOSE_MFA_EMAIL, step_seconds=300, window=1) is False


def test_verify_code_with_matching_state():
    """Code verifies when state matches."""
    state = "2026-01-01T00:00:00"
    code = generate_code("user-1", PURPOSE_PASSWORD_RESET, step_seconds=300, state=state)
    assert (
        verify_code(code, "user-1", PURPOSE_PASSWORD_RESET, step_seconds=300, window=1, state=state)
        is True
    )


def test_verify_code_with_changed_state():
    """Code fails when state has changed since generation."""
    old_state = "2026-01-01T00:00:00"
    new_state = "2026-03-20T12:00:00"
    code = generate_code("user-1", PURPOSE_PASSWORD_RESET, step_seconds=300, state=old_state)
    assert (
        verify_code(
            code, "user-1", PURPOSE_PASSWORD_RESET, step_seconds=300, window=1, state=new_state
        )
        is False
    )


def test_verify_code_bypass_mode():
    """BYPASS_OTP accepts any valid 6-digit code."""
    with patch("utils.tokens.settings.BYPASS_OTP", True):
        assert verify_code("000000", "any", PURPOSE_MFA_EMAIL, step_seconds=300) is True
        assert verify_code("123456", "any", PURPOSE_MFA_EMAIL, step_seconds=300) is True
        assert verify_code("999999", "any", PURPOSE_MFA_EMAIL, step_seconds=300) is True


def test_verify_code_bypass_rejects_bad_format():
    """BYPASS_OTP still rejects non-6-digit codes."""
    with patch("utils.tokens.settings.BYPASS_OTP", True):
        # 5 digits
        assert verify_code("12345", "any", PURPOSE_MFA_EMAIL, step_seconds=300) is False
        # 7 digits
        assert verify_code("1234567", "any", PURPOSE_MFA_EMAIL, step_seconds=300) is False
        # Letters
        assert verify_code("abcdef", "any", PURPOSE_MFA_EMAIL, step_seconds=300) is False


def test_compute_code_zero_padding():
    """Codes that would be less than 6 digits are zero-padded."""
    # We can't easily force a specific HMAC output, but we can verify
    # the format is always correct across many time steps
    for step in range(100):
        code = _compute_code("user-1", PURPOSE_MFA_EMAIL, step, state=None)
        assert len(code) == 6
        assert code.isdigit()


# ---------------------------------------------------------------------------
# URL token tests
# ---------------------------------------------------------------------------


def test_generate_url_token_returns_string():
    """URL token is a non-empty string."""
    token = generate_url_token("user-1", PURPOSE_PASSWORD_RESET)
    assert isinstance(token, str)
    assert len(token) > 0


def test_verify_url_token_valid():
    """A freshly generated URL token is valid."""
    token = generate_url_token("user-1", PURPOSE_PASSWORD_RESET, ttl_seconds=1800)
    user_id = verify_url_token(token, PURPOSE_PASSWORD_RESET, ttl_seconds=1800)
    assert user_id == "user-1"


def test_verify_url_token_wrong_purpose():
    """URL token is rejected when purpose doesn't match."""
    token = generate_url_token("user-1", PURPOSE_PASSWORD_RESET)
    assert verify_url_token(token, PURPOSE_MFA_EMAIL) is None


def test_verify_url_token_expired():
    """URL token is rejected after TTL expires."""
    import time as time_mod

    with patch("utils.tokens.time.time", return_value=time_mod.time() - 3600):
        token = generate_url_token("user-1", PURPOSE_PASSWORD_RESET, ttl_seconds=1800)

    # Now verify at current time (token was issued 1 hour ago, TTL is 30 min)
    assert verify_url_token(token, PURPOSE_PASSWORD_RESET, ttl_seconds=1800) is None


def test_verify_url_token_tampered():
    """Tampered URL token is rejected."""
    token = generate_url_token("user-1", PURPOSE_PASSWORD_RESET)
    # Flip a character in the token
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    assert verify_url_token(tampered, PURPOSE_PASSWORD_RESET) is None


def test_verify_url_token_with_state():
    """URL token with matching state is accepted."""
    state = "2026-01-01T00:00:00"
    token = generate_url_token("user-1", PURPOSE_PASSWORD_RESET, state=state)
    assert verify_url_token(token, PURPOSE_PASSWORD_RESET, state=state) == "user-1"


def test_verify_url_token_state_changed():
    """URL token is rejected when state has changed."""
    old_state = "2026-01-01T00:00:00"
    new_state = "2026-03-20T12:00:00"
    token = generate_url_token("user-1", PURPOSE_PASSWORD_RESET, state=old_state)
    assert verify_url_token(token, PURPOSE_PASSWORD_RESET, state=new_state) is None


def test_extract_user_id_from_url_token():
    """User ID can be extracted from a URL token without verification."""
    token = generate_url_token("user-123", PURPOSE_PASSWORD_RESET)
    assert extract_user_id_from_url_token(token) == "user-123"


def test_extract_user_id_from_invalid_token():
    """Extracting from garbage returns None."""
    assert extract_user_id_from_url_token("not-a-token") is None
    assert extract_user_id_from_url_token("") is None


def test_verify_url_token_malformed():
    """Completely invalid tokens return None."""
    assert verify_url_token("", PURPOSE_PASSWORD_RESET) is None
    assert verify_url_token("garbage", PURPOSE_PASSWORD_RESET) is None
    assert verify_url_token("!!!invalid!!!", PURPOSE_PASSWORD_RESET) is None
