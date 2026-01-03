"""End-to-end MFA tests using maildev for email verification.

These tests perform real login flows and verify actual email delivery/verification.
They require the maildev container to be running (docker compose up maildev).

Tests are skipped if maildev is not available.
"""

import pyotp
import pytest
from fastapi.testclient import TestClient

from tests.helpers import maildev

# Skip all tests in this module if maildev is not available
pytestmark = pytest.mark.skipif(
    not maildev.is_available(),
    reason="Maildev not running - start with 'docker compose up maildev'",
)


@pytest.fixture(autouse=True)
def setup_mfa_e2e_env(monkeypatch):
    """Configure environment for e2e MFA tests.

    Critical: BYPASS_OTP must be false for real OTP validation.
    Also configure SMTP to use maildev.
    """
    monkeypatch.setenv("BYPASS_OTP", "false")
    monkeypatch.setenv("SMTP_HOST", "127.0.0.1")
    monkeypatch.setenv("SMTP_PORT", "1025")
    monkeypatch.setenv("EMAIL_BACKEND", "smtp")

    # Force settings module to reload with new env vars
    import settings

    settings.BYPASS_OTP = False
    settings.SMTP_HOST = "127.0.0.1"
    settings.SMTP_PORT = 1025


@pytest.fixture
def mfa_client(test_tenant):
    """Create a test client configured for MFA e2e tests."""
    import os
    from pathlib import Path

    from dependencies import get_tenant_id_from_request
    from main import app

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    # Change to app directory so templates can be found
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent / "app"
    os.chdir(app_dir)

    client = TestClient(app)
    yield client

    os.chdir(original_cwd)
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def clear_mail_before_test():
    """Clear maildev inbox before each test."""
    maildev.clear_emails()
    yield


# ============================================================================
# Email MFA Tests
# ============================================================================


class TestEmailMFAFlow:
    """Tests for email-based MFA verification."""

    def test_email_mfa_login_complete_flow(self, mfa_client, email_mfa_user, test_tenant):
        """Test complete login flow with email MFA verification."""
        # Step 1: Submit login credentials
        response = mfa_client.post(
            "/login",
            data={"email": email_mfa_user["email"], "password": email_mfa_user["password"]},
            follow_redirects=False,
        )

        # Should redirect to MFA verification
        assert response.status_code == 303
        assert response.headers["location"] == "/mfa/verify"

        # Step 2: Get the email from maildev
        email = maildev.get_latest_email(email_mfa_user["email"], timeout=5)
        assert email is not None, "MFA email not received"

        # Step 3: Extract OTP code from email
        code = maildev.extract_otp_code(email)
        assert code is not None, "OTP code not found in email"
        assert len(code) == 6, "OTP code should be 6 digits"

        # Step 4: Submit the MFA code
        response = mfa_client.post(
            "/mfa/verify",
            data={"code": code},
            follow_redirects=False,
        )

        # Should redirect to dashboard after successful MFA
        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"

    def test_email_mfa_invalid_code_shows_error(self, mfa_client, email_mfa_user):
        """Test that submitting an invalid MFA code shows an error."""
        # Login first
        mfa_client.post(
            "/login",
            data={"email": email_mfa_user["email"], "password": email_mfa_user["password"]},
            follow_redirects=False,
        )

        # Submit wrong code
        response = mfa_client.post(
            "/mfa/verify",
            data={"code": "000000"},
            follow_redirects=False,
        )

        # Should return 200 with error message (stays on verify page)
        assert response.status_code == 200
        assert b"Invalid or expired code" in response.content

    def test_email_mfa_resend_code(self, mfa_client, email_mfa_user):
        """Test requesting a new email OTP code."""
        # Login first
        mfa_client.post(
            "/login",
            data={"email": email_mfa_user["email"], "password": email_mfa_user["password"]},
            follow_redirects=False,
        )

        # Wait for first email
        first_email = maildev.get_latest_email(email_mfa_user["email"], timeout=5)
        assert first_email is not None

        # Clear emails to detect new one
        maildev.clear_emails()

        # Request new code
        response = mfa_client.post("/mfa/verify/send-email", follow_redirects=False)

        # Should redirect back to verify page
        assert response.status_code == 303
        assert "/mfa/verify" in response.headers["location"]

        # Wait for new email
        second_email = maildev.get_latest_email(email_mfa_user["email"], timeout=5)
        assert second_email is not None

        second_code = maildev.extract_otp_code(second_email)
        assert second_code is not None

        # New code should work
        response = mfa_client.post(
            "/mfa/verify",
            data={"code": second_code},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"

    def test_email_mfa_code_with_spaces_cleaned(self, mfa_client, email_mfa_user):
        """Test that spaces and dashes in code input are stripped."""
        # Login first
        mfa_client.post(
            "/login",
            data={"email": email_mfa_user["email"], "password": email_mfa_user["password"]},
            follow_redirects=False,
        )

        # Get the real code
        email = maildev.get_latest_email(email_mfa_user["email"], timeout=5)
        code = maildev.extract_otp_code(email)

        # Format code with spaces: "123 456"
        formatted_code = f"{code[:3]} {code[3:]}"

        # Submit with spaces - should still work
        response = mfa_client.post(
            "/mfa/verify",
            data={"code": formatted_code},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"

    def test_email_mfa_code_with_dashes_cleaned(self, mfa_client, email_mfa_user):
        """Test that dashes in code input are stripped."""
        # Login first
        mfa_client.post(
            "/login",
            data={"email": email_mfa_user["email"], "password": email_mfa_user["password"]},
            follow_redirects=False,
        )

        # Get the real code
        email = maildev.get_latest_email(email_mfa_user["email"], timeout=5)
        code = maildev.extract_otp_code(email)

        # Format code with dashes: "123-456"
        formatted_code = f"{code[:3]}-{code[3:]}"

        # Submit with dashes - should still work
        response = mfa_client.post(
            "/mfa/verify",
            data={"code": formatted_code},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"


# ============================================================================
# TOTP MFA Tests
# ============================================================================


class TestTOTPMFAFlow:
    """Tests for TOTP-based MFA verification."""

    def test_totp_mfa_login_complete_flow(self, mfa_client, totp_mfa_user):
        """Test complete login flow with TOTP MFA verification."""
        # Step 1: Submit login credentials
        response = mfa_client.post(
            "/login",
            data={"email": totp_mfa_user["email"], "password": totp_mfa_user["password"]},
            follow_redirects=False,
        )

        # Should redirect to MFA verification
        assert response.status_code == 303
        assert response.headers["location"] == "/mfa/verify"

        # Step 2: No email should be sent for TOTP users
        email = maildev.get_latest_email(totp_mfa_user["email"], timeout=1)
        assert email is None, "No email should be sent for TOTP MFA users"

        # Step 3: Generate valid TOTP code using the secret
        totp = pyotp.TOTP(totp_mfa_user["totp_secret"])
        code = totp.now()

        # Step 4: Submit the TOTP code
        response = mfa_client.post(
            "/mfa/verify",
            data={"code": code},
            follow_redirects=False,
        )

        # Should redirect to dashboard after successful MFA
        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"

    def test_totp_mfa_invalid_code_shows_error(self, mfa_client, totp_mfa_user):
        """Test that submitting an invalid TOTP code shows an error."""
        # Login first
        mfa_client.post(
            "/login",
            data={"email": totp_mfa_user["email"], "password": totp_mfa_user["password"]},
            follow_redirects=False,
        )

        # Submit wrong code
        response = mfa_client.post(
            "/mfa/verify",
            data={"code": "000000"},
            follow_redirects=False,
        )

        # Should return 200 with error message
        assert response.status_code == 200
        assert b"Invalid or expired code" in response.content

    def test_totp_mfa_email_fallback_blocked(self, mfa_client, totp_mfa_user):
        """Test that TOTP users cannot request email codes."""
        # Login first
        mfa_client.post(
            "/login",
            data={"email": totp_mfa_user["email"], "password": totp_mfa_user["password"]},
            follow_redirects=False,
        )

        # Try to request email code
        response = mfa_client.post("/mfa/verify/send-email", follow_redirects=False)

        # Should redirect back to /mfa/verify (not send email)
        assert response.status_code == 303
        assert "/mfa/verify" in response.headers["location"]

        # No email should have been sent
        email = maildev.get_latest_email(totp_mfa_user["email"], timeout=1)
        assert email is None, "Email should not be sent for TOTP users"


# ============================================================================
# Backup Code Tests
# ============================================================================


class TestBackupCodes:
    """Tests for MFA backup code functionality."""

    def test_backup_code_works_for_email_user(self, mfa_client, mfa_user_with_backup_codes):
        """Test that backup codes work for email MFA users."""
        user = mfa_user_with_backup_codes

        # Login first
        mfa_client.post(
            "/login",
            data={"email": user["email"], "password": user["password"]},
            follow_redirects=False,
        )

        # Use a backup code instead of waiting for email
        backup_code = user["backup_codes"][0]

        response = mfa_client.post(
            "/mfa/verify",
            data={"code": backup_code},
            follow_redirects=False,
        )

        # Should succeed
        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"

    def test_backup_code_works_for_totp_user(self, mfa_client, test_tenant):
        """Test that backup codes work for TOTP MFA users."""
        # Create a TOTP user with backup codes
        from uuid import uuid4

        import database
        from argon2 import PasswordHasher
        from utils.mfa import encrypt_secret, generate_backup_codes, hash_code

        ph = PasswordHasher()
        unique_suffix = str(uuid4())[:8]
        email = f"totp-backup-{unique_suffix}@example.com"
        password = "TotpBackupPassword123!"
        password_hash = ph.hash(password)
        totp_secret = pyotp.random_base32()

        # Create user with TOTP
        user = database.fetchone(
            test_tenant["id"],
            """
            INSERT INTO users (
                tenant_id, password_hash, first_name, last_name, role, mfa_method
            ) VALUES (
                :tenant_id, :password_hash, :first_name, :last_name, :role, :mfa_method
            ) RETURNING id, first_name, last_name, role, mfa_method
            """,
            {
                "tenant_id": test_tenant["id"],
                "password_hash": password_hash,
                "first_name": "TOTP",
                "last_name": "Backup User",
                "role": "member",
                "mfa_method": "totp",
            },
        )

        # Create email
        database.execute(
            test_tenant["id"],
            """
            INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at)
            VALUES (:tenant_id, :user_id, :email, true, now())
            """,
            {"tenant_id": test_tenant["id"], "user_id": user["id"], "email": email},
        )

        # Store TOTP secret (encrypted)
        encrypted_secret = encrypt_secret(totp_secret)
        database.execute(
            test_tenant["id"],
            """
            INSERT INTO mfa_totp (tenant_id, user_id, secret_encrypted, method, verified_at)
            VALUES (:tenant_id, :user_id, :secret_encrypted, 'totp', now())
            """,
            {
                "tenant_id": test_tenant["id"],
                "user_id": user["id"],
                "secret_encrypted": encrypted_secret,
            },
        )

        # Generate and store backup codes
        backup_codes = generate_backup_codes()
        for code in backup_codes:
            # Hash without dashes (matching how verify_backup_code strips them)
            code_hash = hash_code(code.upper().replace("-", ""))
            database.execute(
                test_tenant["id"],
                """
                INSERT INTO mfa_backup_codes (tenant_id, user_id, code_hash)
                VALUES (:tenant_id, :user_id, :code_hash)
                """,
                {
                    "tenant_id": test_tenant["id"],
                    "user_id": user["id"],
                    "code_hash": code_hash,
                },
            )

        # Login
        mfa_client.post(
            "/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )

        # Use backup code instead of TOTP
        response = mfa_client.post(
            "/mfa/verify",
            data={"code": backup_codes[0]},
            follow_redirects=False,
        )

        # Should succeed
        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"

    def test_backup_code_single_use(self, mfa_client, mfa_user_with_backup_codes):
        """Test that backup codes can only be used once."""
        user = mfa_user_with_backup_codes
        backup_code = user["backup_codes"][0]

        # First login with backup code
        mfa_client.post(
            "/login",
            data={"email": user["email"], "password": user["password"]},
            follow_redirects=False,
        )

        response = mfa_client.post(
            "/mfa/verify",
            data={"code": backup_code},
            follow_redirects=False,
        )

        # Should succeed first time
        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"

        # Logout
        mfa_client.post("/logout", follow_redirects=False)

        # Second login attempt with same backup code
        mfa_client.post(
            "/login",
            data={"email": user["email"], "password": user["password"]},
            follow_redirects=False,
        )

        response = mfa_client.post(
            "/mfa/verify",
            data={"code": backup_code},
            follow_redirects=False,
        )

        # Should fail - code already used
        assert response.status_code == 200
        assert b"Invalid or expired code" in response.content

    def test_different_backup_codes_work(self, mfa_client, mfa_user_with_backup_codes):
        """Test that different backup codes can each be used once."""
        user = mfa_user_with_backup_codes

        # Use first backup code
        mfa_client.post(
            "/login",
            data={"email": user["email"], "password": user["password"]},
            follow_redirects=False,
        )

        response = mfa_client.post(
            "/mfa/verify",
            data={"code": user["backup_codes"][0]},
            follow_redirects=False,
        )
        assert response.status_code == 303

        # Logout
        mfa_client.post("/logout", follow_redirects=False)

        # Use second backup code
        mfa_client.post(
            "/login",
            data={"email": user["email"], "password": user["password"]},
            follow_redirects=False,
        )

        response = mfa_client.post(
            "/mfa/verify",
            data={"code": user["backup_codes"][1]},
            follow_redirects=False,
        )

        # Second code should also work
        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"
