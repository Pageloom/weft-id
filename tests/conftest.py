"""Pytest configuration and fixtures."""

import os
import sys
from pathlib import Path
from uuid import uuid4

# Add app directory to path so we can import modules
app_path = Path(__file__).parent.parent / "app"
sys.path.insert(0, str(app_path))

# Configure database connection for tests
# Use appuser (non-superuser) to ensure RLS is enforced
os.environ.setdefault("POSTGRES_USER", "appuser")
os.environ.setdefault("POSTGRES_PASSWORD", "apppass")
os.environ.setdefault("POSTGRES_DB", "appdb")
os.environ.setdefault("POSTGRES_PORT", "5432")
os.environ.setdefault("BASE_DOMAIN", "pageloom.localhost")

import pytest  # noqa: E402

# Import settings and patch DATABASE_URL to use localhost
import settings  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

settings.DATABASE_URL = f"postgresql://{os.environ['POSTGRES_USER']}:{os.environ['POSTGRES_PASSWORD']}@localhost:5432/{os.environ['POSTGRES_DB']}"
settings.BASE_DOMAIN = os.environ["BASE_DOMAIN"]


@pytest.fixture(autouse=True)
def clear_dependency_overrides():
    """Clear dependency overrides after each test to prevent state leakage."""
    yield
    from main import app

    app.dependency_overrides.clear()


@pytest.fixture
def client():
    """Create a test client for the FastAPI application."""
    from main import app

    return TestClient(app)


@pytest.fixture(scope="session", autouse=True)
def cleanup_database_pool():
    """Cleanup database pool after all tests complete."""
    yield
    # Cleanup after all tests
    import database

    database.close_pool()


@pytest.fixture
def test_subdomain():
    """Provide a test subdomain for testing."""
    return "dev"


@pytest.fixture
def test_host(test_subdomain):
    """Provide a test host header."""
    import settings

    return f"{test_subdomain}.{settings.BASE_DOMAIN}"


@pytest.fixture
def test_tenant_host(test_tenant):
    """Provide a test host header for the dynamically created test_tenant."""
    import settings

    return f"{test_tenant['subdomain']}.{settings.BASE_DOMAIN}"


@pytest.fixture
def test_tenant():
    """
    Create a test tenant for database tests and clean it up afterward.

    Yields a dict with tenant details:
        {
            'id': UUID,
            'subdomain': str,
            'name': str
        }
    """
    import database

    # Generate unique subdomain for this test run
    unique_suffix = str(uuid4())[:8]
    subdomain = f"test-{unique_suffix}"
    name = f"Test Tenant {unique_suffix}"

    # Create tenant
    database.execute(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:subdomain, :name) RETURNING id",
        {"subdomain": subdomain, "name": name},
    )

    # Fetch the created tenant to get the full record
    tenant = database.fetchone(
        database.UNSCOPED,
        "SELECT id, subdomain, name FROM tenants WHERE subdomain = :subdomain",
        {"subdomain": subdomain},
    )

    yield tenant

    # Cleanup: Delete tenant and all associated data
    # Note: This assumes cascading deletes are set up in your schema
    # If not, you may need to manually delete related records first
    database.execute(
        database.UNSCOPED, "DELETE FROM tenants WHERE id = :tenant_id", {"tenant_id": tenant["id"]}
    )


@pytest.fixture
def test_user(test_tenant):
    """
    Create a test user in the test tenant.

    Yields a dict with user details:
        {
            'id': UUID,
            'email': str,
            'first_name': str,
            'last_name': str,
            'role': str,
            'tenant_id': UUID
        }
    """
    import database
    from argon2 import PasswordHasher

    ph = PasswordHasher()
    unique_suffix = str(uuid4())[:8]
    email = f"testuser-{unique_suffix}@example.com"
    password_hash = ph.hash("TestPassword123!")

    # Create user
    user = database.fetchone(
        test_tenant["id"],
        """
        INSERT INTO users (
            tenant_id, password_hash, first_name, last_name, role
        ) VALUES (
            :tenant_id, :password_hash, :first_name, :last_name, :role
        ) RETURNING id, first_name, last_name, role
        """,
        {
            "tenant_id": test_tenant["id"],
            "password_hash": password_hash,
            "first_name": "Test",
            "last_name": "User",
            "role": "member",
        },
    )

    # Add tenant_id and email to the returned dict for convenience
    user["tenant_id"] = test_tenant["id"]
    user["email"] = email

    # Create primary verified email
    database.execute(
        test_tenant["id"],
        """
        INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at)
        VALUES (:tenant_id, :user_id, :email, true, now())
        """,
        {"tenant_id": test_tenant["id"], "user_id": user["id"], "email": email},
    )

    yield user

    # Cleanup happens via tenant deletion (cascading delete)


@pytest.fixture
def test_admin_user(test_tenant):
    """
    Create a test admin user in the test tenant.

    Yields a dict with user details (same structure as test_user).
    """
    import database
    from argon2 import PasswordHasher

    ph = PasswordHasher()
    unique_suffix = str(uuid4())[:8]
    email = f"admin-{unique_suffix}@example.com"
    password_hash = ph.hash("AdminPassword123!")

    # Create admin user
    user = database.fetchone(
        test_tenant["id"],
        """
        INSERT INTO users (
            tenant_id, password_hash, first_name, last_name, role
        ) VALUES (
            :tenant_id, :password_hash, :first_name, :last_name, :role
        ) RETURNING id, first_name, last_name, role
        """,
        {
            "tenant_id": test_tenant["id"],
            "password_hash": password_hash,
            "first_name": "Admin",
            "last_name": "User",
            "role": "admin",
        },
    )

    user["tenant_id"] = test_tenant["id"]
    user["email"] = email

    # Create primary verified email
    database.execute(
        test_tenant["id"],
        """
        INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at)
        VALUES (:tenant_id, :user_id, :email, true, now())
        """,
        {"tenant_id": test_tenant["id"], "user_id": user["id"], "email": email},
    )

    yield user

    # Cleanup happens via tenant deletion (cascading delete)


@pytest.fixture
def test_super_admin_user(test_tenant):
    """
    Create a test super_admin user in the test tenant.

    Yields a dict with user details (same structure as test_user).
    """
    import database
    from argon2 import PasswordHasher

    ph = PasswordHasher()
    unique_suffix = str(uuid4())[:8]
    email = f"superadmin-{unique_suffix}@example.com"
    password_hash = ph.hash("SuperAdminPassword123!")

    # Create super_admin user
    user = database.fetchone(
        test_tenant["id"],
        """
        INSERT INTO users (
            tenant_id, password_hash, first_name, last_name, role
        ) VALUES (
            :tenant_id, :password_hash, :first_name, :last_name, :role
        ) RETURNING id, first_name, last_name, role
        """,
        {
            "tenant_id": test_tenant["id"],
            "password_hash": password_hash,
            "first_name": "Super",
            "last_name": "Admin",
            "role": "super_admin",
        },
    )

    user["tenant_id"] = test_tenant["id"]
    user["email"] = email

    # Create primary verified email
    database.execute(
        test_tenant["id"],
        """
        INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at)
        VALUES (:tenant_id, :user_id, :email, true, now())
        """,
        {"tenant_id": test_tenant["id"], "user_id": user["id"], "email": email},
    )

    yield user

    # Cleanup happens via tenant deletion (cascading delete)


# ============================================================================
# OAuth2 Test Fixtures
# ============================================================================


@pytest.fixture
def normal_oauth2_client(test_tenant, test_admin_user):
    """
    Create a normal OAuth2 client for testing authorization code flow.

    Returns a dict with client details including the plain text client_secret.
    """
    import database

    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Test OAuth2 Client",
        redirect_uris=["http://localhost:3000/callback", "http://localhost:3000/auth/callback"],
        created_by=test_admin_user["id"],
    )

    yield client

    # Cleanup happens via tenant deletion (cascading delete)


@pytest.fixture
def b2b_oauth2_client(test_tenant, test_admin_user):
    """
    Create a B2B OAuth2 client for testing client credentials flow.

    Returns a dict with client details including the plain text client_secret.
    Also creates a service user automatically.
    """
    import database

    client = database.oauth2.create_b2b_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Test B2B Client",
        role="admin",
        created_by=test_admin_user["id"],
    )

    yield client

    # Cleanup happens via tenant deletion (cascading delete)


@pytest.fixture
def oauth2_access_token(test_tenant, normal_oauth2_client, test_user):
    """
    Create an OAuth2 access token for a user (simulating authorization code flow).

    Returns the plain text access token.
    """
    import database

    # Create a refresh token first
    refresh_token, refresh_token_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    # Create an access token linked to the refresh token
    access_token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        parent_token_id=refresh_token_id,
    )

    yield access_token

    # Cleanup happens via tenant deletion (cascading delete)


@pytest.fixture
def oauth2_authorization_header(oauth2_access_token):
    """
    Create an Authorization header with Bearer token for API testing.

    Returns a dict suitable for TestClient headers parameter.
    """
    return {"Authorization": f"Bearer {oauth2_access_token}"}


@pytest.fixture
def oauth2_admin_access_token(test_tenant, normal_oauth2_client, test_admin_user):
    """
    Create an OAuth2 access token for an admin user (simulating authorization code flow).

    Returns the plain text access token.
    """
    import database

    # Create a refresh token first
    refresh_token, refresh_token_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_admin_user["id"],
    )

    # Create an access token linked to the refresh token
    access_token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_admin_user["id"],
        parent_token_id=refresh_token_id,
    )

    yield access_token

    # Cleanup happens via tenant deletion (cascading delete)


@pytest.fixture
def oauth2_admin_authorization_header(oauth2_admin_access_token):
    """
    Create an Authorization header with Bearer token for an admin user.

    Returns a dict suitable for TestClient headers parameter.
    """
    return {"Authorization": f"Bearer {oauth2_admin_access_token}"}


# ============================================================================
# MFA E2E Test Fixtures
# ============================================================================


@pytest.fixture
def maildev_available():
    """Check if maildev is available for e2e email tests."""
    from tests.helpers import maildev

    return maildev.is_available()


@pytest.fixture
def clean_maildev():
    """Clear maildev inbox before test. Skips if maildev unavailable."""
    from tests.helpers import maildev

    if maildev.is_available():
        maildev.clear_emails()
    yield


@pytest.fixture
def email_mfa_user(test_tenant):
    """
    Create a test user with email MFA configured.

    Yields a dict with user details including plaintext password.
    """
    import database
    from argon2 import PasswordHasher

    ph = PasswordHasher()
    unique_suffix = str(uuid4())[:8]
    email = f"mfa-email-{unique_suffix}@example.com"
    password = "MfaTestPassword123!"
    password_hash = ph.hash(password)

    # Create user with email MFA method
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
            "first_name": "Email",
            "last_name": "MFA User",
            "role": "member",
            "mfa_method": "email",
        },
    )

    user["tenant_id"] = test_tenant["id"]
    user["email"] = email
    user["password"] = password  # For e2e login tests

    # Create primary verified email
    database.execute(
        test_tenant["id"],
        """
        INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at)
        VALUES (:tenant_id, :user_id, :email, true, now())
        """,
        {"tenant_id": test_tenant["id"], "user_id": user["id"], "email": email},
    )

    yield user


@pytest.fixture
def totp_mfa_user(test_tenant):
    """
    Create a test user with TOTP MFA configured.

    Yields a dict with user details including plaintext password and TOTP secret.
    """
    import database
    import pyotp
    from argon2 import PasswordHasher

    ph = PasswordHasher()
    unique_suffix = str(uuid4())[:8]
    email = f"mfa-totp-{unique_suffix}@example.com"
    password = "MfaTotpPassword123!"
    password_hash = ph.hash(password)
    totp_secret = pyotp.random_base32()

    # Create user with TOTP MFA method
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
            "last_name": "MFA User",
            "role": "member",
            "mfa_method": "totp",
        },
    )

    user["tenant_id"] = test_tenant["id"]
    user["email"] = email
    user["password"] = password
    user["totp_secret"] = totp_secret

    # Create primary verified email
    database.execute(
        test_tenant["id"],
        """
        INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at)
        VALUES (:tenant_id, :user_id, :email, true, now())
        """,
        {"tenant_id": test_tenant["id"], "user_id": user["id"], "email": email},
    )

    # Store TOTP secret (encrypted)
    from utils.mfa import encrypt_secret

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

    yield user


@pytest.fixture
def mfa_user_with_backup_codes(test_tenant):
    """
    Create a test user with email MFA and backup codes.

    Yields a dict with user details including plaintext backup codes.
    """
    import database
    from argon2 import PasswordHasher
    from utils.mfa import generate_backup_codes, hash_code

    ph = PasswordHasher()
    unique_suffix = str(uuid4())[:8]
    email = f"mfa-backup-{unique_suffix}@example.com"
    password = "MfaBackupPassword123!"
    password_hash = ph.hash(password)

    # Create user with email MFA method
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
            "first_name": "Backup",
            "last_name": "Code User",
            "role": "member",
            "mfa_method": "email",
        },
    )

    user["tenant_id"] = test_tenant["id"]
    user["email"] = email
    user["password"] = password

    # Create primary verified email
    database.execute(
        test_tenant["id"],
        """
        INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at)
        VALUES (:tenant_id, :user_id, :email, true, now())
        """,
        {"tenant_id": test_tenant["id"], "user_id": user["id"], "email": email},
    )

    # Generate and store backup codes
    backup_codes = generate_backup_codes()
    user["backup_codes"] = backup_codes  # Store plaintext for tests

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

    yield user
