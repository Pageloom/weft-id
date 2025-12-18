import os


def _parse_bool(value: str | None) -> bool:
    """Parse string to boolean."""
    if value is None:
        return False
    return value.lower() in ("true", "1", "yes", "on")


POSTGRES_USER = os.environ.get("POSTGRES_USER", "")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "")
POSTGRES_DB = os.environ.get("POSTGRES_DB", "")
POSTGRES_PORT = os.environ.get("POSTGRES_PORT", "5432")
DATABASE_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@db:5432/{POSTGRES_DB}"

IS_DEV = _parse_bool(os.environ.get("IS_DEV"))
BASE_DOMAIN = os.environ.get("BASE_DOMAIN", "")
DEFAULT_SUBDOMAIN = os.environ.get("DEFAULT_SUBDOMAIN", "dev")

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "25"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_TLS = _parse_bool(os.environ.get("SMTP_TLS"))

FROM_EMAIL = os.environ.get("FROM_EMAIL", "no-reply@pageloom.localhost")

SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY", "dev-secret-key-change-in-production")
MFA_ENCRYPTION_KEY = os.environ.get(
    "MFA_ENCRYPTION_KEY", "dev-mfa-key-change-in-production-must-be-base64"
)

# OAuth2 Configuration
# Token expiry times (in seconds)
OAUTH2_AUTHORIZATION_CODE_EXPIRY = 300  # 5 minutes
OAUTH2_ACCESS_TOKEN_EXPIRY = 3600  # 1 hour
OAUTH2_REFRESH_TOKEN_EXPIRY = 2592000  # 30 days
OAUTH2_CLIENT_CREDENTIALS_TOKEN_EXPIRY = 86400  # 24 hours
