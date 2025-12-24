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

# Email backend selection: smtp, resend, or sendgrid
EMAIL_BACKEND = os.environ.get("EMAIL_BACKEND", "smtp")

# API keys for HTTP-based email backends
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY", "")

# MFA bypass mode (DEVELOPMENT/ON-PREM ONLY - allows any 6-digit code)
BYPASS_OTP = _parse_bool(os.environ.get("BYPASS_OTP"))

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

# Memcached Configuration
MEMCACHED_HOST = os.environ.get("MEMCACHED_HOST", "memcached")
MEMCACHED_PORT = int(os.environ.get("MEMCACHED_PORT", "11211"))

# Activity Tracking Configuration
ACTIVITY_CACHE_TTL_SECONDS = 3 * 60 * 60  # 3 hours

# File Storage Configuration
STORAGE_BACKEND = os.environ.get("STORAGE_BACKEND", "local")  # "local" or "spaces"
LOCAL_STORAGE_PATH = os.environ.get("LOCAL_STORAGE_PATH", "/app/storage")

# DigitalOcean Spaces (S3-compatible) Configuration
SPACES_ENDPOINT = os.environ.get("SPACES_ENDPOINT", "")
SPACES_KEY = os.environ.get("SPACES_KEY", "")
SPACES_SECRET = os.environ.get("SPACES_SECRET", "")
SPACES_BUCKET = os.environ.get("SPACES_BUCKET", "")
SPACES_REGION = os.environ.get("SPACES_REGION", "nyc3")

# Export Configuration
EXPORT_FILE_EXPIRY_HOURS = int(os.environ.get("EXPORT_FILE_EXPIRY_HOURS", "24"))
