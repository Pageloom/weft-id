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

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "25"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_TLS = _parse_bool(os.environ.get("SMTP_TLS"))

FROM_EMAIL = os.environ.get("FROM_EMAIL", "no-reply@pageloom.localhost")

DEV_SUPERUSER_EMAIL = os.environ.get("DEV_SUPERUSER_EMAIL", "admin@dev.pageloom.localhost")
DEV_SUPERUSER_PASSWORD = os.environ.get("DEV_SUPERUSER_PASSWORD", "devpass123")

SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY", "dev-secret-key-change-in-production")
MFA_ENCRYPTION_KEY = os.environ.get(
    "MFA_ENCRYPTION_KEY", "dev-mfa-key-change-in-production-must-be-base64"
)
