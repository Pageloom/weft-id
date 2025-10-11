import os

POSTGRES_USER = os.environ.get('POSTGRES_USER', '')
POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD', '')
POSTGRES_DB = os.environ.get('POSTGRES_DB', '')
POSTRGRES_PORT = os.environ.get('POSTGRES_PORT', '5432')
DATABASE_URL = f'postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@db:5432/{POSTGRES_DB}'
IS_DEV = os.environ.get('IS_DEV', 'False').lower() == 'true'
BASE_DOMAIN = os.environ.get('BASE_DOMAIN', '')
SMTP_HOST = os.environ.get('SMTP_HOST', '')
SMTP_PORT = int(os.environ.get('SMTP_PORT', ''))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
SMTP_TLS = bool(os.environ.get('SMTP_TLS', False))
FROM_EMAIL = 'no-reply@pageloom.localhost'
