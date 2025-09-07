import os
POSTGRES_USER=os.environ.get('POSTGRES_USER', '')
POSTGRES_PASSWORD=os.environ.get('POSTGRES_PASSWORD', '')
POSTGRES_DB=os.environ.get('POSTGRES_DB', '')
POSTRGRES_PORT=os.environ.get('POSTGRES_PORT', '5432')
DATABASE_URL=f'postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@db:5432/{POSTGRES_DB}'
IS_DEV=os.environ.get('IS_DEV', 'False').lower()=='true'
BASE_DOMAIN=os.environ.get('BASE_DOMAIN', '')
