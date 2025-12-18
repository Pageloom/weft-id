#!/usr/bin/env sh
set -e

until python - <<'PY'
import os, psycopg, settings
psycopg.connect(settings.DATABASE_URL).close()
PY
do
 echo "Waiting for database..."
 sleep 1
done

echo "Ensuring default tenant"
python ./dev/tenants.py "$DEV_SUBDOMAIN" 'Development'

echo "Ensuring admin users"
python ./dev/users.py "$DEV_SUBDOMAIN" super-"$DEV_SUBDOMAIN"@pageloom.com "$DEV_PASSWORD" --role=super_admin --first-name=Super --last-name=Admin
python ./dev/users.py "$DEV_SUBDOMAIN" admin-"$DEV_SUBDOMAIN"@pageloom.com "$DEV_PASSWORD" --role=admin --first-name=Admin --last-name=User
python ./dev/users.py "$DEV_SUBDOMAIN" member-"$DEV_SUBDOMAIN"@pageloom.com "$DEV_PASSWORD" --role=member --first-name=Normal --last-name=Member

echo "Starting app..."
exec uvicorn main:app --host 0.0.0.0 --port 8000 --reload --app-dir /app --reload-dir /app
