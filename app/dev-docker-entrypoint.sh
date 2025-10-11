#!/usr/bin/env sh
set -e

until python - <<'PY'
import os, psycopg, config
psycopg.connect(config.DATABASE_URL).close()
PY
do
 echo "Waiting for database..."
 sleep 1
done

echo "Ensuring default tenant"
python ./dev/tenants.py dev 'Development'

echo "Ensuring super admin user"
python ./dev/users.py dev "$DEV_SUPERUSER_EMAIL" "$DEV_SUPERUSER_PASSWORD"

echo "Starting app..."
exec uvicorn main:app --host 0.0.0.0 --port 8000 --reload --app-dir /app --reload-dir /app
