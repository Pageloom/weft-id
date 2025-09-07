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

echo "Ensuring default tenant (Acme Inc.)..."
./dev/tenants.py acme-inc 'Acme Incorporated'

echo "Starting app..."
exec uvicorn main:app --host 0.0.0.0 --port 8000 --reload --app-dir /app --reload-dir /app
