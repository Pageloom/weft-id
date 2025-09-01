#!/usr/bin/env sh
set -e

until python - <<'PY'
import os, psycopg
psycopg.connect(os.environ["DATABASE_URL"]).close()
PY
do
 echo "Waiting for database..."
 sleep 1
done

echo "Running migrations..."
./migrate.py run

echo "Starting app..."
exec uvicorn main:app --host 0.0.0.0 --port 8000
