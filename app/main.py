import os
from typing import Optional
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from psycopg_pool import ConnectionPool

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://appuser:apppass@db:5432/appdb")

# Small connection pool (psycopg3)
pool = ConnectionPool(conninfo=DATABASE_URL, min_size=1, max_size=10, open=True)

app = FastAPI(title="Multitenant (no ORM)")

def normalize_host(h: Optional[str]) -> str:
    # strip port, lowercase, trim trailing dot
    h = (h or "").split(":")[0].rstrip(".").lower()
    return h

def tenant_exists(host: str) -> bool:
    sql = "select 1 from tenants where host = %s limit 1"
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (host,))
            return cur.fetchone() is not None

@app.get("/")
def root(request: Request):
    host = normalize_host(request.headers.get("x-forwarded-host") or request.headers.get("host"))
    # Only accept our dev domain space
    if not (host == "dev.localhost" or host.endswith(".dev.localhost")):
        # outside our domain space → pretend it doesn't exist
        raise HTTPException(status_code=404, detail="Unknown host")

    # ✅ If tenant exists -> OK  | ❌ If not -> 404
    if tenant_exists(host):
        return JSONResponse({"ok": True, "host": host})
    raise HTTPException(status_code=404, detail=f"No tenant configured for host {host}")
