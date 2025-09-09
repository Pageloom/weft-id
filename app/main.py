import sql
from typing import Optional
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI(title="Loom")

def normalize_host(h: Optional[str]) -> str:
    h = (h or "").split(":")[0].rstrip(".").lower()
    return h

def _tenant(host: str) -> bool:
    subdomain = host.split(".")[0]
    if row := sql.fetchone(
        sql.UNSCOPED, 'select id from tenants where subdomain = %(subdomain)s', {'subdomain': subdomain}
    ):
        return row['id']

    return None

@app.get("/")
def root(request: Request):
    host = normalize_host(request.headers.get("x-forwarded-host") or request.headers.get("host"))
    if not host.endswith(".pageloom.localhost"):
        raise HTTPException(status_code=404, detail="Unknown host")

    if _tenant(host):
        return JSONResponse({"ok": True, "host": host})

    raise HTTPException(status_code=404, detail=f"No tenant configured for host {host}")

