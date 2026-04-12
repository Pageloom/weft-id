"""Infrastructure endpoints for load balancer probes and reverse proxy validation.

These routes are infrastructure-only and are NOT registered in pages.py.
They bypass tenant resolution (no subdomain required) and need no authentication.
"""

import logging

import settings
from fastapi import APIRouter, Query, Response
from services.health import check_db_connectivity, check_subdomain_exists

logger = logging.getLogger(__name__)

router = APIRouter(tags=["infrastructure"])


@router.get("/healthz", include_in_schema=False)
def healthz() -> Response:
    """Return 200 if the app is healthy, 503 if the database is unreachable."""
    try:
        check_db_connectivity()
        return Response(status_code=200)
    except Exception:
        logger.exception("Health check failed: database unreachable")
        return Response(status_code=503)


@router.get("/caddy/check-domain", include_in_schema=False)
def check_domain(domain: str = Query("")) -> Response:
    """Validate a domain for Caddy on-demand TLS certificate issuance.

    Caddy calls this endpoint before issuing a TLS certificate for a new
    hostname. Returns 200 to allow issuance, or a non-200 status to deny it.
    """
    if not domain:
        return Response(status_code=400)

    base = settings.BASE_DOMAIN
    if not base:
        return Response(status_code=200)

    domain = domain.lower().rstrip(".")

    # Allow the bare base domain (e.g., id.example.com)
    if domain == base:
        return Response(status_code=200)

    # Must be a direct subdomain of BASE_DOMAIN
    suffix = f".{base}"
    if not domain.endswith(suffix):
        return Response(status_code=404)

    subdomain = domain[: -len(suffix)]

    # Reject multi-level subdomains (e.g., foo.bar.id.example.com)
    if "." in subdomain:
        return Response(status_code=404)

    if check_subdomain_exists(subdomain):
        return Response(status_code=200)

    return Response(status_code=404)
