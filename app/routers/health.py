"""Health check endpoint for load balancer probes.

This route is infrastructure-only and is NOT registered in pages.py.
It bypasses tenant resolution (no subdomain required) and needs no authentication.
"""

import logging

from fastapi import APIRouter, Response
from services.health import check_db_connectivity

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
