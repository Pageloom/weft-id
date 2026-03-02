"""Health check service."""

import database


def check_db_connectivity() -> None:
    """Verify that the database is reachable. Raises on failure."""
    database.fetchone(database.UNSCOPED, "SELECT 1")
