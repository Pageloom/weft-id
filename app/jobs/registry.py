"""Job handler registry.

This module is separate from worker.py to avoid the __main__ import issue.
When worker.py is run as a script, it's loaded as __main__, not 'worker'.
By keeping the registry here, all imports see the same _handlers dict.
"""

import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

# Job handler registry
_handlers: dict[str, Callable[[dict], dict | None]] = {}


def register_handler(job_type: str) -> Callable:
    """Decorator to register a job handler.

    Usage:
        @register_handler("export_events")
        def handle_export_events(task: dict) -> dict | None:
            # ... job logic ...
            return {"result": "data"}
    """

    def decorator(func: Callable[[dict], dict[str, Any] | None]) -> Callable:
        _handlers[job_type] = func
        logger.info("Registered handler for job type: %s", job_type)
        return func

    return decorator


def get_handler(job_type: str) -> Callable[[dict], dict | None] | None:
    """Get a handler for a job type."""
    return _handlers.get(job_type)


def get_registered_handlers() -> list[str]:
    """Get list of registered handler names."""
    return list(_handlers.keys())
