"""Background job worker process.

Polls for pending tasks and executes them using registered handlers.
Also runs periodic cleanup tasks.

Run as: python worker.py
"""

import logging
import os
import signal
import time
from datetime import UTC, datetime, timedelta
from typing import Any

# Force server timezone to UTC for consistent datetime handling
os.environ["TZ"] = "UTC"
time.tzset()

import database  # noqa: E402
from database._core import session  # noqa: E402
from jobs.registry import get_handler, get_registered_handlers  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# Re-export register_handler for backwards compatibility
def register_handler(job_type: str):
    """Decorator to register a job handler.

    Note: This is re-exported from jobs.registry for backwards compatibility.
    New code should import directly from jobs.registry.
    """
    from jobs.registry import register_handler as _register_handler

    return _register_handler(job_type)


class Worker:
    """Background job worker."""

    def __init__(
        self,
        poll_interval: int = 10,
        cleanup_interval_hours: int = 1,
        inactivation_interval_hours: int = 24,
        saml_refresh_interval_hours: int = 24,
    ) -> None:
        """Initialize the worker.

        Args:
            poll_interval: Seconds between polling for new tasks
            cleanup_interval_hours: Hours between cleanup runs
            inactivation_interval_hours: Hours between idle user inactivation checks
            saml_refresh_interval_hours: Hours between SAML metadata refresh runs
        """
        self.poll_interval = poll_interval
        self.cleanup_interval = timedelta(hours=cleanup_interval_hours)
        self.inactivation_interval = timedelta(hours=inactivation_interval_hours)
        self.saml_refresh_interval = timedelta(hours=saml_refresh_interval_hours)
        self.running = True
        self.last_cleanup: datetime | None = None
        self.last_inactivation: datetime | None = None
        self.last_saml_refresh: datetime | None = None

    def stop(self, signum: int | None = None, frame: Any = None) -> None:
        """Handle shutdown signal."""
        logger.info("Received shutdown signal, stopping...")
        self.running = False

    def run(self) -> None:
        """Main worker loop."""
        logger.info("Worker starting, poll interval: %ds", self.poll_interval)
        logger.info("Registered handlers: %s", get_registered_handlers())
        logger.info("Cleanup interval: %s", self.cleanup_interval)
        logger.info("Inactivation interval: %s", self.inactivation_interval)
        logger.info("SAML refresh interval: %s", self.saml_refresh_interval)

        while self.running:
            try:
                # Check if cleanup is due
                self._maybe_run_cleanup()

                # Check if inactivation is due
                self._maybe_run_inactivation()

                # Check if SAML metadata refresh is due
                self._maybe_run_saml_refresh()

                # Poll for next task
                task = database.bg_tasks.claim_next_task()
                if task:
                    self._process_task(task)
                else:
                    time.sleep(self.poll_interval)
            except Exception as e:
                logger.exception("Worker loop error: %s", e)
                time.sleep(self.poll_interval)

        logger.info("Worker stopped")

    def _maybe_run_cleanup(self) -> None:
        """Run cleanup if enough time has passed since last run."""
        now = datetime.now(UTC)

        if self.last_cleanup is None:
            # Run cleanup on first iteration
            self.last_cleanup = now
            self._run_cleanup()
        elif now - self.last_cleanup >= self.cleanup_interval:
            self.last_cleanup = now
            self._run_cleanup()

    def _run_cleanup(self) -> None:
        """Run the cleanup job directly (not as a queued task)."""
        logger.info("Running periodic cleanup...")
        try:
            from jobs.cleanup_exports import cleanup_expired_exports

            result = cleanup_expired_exports()
            logger.info("Cleanup completed: %s", result)
        except Exception as e:
            logger.exception("Cleanup failed: %s", e)

    def _maybe_run_inactivation(self) -> None:
        """Run inactivation check if enough time has passed since last run."""
        now = datetime.now(UTC)

        if self.last_inactivation is None:
            # Run inactivation on first iteration
            self.last_inactivation = now
            self._run_inactivation()
        elif now - self.last_inactivation >= self.inactivation_interval:
            self.last_inactivation = now
            self._run_inactivation()

    def _run_inactivation(self) -> None:
        """Run the idle user inactivation job directly (not as a queued task)."""
        logger.info("Running idle user inactivation check...")
        try:
            from jobs.inactivate_idle_users import inactivate_idle_users

            result = inactivate_idle_users()
            logger.info("Inactivation check completed: %s", result)
        except Exception as e:
            logger.exception("Inactivation check failed: %s", e)

    def _maybe_run_saml_refresh(self) -> None:
        """Run SAML metadata refresh if enough time has passed since last run."""
        now = datetime.now(UTC)

        if self.last_saml_refresh is None:
            # Run refresh on first iteration
            self.last_saml_refresh = now
            self._run_saml_refresh()
        elif now - self.last_saml_refresh >= self.saml_refresh_interval:
            self.last_saml_refresh = now
            self._run_saml_refresh()

    def _run_saml_refresh(self) -> None:
        """Run the SAML IdP metadata refresh job directly (not as a queued task)."""
        logger.info("Running SAML IdP metadata refresh...")
        try:
            from jobs.refresh_saml_metadata import refresh_saml_metadata

            result = refresh_saml_metadata()
            logger.info("SAML metadata refresh completed: %s", result)
        except Exception as e:
            logger.exception("SAML metadata refresh failed: %s", e)

    def _process_task(self, task: dict) -> None:
        """Process a single task."""
        task_id = str(task["id"])
        job_type = task["job_type"]
        tenant_id = str(task["tenant_id"])

        logger.info(
            "Processing task %s (type=%s, tenant=%s)",
            task_id,
            job_type,
            tenant_id,
        )

        handler = get_handler(job_type)
        if not handler:
            logger.error("No handler for job type: %s", job_type)
            database.bg_tasks.fail_task(task_id, f"Unknown job type: {job_type}")
            return

        try:
            # Execute handler within tenant-scoped session
            with session(tenant_id=tenant_id):
                result = handler(task)
            database.bg_tasks.complete_task(task_id, result)
            logger.info("Task %s completed successfully", task_id)
        except Exception as e:
            logger.exception("Task %s failed: %s", task_id, e)
            database.bg_tasks.fail_task(task_id, str(e))


def main() -> None:
    """Entry point for the worker process."""
    # Import job handlers to register them
    # This must happen before creating the worker
    try:
        from jobs import (
            cleanup_exports,  # noqa: F401
            export_events,  # noqa: F401
        )
    except ImportError as e:
        logger.warning("Could not import job handlers: %s", e)

    worker = Worker()

    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, worker.stop)
    signal.signal(signal.SIGINT, worker.stop)

    worker.run()


if __name__ == "__main__":
    main()
