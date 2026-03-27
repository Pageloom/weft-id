"""Background job worker process.

Polls for pending tasks and executes them using registered handlers.
Also runs periodic cleanup tasks.

Run as: python worker.py
"""

import logging
import os
import signal
import time
from collections.abc import Callable
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


def _load_cleanup() -> Any:
    """Import and run the cleanup job."""
    from jobs.cleanup_exports import cleanup_expired_exports

    return cleanup_expired_exports()


def _load_inactivation() -> Any:
    """Import and run the inactivation job."""
    from jobs.inactivate_idle_users import inactivate_idle_users

    return inactivate_idle_users()


def _load_saml_refresh() -> Any:
    """Import and run the SAML metadata refresh job."""
    from jobs.refresh_saml_metadata import refresh_saml_metadata

    return refresh_saml_metadata()


def _load_certificate_rotation() -> Any:
    """Import and run the certificate rotation/cleanup job."""
    from jobs.rotate_certificates import rotate_and_cleanup_certificates

    return rotate_and_cleanup_certificates()


def _load_hibp_check() -> Any:
    """Import and run the HIBP breach check job."""
    from jobs.check_hibp_breaches import check_hibp_breaches

    return check_hibp_breaches()


class PeriodicJob:
    """A periodic background job with interval-based scheduling."""

    __slots__ = ("name", "func", "interval", "last_run")

    def __init__(self, name: str, func: Callable[[], Any], interval: timedelta) -> None:
        self.name = name
        self.func = func
        self.interval = interval
        self.last_run: datetime | None = None


class Worker:
    """Background job worker."""

    def __init__(
        self,
        poll_interval: int = 10,
        cleanup_interval_hours: int = 1,
        inactivation_interval_hours: int = 24,
        saml_refresh_interval_hours: int = 24,
        cert_rotation_interval_hours: int = 24,
        hibp_check_interval_hours: int = 168,
    ) -> None:
        """Initialize the worker.

        Args:
            poll_interval: Seconds between polling for new tasks
            cleanup_interval_hours: Hours between cleanup runs
            inactivation_interval_hours: Hours between idle user inactivation checks
            saml_refresh_interval_hours: Hours between SAML metadata refresh runs
            cert_rotation_interval_hours: Hours between certificate rotation/cleanup checks
            hibp_check_interval_hours: Hours between HIBP breach checks (default: weekly)
        """
        self.poll_interval = poll_interval
        self.running = True
        self._periodic_jobs = [
            PeriodicJob(
                "cleanup",
                _load_cleanup,
                timedelta(hours=cleanup_interval_hours),
            ),
            PeriodicJob(
                "inactivation",
                _load_inactivation,
                timedelta(hours=inactivation_interval_hours),
            ),
            PeriodicJob(
                "SAML metadata refresh",
                _load_saml_refresh,
                timedelta(hours=saml_refresh_interval_hours),
            ),
            PeriodicJob(
                "certificate rotation",
                _load_certificate_rotation,
                timedelta(hours=cert_rotation_interval_hours),
            ),
            PeriodicJob(
                "HIBP breach check",
                _load_hibp_check,
                timedelta(hours=hibp_check_interval_hours),
            ),
        ]

    def stop(self, signum: int | None = None, frame: Any = None) -> None:
        """Handle shutdown signal."""
        logger.info("Received shutdown signal, stopping...")
        self.running = False

    def run(self) -> None:
        """Main worker loop."""
        logger.info("Worker starting, poll interval: %ds", self.poll_interval)
        logger.info("Registered handlers: %s", get_registered_handlers())
        for job in self._periodic_jobs:
            logger.info("%s interval: %s", job.name, job.interval)

        while self.running:
            try:
                self._check_periodic_jobs()

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

    def _check_periodic_jobs(self) -> None:
        """Run periodic jobs whose interval has elapsed."""
        now = datetime.now(UTC)
        for job in self._periodic_jobs:
            if job.last_run is None or now - job.last_run >= job.interval:
                job.last_run = now
                self._run_job(job)

    def _run_job(self, job: PeriodicJob) -> None:
        """Execute a periodic job with logging and error handling."""
        logger.info("Running %s...", job.name)
        try:
            result = job.func()
            logger.info("%s completed: %s", job.name, result)
        except Exception as e:
            logger.exception("%s failed: %s", job.name, e)

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
            bulk_update_users,  # noqa: F401
            cleanup_exports,  # noqa: F401
            export_events,  # noqa: F401
            export_users_template,  # noqa: F401
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
