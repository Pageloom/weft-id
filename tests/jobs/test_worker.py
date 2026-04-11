"""Comprehensive tests for the background job worker.

This test file covers the Worker class in worker.py:
- Initialization and default values
- Shutdown handling
- Periodic job scheduling (_check_periodic_jobs)
- Periodic job execution (_run_job)
- Job loader functions (_load_cleanup, _load_inactivation, etc.)
- Task processing (success, unknown handler, exception)
- Tenant-scoped session usage
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

# =============================================================================
# Helper Functions
# =============================================================================


def _make_task(
    task_id: str | None = None,
    job_type: str = "export_events",
    tenant_id: str | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a test task dict."""
    return {
        "id": task_id or str(uuid4()),
        "job_type": job_type,
        "tenant_id": tenant_id or str(uuid4()),
        "payload": payload,
    }


# =============================================================================
# Worker Initialization Tests
# =============================================================================


def test_worker_init_defaults():
    """Test Worker initializes with correct default values."""
    from worker import Worker

    worker = Worker()

    assert worker.poll_interval == 10
    assert worker.running is True
    assert len(worker._periodic_jobs) == 6

    cleanup = worker._periodic_jobs[0]
    assert cleanup.name == "cleanup"
    assert cleanup.interval == timedelta(hours=1)
    assert cleanup.last_run is None

    inactivation = worker._periodic_jobs[1]
    assert inactivation.name == "inactivation"
    assert inactivation.interval == timedelta(hours=24)
    assert inactivation.last_run is None

    saml = worker._periodic_jobs[2]
    assert saml.name == "SAML metadata refresh"
    assert saml.interval == timedelta(hours=24)
    assert saml.last_run is None

    cert_rotation = worker._periodic_jobs[3]
    assert cert_rotation.name == "certificate rotation"
    assert cert_rotation.interval == timedelta(hours=24)
    assert cert_rotation.last_run is None

    hibp_check = worker._periodic_jobs[4]
    assert hibp_check.name == "HIBP breach check"
    assert hibp_check.interval == timedelta(hours=168)
    assert hibp_check.last_run is None


def test_worker_init_custom_values():
    """Test Worker initializes with custom values."""
    from worker import Worker

    worker = Worker(
        poll_interval=30,
        cleanup_interval_hours=2,
        inactivation_interval_hours=12,
        saml_refresh_interval_hours=6,
    )

    assert worker.poll_interval == 30
    assert worker._periodic_jobs[0].interval == timedelta(hours=2)
    assert worker._periodic_jobs[1].interval == timedelta(hours=12)
    assert worker._periodic_jobs[2].interval == timedelta(hours=6)


def test_worker_stop_sets_running_false():
    """Test stop() method sets running to False."""
    from worker import Worker

    worker = Worker()
    assert worker.running is True

    worker.stop()

    assert worker.running is False


def test_worker_stop_with_signal_args():
    """Test stop() accepts signal handler arguments."""
    from worker import Worker

    worker = Worker()

    # Should accept signum and frame like a signal handler
    worker.stop(signum=15, frame=None)

    assert worker.running is False


# =============================================================================
# Periodic Job Scheduling Tests
# =============================================================================


@patch("worker.datetime")
def test_check_periodic_jobs_first_run(mock_datetime):
    """Test all periodic jobs run on first iteration (last_run is None)."""
    from worker import Worker

    now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)
    mock_datetime.now.return_value = now

    worker = Worker()
    worker._run_job = MagicMock()

    worker._check_periodic_jobs()

    assert worker._run_job.call_count == 6
    for job in worker._periodic_jobs:
        assert job.last_run == now


@patch("worker.datetime")
def test_check_periodic_jobs_respects_interval(mock_datetime):
    """Test jobs don't run before their interval has elapsed."""
    from worker import Worker

    now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)
    mock_datetime.now.return_value = now

    worker = Worker(cleanup_interval_hours=1)
    worker._run_job = MagicMock()
    # Set all as recently run (30 min ago, well within all intervals)
    for job in worker._periodic_jobs:
        job.last_run = now - timedelta(minutes=30)

    worker._check_periodic_jobs()

    worker._run_job.assert_not_called()


@patch("worker.datetime")
def test_check_periodic_jobs_runs_overdue_only(mock_datetime):
    """Test only jobs whose interval has elapsed are run."""
    from worker import Worker

    now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)
    mock_datetime.now.return_value = now

    worker = Worker(cleanup_interval_hours=1)
    worker._run_job = MagicMock()
    # Only cleanup is overdue (2h ago vs 1h interval)
    worker._periodic_jobs[0].last_run = now - timedelta(hours=2)
    worker._periodic_jobs[1].last_run = now - timedelta(minutes=5)
    worker._periodic_jobs[2].last_run = now - timedelta(minutes=5)
    worker._periodic_jobs[3].last_run = now - timedelta(minutes=5)
    worker._periodic_jobs[4].last_run = now - timedelta(minutes=5)
    worker._periodic_jobs[5].last_run = now - timedelta(minutes=5)

    old_last_run_1 = worker._periodic_jobs[1].last_run
    old_last_run_2 = worker._periodic_jobs[2].last_run
    old_last_run_3 = worker._periodic_jobs[3].last_run
    old_last_run_4 = worker._periodic_jobs[4].last_run
    old_last_run_5 = worker._periodic_jobs[5].last_run

    worker._check_periodic_jobs()

    worker._run_job.assert_called_once()
    assert worker._run_job.call_args[0][0].name == "cleanup"
    assert worker._periodic_jobs[0].last_run == now
    # Others unchanged
    assert worker._periodic_jobs[1].last_run == old_last_run_1
    assert worker._periodic_jobs[2].last_run == old_last_run_2
    assert worker._periodic_jobs[3].last_run == old_last_run_3
    assert worker._periodic_jobs[4].last_run == old_last_run_4
    assert worker._periodic_jobs[5].last_run == old_last_run_5


# =============================================================================
# Job Execution Tests
# =============================================================================


def test_run_job_success():
    """Test _run_job calls the job function successfully."""
    from worker import PeriodicJob, Worker

    mock_func = MagicMock(return_value={"items": 5})
    job = PeriodicJob("test_job", mock_func, timedelta(hours=1))

    worker = Worker()
    worker._run_job(job)

    mock_func.assert_called_once()


def test_run_job_exception():
    """Test _run_job handles exceptions without raising."""
    from worker import PeriodicJob, Worker

    mock_func = MagicMock(side_effect=RuntimeError("Job exploded"))
    job = PeriodicJob("test_job", mock_func, timedelta(hours=1))

    worker = Worker()
    # Should not raise, just log
    worker._run_job(job)

    mock_func.assert_called_once()


# =============================================================================
# Job Loader Function Tests
# =============================================================================


@patch("jobs.cleanup_exports.cleanup_expired_exports")
def test_load_cleanup(mock_cleanup):
    """Test _load_cleanup imports and calls cleanup_expired_exports."""
    from worker import _load_cleanup

    mock_cleanup.return_value = {"deleted_files": 5}

    result = _load_cleanup()

    mock_cleanup.assert_called_once()
    assert result == {"deleted_files": 5}


@patch("jobs.inactivate_idle_users.inactivate_idle_users")
def test_load_inactivation(mock_inactivation):
    """Test _load_inactivation imports and calls inactivate_idle_users."""
    from worker import _load_inactivation

    mock_inactivation.return_value = {"inactivated_count": 3}

    result = _load_inactivation()

    mock_inactivation.assert_called_once()
    assert result == {"inactivated_count": 3}


@patch("jobs.refresh_saml_metadata.refresh_saml_metadata")
def test_load_saml_refresh(mock_refresh):
    """Test _load_saml_refresh imports and calls refresh_saml_metadata."""
    from worker import _load_saml_refresh

    mock_refresh.return_value = {"refreshed_count": 2}

    result = _load_saml_refresh()

    mock_refresh.assert_called_once()
    assert result == {"refreshed_count": 2}


@patch("jobs.rotate_certificates.rotate_and_cleanup_certificates")
def test_load_certificate_rotation(mock_rotate):
    """Test _load_certificate_rotation imports and calls the job."""
    from worker import _load_certificate_rotation

    mock_rotate.return_value = {"rotated": 1, "cleaned_up": 2, "errors": []}

    result = _load_certificate_rotation()

    mock_rotate.assert_called_once()
    assert result == {"rotated": 1, "cleaned_up": 2, "errors": []}


# =============================================================================
# Task Processing Tests
# =============================================================================


@patch("worker.session")
@patch("worker.get_handler")
@patch("worker.database")
def test_process_task_success(mock_database, mock_get_handler, mock_session):
    """Test successful task processing calls handler and completes task."""
    from worker import Worker

    task = _make_task()
    handler = MagicMock(return_value={"success": True})
    mock_get_handler.return_value = handler

    # Mock session context manager
    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    worker = Worker()
    worker._process_task(task)

    mock_get_handler.assert_called_once_with(task["job_type"])
    handler.assert_called_once_with(task)
    mock_database.bg_tasks.complete_task.assert_called_once_with(str(task["id"]), {"success": True})
    mock_database.bg_tasks.fail_task.assert_not_called()


@patch("worker.get_handler")
@patch("worker.database")
def test_process_task_unknown_handler(mock_database, mock_get_handler):
    """Test unknown job type fails the task."""
    from worker import Worker

    task = _make_task(job_type="unknown_job_type")
    mock_get_handler.return_value = None

    worker = Worker()
    worker._process_task(task)

    mock_get_handler.assert_called_once_with("unknown_job_type")
    mock_database.bg_tasks.fail_task.assert_called_once()
    call_args = mock_database.bg_tasks.fail_task.call_args
    task_id, error_message = call_args[0]
    assert task_id == str(task["id"])
    assert "Unknown job type" in error_message
    mock_database.bg_tasks.complete_task.assert_not_called()


@patch("worker.session")
@patch("worker.get_handler")
@patch("worker.database")
def test_process_task_handler_exception(mock_database, mock_get_handler, mock_session):
    """Test handler exception fails the task with error message."""
    from worker import Worker

    task = _make_task()
    handler = MagicMock(side_effect=ValueError("Handler exploded"))
    mock_get_handler.return_value = handler

    # Mock session context manager
    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    worker = Worker()
    worker._process_task(task)

    mock_database.bg_tasks.fail_task.assert_called_once()
    call_args = mock_database.bg_tasks.fail_task.call_args
    task_id, error_message = call_args[0]
    assert task_id == str(task["id"])
    assert "Handler exploded" in error_message
    mock_database.bg_tasks.complete_task.assert_not_called()


@patch("worker.session")
@patch("worker.get_handler")
@patch("worker.database")
def test_process_task_uses_tenant_scoped_session(mock_database, mock_get_handler, mock_session):
    """Test task processing uses tenant-scoped session for RLS."""
    from worker import Worker

    tenant_id = str(uuid4())
    task = _make_task(tenant_id=tenant_id)
    handler = MagicMock(return_value={})
    mock_get_handler.return_value = handler

    # Mock session context manager
    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    worker = Worker()
    worker._process_task(task)

    # Verify session was created with correct tenant_id
    mock_session.assert_called_once_with(tenant_id=tenant_id)


# =============================================================================
# Main Worker Loop Tests
# =============================================================================


@patch("worker.time.sleep")
@patch("worker.database")
def test_worker_run_stops_when_running_false(mock_database, mock_sleep):
    """Test worker loop exits when running is set to False."""
    from worker import Worker

    mock_database.bg_tasks.claim_next_task.return_value = None

    worker = Worker(poll_interval=1)
    worker._check_periodic_jobs = MagicMock()

    # Stop after first sleep
    def stop_after_first_call(*args):
        worker.running = False

    mock_sleep.side_effect = stop_after_first_call

    worker.run()

    worker._check_periodic_jobs.assert_called()
    mock_database.bg_tasks.claim_next_task.assert_called()


@patch("worker.time.sleep")
@patch("worker.database")
def test_worker_run_processes_task_when_available(mock_database, mock_sleep):
    """Test worker loop processes task when one is claimed."""
    from worker import Worker

    task = _make_task()
    # First call returns task, second call returns None (to allow loop exit)
    mock_database.bg_tasks.claim_next_task.side_effect = [task, None]

    worker = Worker(poll_interval=1)
    worker._check_periodic_jobs = MagicMock()
    worker._process_task = MagicMock()

    # Stop after processing
    def stop_after_sleep(*args):
        worker.running = False

    mock_sleep.side_effect = stop_after_sleep

    worker.run()

    # Should have processed the task
    worker._process_task.assert_called_once_with(task)


@patch("worker.time.sleep")
@patch("worker.database")
def test_worker_run_handles_exception_and_continues(mock_database, mock_sleep):
    """Test worker loop handles exceptions without crashing."""
    from worker import Worker

    # First call raises, second call returns None
    mock_database.bg_tasks.claim_next_task.side_effect = [
        RuntimeError("Database exploded"),
        None,
    ]

    worker = Worker(poll_interval=1)
    worker._check_periodic_jobs = MagicMock()

    call_count = [0]

    def stop_after_two_sleeps(*args):
        call_count[0] += 1
        if call_count[0] >= 2:
            worker.running = False

    mock_sleep.side_effect = stop_after_two_sleeps

    # Should not raise
    worker.run()

    # Should have slept twice (once after exception, once after no task)
    assert mock_sleep.call_count >= 2


# =============================================================================
# main() Entry Point Tests
# =============================================================================


@patch("worker.Worker")
@patch("worker.signal.signal")
def test_main_imports_job_handlers(mock_signal, mock_worker_class):
    """Test main() imports job handlers before creating worker."""
    from worker import main

    mock_worker = MagicMock()
    mock_worker_class.return_value = mock_worker
    mock_worker.run.side_effect = KeyboardInterrupt  # Exit immediately

    try:
        main()
    except KeyboardInterrupt:
        pass

    # Worker should have been created
    mock_worker_class.assert_called_once()


@patch("worker.Worker")
@patch("worker.signal.signal")
def test_main_sets_up_signal_handlers(mock_signal, mock_worker_class):
    """Test main() registers signal handlers for graceful shutdown."""
    import signal as sig

    from worker import main

    mock_worker = MagicMock()
    mock_worker_class.return_value = mock_worker
    mock_worker.run.side_effect = KeyboardInterrupt  # Exit immediately

    try:
        main()
    except KeyboardInterrupt:
        pass

    # Should register SIGTERM and SIGINT handlers
    signal_calls = [call[0][0] for call in mock_signal.call_args_list]
    assert sig.SIGTERM in signal_calls
    assert sig.SIGINT in signal_calls


@patch("worker.Worker")
@patch("worker.signal.signal")
def test_main_runs_worker(mock_signal, mock_worker_class):
    """Test main() calls worker.run()."""
    from worker import main

    mock_worker = MagicMock()
    mock_worker_class.return_value = mock_worker
    mock_worker.run.return_value = None

    main()

    mock_worker.run.assert_called_once()


@patch("worker.Worker")
@patch("worker.signal.signal")
@patch("worker.logger")
def test_main_handles_import_failure(mock_logger, mock_signal, mock_worker_class):
    """Test main() logs warning if job handlers can't be imported."""
    import builtins

    from worker import main

    mock_worker = MagicMock()
    mock_worker_class.return_value = mock_worker
    mock_worker.run.return_value = None

    # Simulate ImportError by making the import fail
    original_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "jobs" or name.startswith("jobs."):
            raise ImportError("Mocked import failure")
        return original_import(name, *args, **kwargs)

    with patch.object(builtins, "__import__", side_effect=mock_import):
        main()

    # Worker should still run despite import failure
    mock_worker.run.assert_called_once()
    # Logger should have warned about import failure
    mock_logger.warning.assert_called_once()
    warning_message = mock_logger.warning.call_args[0][0]
    assert "Could not import job handlers" in warning_message
