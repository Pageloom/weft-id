"""Comprehensive tests for the background job worker.

This test file covers the Worker class in worker.py:
- Initialization and default values
- Shutdown handling
- Periodic cleanup timing
- Periodic inactivation timing
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
    assert worker.cleanup_interval == timedelta(hours=1)
    assert worker.inactivation_interval == timedelta(hours=24)
    assert worker.running is True
    assert worker.last_cleanup is None
    assert worker.last_inactivation is None


def test_worker_init_custom_values():
    """Test Worker initializes with custom values."""
    from worker import Worker

    worker = Worker(
        poll_interval=30,
        cleanup_interval_hours=2,
        inactivation_interval_hours=12,
    )

    assert worker.poll_interval == 30
    assert worker.cleanup_interval == timedelta(hours=2)
    assert worker.inactivation_interval == timedelta(hours=12)


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
# Cleanup Timing Tests
# =============================================================================


@patch("worker.datetime")
def test_maybe_run_cleanup_first_run(mock_datetime):
    """Test cleanup runs immediately on first iteration."""
    from worker import Worker

    now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)
    mock_datetime.now.return_value = now

    worker = Worker()
    worker._run_cleanup = MagicMock()

    assert worker.last_cleanup is None

    worker._maybe_run_cleanup()

    worker._run_cleanup.assert_called_once()
    assert worker.last_cleanup == now


@patch("worker.datetime")
def test_maybe_run_cleanup_respects_interval(mock_datetime):
    """Test cleanup doesn't run before interval elapsed."""
    from worker import Worker

    now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)
    mock_datetime.now.return_value = now

    worker = Worker(cleanup_interval_hours=1)
    worker._run_cleanup = MagicMock()
    worker.last_cleanup = now - timedelta(minutes=30)  # Only 30 min ago

    worker._maybe_run_cleanup()

    worker._run_cleanup.assert_not_called()


@patch("worker.datetime")
def test_maybe_run_cleanup_runs_after_interval(mock_datetime):
    """Test cleanup runs after interval has elapsed."""
    from worker import Worker

    now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)
    mock_datetime.now.return_value = now

    worker = Worker(cleanup_interval_hours=1)
    worker._run_cleanup = MagicMock()
    worker.last_cleanup = now - timedelta(hours=2)  # 2 hours ago

    worker._maybe_run_cleanup()

    worker._run_cleanup.assert_called_once()
    assert worker.last_cleanup == now


# =============================================================================
# Inactivation Timing Tests
# =============================================================================


@patch("worker.datetime")
def test_maybe_run_inactivation_first_run(mock_datetime):
    """Test inactivation runs on first iteration."""
    from worker import Worker

    now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)
    mock_datetime.now.return_value = now

    worker = Worker()
    worker._run_inactivation = MagicMock()

    assert worker.last_inactivation is None

    worker._maybe_run_inactivation()

    worker._run_inactivation.assert_called_once()
    assert worker.last_inactivation == now


@patch("worker.datetime")
def test_maybe_run_inactivation_respects_interval(mock_datetime):
    """Test inactivation respects 24h interval."""
    from worker import Worker

    now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)
    mock_datetime.now.return_value = now

    worker = Worker(inactivation_interval_hours=24)
    worker._run_inactivation = MagicMock()
    worker.last_inactivation = now - timedelta(hours=12)  # Only 12 hours ago

    worker._maybe_run_inactivation()

    worker._run_inactivation.assert_not_called()


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
    assert call_args[0][0] == str(task["id"])
    assert "Unknown job type" in call_args[0][1]
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
    assert call_args[0][0] == str(task["id"])
    assert "Handler exploded" in call_args[0][1]
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
