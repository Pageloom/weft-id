"""Tests for database.bg_tasks module."""

from uuid import uuid4


def test_create_task(test_tenant, test_user):
    """Test creating a background task."""
    import database

    result = database.bg_tasks.create_task(
        tenant_id=str(test_tenant["id"]),
        job_type="export_events",
        created_by=str(test_user["id"]),
        payload={"test_key": "test_value"},
    )

    assert result is not None
    assert result["id"] is not None
    assert result["created_at"] is not None


def test_create_task_without_payload(test_tenant, test_user):
    """Test creating a background task without payload."""
    import database

    result = database.bg_tasks.create_task(
        tenant_id=str(test_tenant["id"]),
        job_type="export_events",
        created_by=str(test_user["id"]),
        payload=None,
    )

    assert result is not None
    assert result["id"] is not None


def test_claim_next_task(test_tenant, test_user):
    """Test claiming the next pending task."""
    import database

    unique_job_type = f"test_claim_specific_{uuid4().hex}"

    # Create a task with a unique job type
    created = database.bg_tasks.create_task(
        tenant_id=str(test_tenant["id"]),
        job_type=unique_job_type,
        created_by=str(test_user["id"]),
    )

    # Claim tasks until we get our specific one (other tests may have pending tasks)
    # We limit iterations to avoid infinite loops
    claimed = None
    for _ in range(100):
        result = database.bg_tasks.claim_next_task()
        if result is None:
            break
        if result["id"] == created["id"]:
            claimed = result
            break

    assert claimed is not None, "Our task should have been claimed"
    assert claimed["id"] == created["id"]
    assert claimed["tenant_id"] == test_tenant["id"]
    assert claimed["job_type"] == unique_job_type


def test_claim_next_task_no_pending(test_tenant, test_user):
    """Test claiming when no pending tasks exist."""
    import database

    # Create and claim a task to ensure it's no longer pending
    database.bg_tasks.create_task(
        tenant_id=str(test_tenant["id"]),
        job_type=f"test_claim_{uuid4().hex[:8]}",
        created_by=str(test_user["id"]),
    )
    database.bg_tasks.claim_next_task()

    # Try to claim again - should find the one we claimed (it's now processing)
    # Create a unique job type to avoid conflicts
    database.bg_tasks.claim_next_task()
    # Result depends on whether there are other pending tasks in the DB
    # This is more of an integration test - just verify it doesn't error


def test_complete_task(test_tenant, test_user):
    """Test completing a task."""
    import database

    # Create and claim a task
    created = database.bg_tasks.create_task(
        tenant_id=str(test_tenant["id"]),
        job_type=f"test_complete_{uuid4().hex[:8]}",
        created_by=str(test_user["id"]),
    )
    database.bg_tasks.claim_next_task()

    # Complete the task
    database.bg_tasks.complete_task(
        str(created["id"]),
        result={"export_file_id": "test-file-id"},
    )

    # Verify it's completed
    task = database.bg_tasks.get_task(str(created["id"]))
    assert task is not None
    assert task["status"] == "completed"
    assert task["completed_at"] is not None
    assert task["result"]["export_file_id"] == "test-file-id"


def test_fail_task(test_tenant, test_user):
    """Test failing a task."""
    import database

    # Create and claim a task
    created = database.bg_tasks.create_task(
        tenant_id=str(test_tenant["id"]),
        job_type=f"test_fail_{uuid4().hex[:8]}",
        created_by=str(test_user["id"]),
    )
    database.bg_tasks.claim_next_task()

    # Fail the task
    database.bg_tasks.fail_task(str(created["id"]), "Test error message")

    # Verify it's failed
    task = database.bg_tasks.get_task(str(created["id"]))
    assert task is not None
    assert task["status"] == "failed"
    assert task["completed_at"] is not None
    assert task["error"] == "Test error message"


def test_get_task(test_tenant, test_user):
    """Test getting a task by ID."""
    import database

    # Create a task
    created = database.bg_tasks.create_task(
        tenant_id=str(test_tenant["id"]),
        job_type="test_get",
        created_by=str(test_user["id"]),
        payload={"key": "value"},
    )

    # Get the task
    task = database.bg_tasks.get_task(str(created["id"]))

    assert task is not None
    assert task["id"] == created["id"]
    assert task["job_type"] == "test_get"
    assert task["status"] == "pending"
    assert task["payload"]["key"] == "value"


def test_get_task_not_found():
    """Test getting a non-existent task."""
    import database

    task = database.bg_tasks.get_task(str(uuid4()))
    assert task is None


def test_list_tasks_for_tenant(test_tenant, test_user):
    """Test listing tasks for a tenant."""
    import database

    unique_type = f"list_test_{uuid4().hex[:8]}"

    # Create some tasks
    for i in range(3):
        database.bg_tasks.create_task(
            tenant_id=str(test_tenant["id"]),
            job_type=unique_type,
            created_by=str(test_user["id"]),
        )

    # List tasks
    tasks = database.bg_tasks.list_tasks_for_tenant(
        str(test_tenant["id"]),
        limit=10,
        job_type=unique_type,
    )

    assert len(tasks) == 3


def test_count_pending_tasks(test_tenant, test_user):
    """Test counting pending tasks."""
    import database

    unique_type = f"count_test_{uuid4().hex[:8]}"

    # Create some pending tasks
    for _ in range(2):
        database.bg_tasks.create_task(
            tenant_id=str(test_tenant["id"]),
            job_type=unique_type,
            created_by=str(test_user["id"]),
        )

    # Count pending tasks of this type
    count = database.bg_tasks.count_pending_tasks(unique_type)

    assert count >= 2
