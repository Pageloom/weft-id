"""Comprehensive tests for Job Registry.

This test file covers all functions in jobs/registry.py.
Tests include:
- Handler registration via decorator
- Retrieving registered handlers
- Listing all handlers
- Handler execution
"""

# =============================================================================
# Handler Registration Tests
# =============================================================================


def test_register_handler_decorator():
    """Test that register_handler decorator registers a handler."""
    from jobs.registry import get_handler, register_handler

    @register_handler("test_job")
    def test_handler(task: dict) -> dict:
        return {"result": "success"}

    # Verify handler was registered
    handler = get_handler("test_job")
    assert handler is not None
    assert handler == test_handler


def test_register_handler_executes_function():
    """Test that registered handler can be executed."""
    from jobs.registry import get_handler, register_handler

    @register_handler("test_execution")
    def execute_handler(task: dict) -> dict:
        return {"task_id": task["id"], "status": "completed"}

    handler = get_handler("test_execution")
    result = handler({"id": "task-123"})

    assert result["task_id"] == "task-123"
    assert result["status"] == "completed"


def test_register_handler_preserves_function():
    """Test that decorator returns the original function."""
    from jobs.registry import register_handler

    @register_handler("test_preserve")
    def preserved_handler(task: dict) -> dict:
        """Test docstring."""
        return {"data": "test"}

    # Function should be preserved
    assert preserved_handler.__name__ == "preserved_handler"
    assert preserved_handler.__doc__ == "Test docstring."


def test_register_multiple_handlers():
    """Test registering multiple different handlers."""
    from jobs.registry import get_handler, register_handler

    @register_handler("handler_one")
    def handler_one(task: dict) -> dict:
        return {"type": "one"}

    @register_handler("handler_two")
    def handler_two(task: dict) -> dict:
        return {"type": "two"}

    # Both should be registered
    assert get_handler("handler_one") == handler_one
    assert get_handler("handler_two") == handler_two


def test_register_handler_override():
    """Test that registering same job type twice overrides previous handler."""
    from jobs.registry import get_handler, register_handler

    @register_handler("test_override")
    def first_handler(task: dict) -> dict:
        return {"version": "first"}

    @register_handler("test_override")
    def second_handler(task: dict) -> dict:
        return {"version": "second"}

    # Second handler should override first
    handler = get_handler("test_override")
    assert handler == second_handler
    result = handler({})
    assert result["version"] == "second"


# =============================================================================
# Get Handler Tests
# =============================================================================


def test_get_handler_not_found():
    """Test get_handler returns None for unregistered job type."""
    from jobs.registry import get_handler

    handler = get_handler("nonexistent_job_type")
    assert handler is None


def test_get_handler_returns_correct_handler():
    """Test get_handler returns the correct handler for a job type."""
    from jobs.registry import get_handler, register_handler

    @register_handler("specific_job")
    def specific_handler(task: dict) -> dict:
        return {"specific": True}

    handler = get_handler("specific_job")
    assert handler is not None
    result = handler({})
    assert result["specific"] is True


# =============================================================================
# Get Registered Handlers Tests
# =============================================================================


def test_get_registered_handlers_empty():
    """Test get_registered_handlers when no handlers are registered."""
    from jobs.registry import _handlers, get_registered_handlers

    # Clear handlers first
    _handlers.clear()

    handlers = get_registered_handlers()
    assert handlers == []


def test_get_registered_handlers_returns_list():
    """Test get_registered_handlers returns a list of handler names."""
    from jobs.registry import _handlers, get_registered_handlers, register_handler

    # Clear handlers first
    _handlers.clear()

    @register_handler("test_list_one")
    def handler_one(task: dict) -> dict:
        return {}

    @register_handler("test_list_two")
    def handler_two(task: dict) -> dict:
        return {}

    handlers = get_registered_handlers()
    assert isinstance(handlers, list)
    assert "test_list_one" in handlers
    assert "test_list_two" in handlers
    assert len(handlers) == 2


def test_get_registered_handlers_with_real_handler():
    """Test get_registered_handlers after registering a handler."""
    from jobs.registry import _handlers, get_registered_handlers, register_handler

    # Clear handlers first to avoid interference from other imports
    _handlers.clear()

    @register_handler("test_real_handler")
    def real_handler(task: dict) -> dict:
        return {}

    handlers = get_registered_handlers()

    # Should include our registered handler
    assert "test_real_handler" in handlers


# =============================================================================
# Handler Execution Tests
# =============================================================================


def test_handler_with_return_value():
    """Test handler that returns a dict."""
    from jobs.registry import get_handler, register_handler

    @register_handler("test_return")
    def handler_with_return(task: dict) -> dict:
        return {"output": "test output", "records_processed": 10}

    handler = get_handler("test_return")
    result = handler({"id": "task-1"})

    assert result is not None
    assert result["output"] == "test output"
    assert result["records_processed"] == 10


def test_handler_with_none_return():
    """Test handler that returns None."""
    from jobs.registry import get_handler, register_handler

    @register_handler("test_none")
    def handler_with_none(task: dict) -> None:
        # Handler that doesn't return anything
        pass

    handler = get_handler("test_none")
    result = handler({"id": "task-2"})

    assert result is None


def test_handler_receives_task_parameter():
    """Test that handler receives the task parameter correctly."""
    from jobs.registry import get_handler, register_handler

    @register_handler("test_task_param")
    def handler_with_task(task: dict) -> dict:
        return {
            "task_id": task["id"],
            "tenant_id": task["tenant_id"],
            "job_type": task["job_type"],
        }

    handler = get_handler("test_task_param")
    result = handler(
        {
            "id": "123",
            "tenant_id": "tenant-456",
            "job_type": "test",
        }
    )

    assert result["task_id"] == "123"
    assert result["tenant_id"] == "tenant-456"
    assert result["job_type"] == "test"
