import uuid
from contextlib import contextmanager
from typing import Any, Optional
from decimal import Decimal
from datetime import date, datetime, time, timedelta
from psycopg.types.json import Json
import config
from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row

pool = ConnectionPool(conninfo=config.DATABASE_URL, min_size=1, max_size=10, open=True)


class _Unscoped:
    __slots__ = ()

    def __repr__(self) -> str: return "UNSCOPED"


Params = Optional[dict[str, Any]]

UNSCOPED = _Unscoped()
TenantArg = uuid.UUID | str | _Unscoped

_PG_SCALARS = (
    type(None), bool, int, float, Decimal, str, bytes, bytearray, memoryview,
    uuid.UUID, date, datetime, time, timedelta, Json,
)


def _is_pg_value(value: Any) -> bool:
    """Recursively validate values as PostgreSQL-adaptable."""
    if isinstance(value, _PG_SCALARS):
        return True
    # Arrays: lists/tuples of valid scalars (homogeneous not enforced here)
    if isinstance(value, (list, tuple)):
        return all(_is_pg_value(v) for v in value)
    # NOTE: plain dict is NOT accepted; wrap JSON with psycopg.types.json.Json
    return False


def _validate_params(params: Params) -> Params:
    if params is None:
        return None
    assert isinstance(params, dict)
    for k, v in params.items():
        assert isinstance(k, str)
        if not _is_pg_value(v):
            t = type(v).__name__
            hint = ""
            if isinstance(v, dict):
                hint = " (wrap JSON with psycopg.types.json.Json(value))"
            raise RuntimeError(f"param '{k}' has unsupported type {t}{hint}")
    return params


def _normalize_tenant_id(tenant_id: TenantArg) -> Optional[str]:
    """Return UUID string if scoped, None if UNSCOPED; raise on bad value."""
    if tenant_id is UNSCOPED:
        return None
    if isinstance(tenant_id, uuid.UUID):
        return str(tenant_id)
    try:
        return str(uuid.UUID(str(tenant_id)))
    except Exception as e:
        raise ValueError("tenant_id must be a UUID/uuid-like string or UNSCOPED") from e


def _maybe_set_local(cur, tenant_id: TenantArg) -> None:
    tid = _normalize_tenant_id(tenant_id)
    if tid is not None:
        # Transaction-scoped so it auto-clears at the end of this block
        cur.execute("set local app.tenant_id = %s", (tid,))


@contextmanager
def session(*, tenant_id: TenantArg):
    """
    Open a pooled connection + transaction + dict-row cursor.
    If tenant_id is a UUID/uuid-string, sets `SET LOCAL app.tenant_id = ...`.
    If tenant_id is UNSCOPED, no tenant guard is set.
    Commits on success; rolls back on exception.
    """
    with pool.connection() as conn, conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
        tid = _normalize_tenant_id(tenant_id)
        if tid is not None:
            cur.execute("set local app.tenant_id = %s", (tid,))
        yield cur


def execute(tenant_id: TenantArg, query: str, params: Params = None) -> int:
    """ Executes a statement and returns the number of affected rows. """
    with session(tenant_id=tenant_id) as cur:
        return cur.execute(query, _validate_params(params))


def fetchone(tenant_id: TenantArg, query: str, params: Params = None) -> Optional[dict]:
    """ Return a single row (dict) or None. """
    with session(tenant_id=tenant_id) as cur:
        cur.execute(query, _validate_params(params))
        return cur.fetchone()


def fetchall(tenant_id: TenantArg, query: str, params: Params = None) -> list[dict]:
    """ Return all rows (list[dict]). """
    with session(tenant_id=tenant_id) as cur:
        cur.execute(query, _validate_params(params))
        return cur.fetchall()
