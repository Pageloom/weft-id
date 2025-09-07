import os
import config
from types import NoneType
from typing import Any, Mapping, Optional
from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row

pool = ConnectionPool(conninfo=config.DATABASE_URL, min_size=1, max_size=10, open=True)

Params = Optional[dict[str, Any]]

def _ensure_mapping(params: Params) -> Params:
    try:
        assert isinstance(params, (dict, NoneType))
    except AssertionError:
        raise RuntimeError('params must be a dict (with string values) or None')
    return params

def execute(query: str, params: Params = None):
    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(query, _ensure_mapping(params))
        return cur.fetchall() if cur.description else []

def fetchone(query: str, params: Params = None) -> Optional[dict]:
    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(query, _ensure_mapping(params))
        return cur.fetchone()

def fetchall(query: str, params: Params = None) -> list[dict]:
    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(query, _ensure_mapping(params))
        return cur.fetchall()

