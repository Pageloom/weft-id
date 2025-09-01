import os
from psycopg_pool import ConnectionPool

DATABASE_URL = os.environ.get('DATABASE_URL', '')

pool = ConnectionPool(conninfo=DATABASE_URL)

def execute(query: str, params: tuple = ()) -> list:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            if cur.description:  # If the query returns rows
                return cur.fetchall()
            conn.commit()
            return []


def fetchone(query: str, params: tuple = ()) -> tuple:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            return cur.execute(query, params).fetchone()


def fetchall(query: str, params: tuple = ()) -> list:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchall()


