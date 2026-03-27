"""Schemas for bulk user attribute update."""

from pydantic import BaseModel


class RowError(BaseModel):
    """Error detail for a single row in bulk upload."""

    row: int
    user_id: str | None = None
    error: str


class BulkUpdateSummary(BaseModel):
    """Summary of bulk update processing results."""

    emails_added: int
    names_updated: int
    rows_skipped: int
    row_errors: list[RowError]
    total_rows: int
