"""Background tasks schemas."""

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field, computed_field


class JobStatus(str, Enum):
    """Background job status values."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class JobListItem(BaseModel):
    """Background job list item for UI display."""

    id: str
    job_type: str
    status: JobStatus
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    result: dict | None = None
    created_by: str

    @computed_field  # type: ignore[misc]
    @property
    def has_output(self) -> bool:
        """Check if job has displayable output."""
        return bool(self.result and self.result.get("output"))

    @computed_field  # type: ignore[misc]
    @property
    def has_download(self) -> bool:
        """Check if job has a downloadable file."""
        return bool(self.result and self.result.get("file_id"))

    @computed_field  # type: ignore[misc]
    @property
    def download_expired(self) -> bool:
        """Check if download file has expired (> 24 hours).

        Returns True if job was created more than 24 hours ago.
        No actual file existence check is performed.
        """
        if not self.has_download:
            return False
        from datetime import timedelta

        return datetime.now(UTC) - self.created_at > timedelta(hours=24)

    @computed_field  # type: ignore[misc]
    @property
    def is_deletable(self) -> bool:
        """Check if job can be deleted (completed or failed)."""
        return self.status in (JobStatus.COMPLETED, JobStatus.FAILED)


class JobDetail(JobListItem):
    """Full job details including all fields."""

    pass


class JobListResponse(BaseModel):
    """Response for job list endpoint."""

    jobs: list[JobListItem]
    has_active_jobs: bool = Field(
        ...,
        description="Whether any jobs are in pending or processing state (for UI polling)",
    )
