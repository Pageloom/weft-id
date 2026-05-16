"""Outbound SCIM client package.

Exposes the generic SCIM 2.0 client used by the push worker (iteration 4)
to provision users and groups into downstream Service Providers. Per-vendor
behavior diverges through quirk modules under `services.scim.quirks`.

This package contains pure transport, payload, and retry logic. The queue,
dispatch, and worker layers live elsewhere and are introduced in later
iterations.
"""

from .client import (
    PushResult,
    delete_group,
    delete_user,
    push_group,
    push_user,
)
from .payload import build_group_resource, build_user_resource

__all__ = [
    "PushResult",
    "build_group_resource",
    "build_user_resource",
    "delete_group",
    "delete_user",
    "push_group",
    "push_user",
]
