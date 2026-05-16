"""Atlassian SCIM quirks.

Iteration 2 stub: re-exports the generic contract unchanged. Iteration 6 will
fill in Atlassian-specific behavior (rejects empty PATCH value arrays, group
naming constraints, partial `meta` field tolerance, etc.).
"""

from .generic import (
    interpret_error,
    transform_group_payload,
    transform_patch_ops,
    transform_user_payload,
)

__all__ = [
    "interpret_error",
    "transform_group_payload",
    "transform_patch_ops",
    "transform_user_payload",
]
