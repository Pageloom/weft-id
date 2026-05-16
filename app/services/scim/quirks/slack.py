"""Slack SCIM quirks.

Iteration 2 stub: re-exports the generic contract unchanged. Iteration 6 will
fill in Slack-specific behavior (schema extension URN handling, `userName` =
email convention, attribute-drop tolerance, etc.).
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
