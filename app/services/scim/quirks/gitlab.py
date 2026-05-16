"""GitLab SCIM quirks.

Iteration 2 stub: re-exports the generic contract unchanged. Iteration 6 will
fill in GitLab-specific behavior (`externalId` = SAML NameID coupling, group
membership PATCH semantics, etc.).
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
