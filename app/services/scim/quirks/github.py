"""GitHub SCIM quirks.

Iteration 2 stub: re-exports the generic contract unchanged. Iteration 6 will
fill in GitHub-specific behavior (strict PATCH path syntax, `externalId` must
match SAML NameID, forced PATCH on Groups, etc.).
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
