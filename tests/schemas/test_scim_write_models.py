"""Tests for the SCIM write-path Pydantic models.

The routers currently accept raw `dict` bodies, so these models are not
wired into request validation yet. The `max_length` bounds are present
so the models are safe to adopt as typed bodies later; these tests pin
the bounds (and that valid payloads still parse).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.scim import ScimGroupWrite, ScimPatchOperation, ScimUserWrite


def test_user_write_accepts_normal_payload():
    model = ScimUserWrite(
        userName="alice@example.com",
        externalId="00u123",
        displayName="Alice Example",
    )
    assert model.userName == "alice@example.com"


@pytest.mark.parametrize(
    "field,length",
    [
        ("userName", 321),
        ("externalId", 256),
        ("displayName", 256),
    ],
)
def test_user_write_rejects_overlong_strings(field, length):
    with pytest.raises(ValidationError):
        ScimUserWrite(**{field: "x" * length})


@pytest.mark.parametrize(
    "field,length",
    [
        ("externalId", 256),
        ("displayName", 256),
    ],
)
def test_group_write_rejects_overlong_strings(field, length):
    with pytest.raises(ValidationError):
        ScimGroupWrite(**{field: "x" * length})


def test_patch_operation_rejects_overlong_op_and_path():
    with pytest.raises(ValidationError):
        ScimPatchOperation(op="r" * 21)
    with pytest.raises(ValidationError):
        ScimPatchOperation(op="replace", path="p" * 513)


def test_patch_operation_accepts_normal_values():
    op = ScimPatchOperation(op="replace", path="displayName", value="x")
    assert op.op == "replace"
