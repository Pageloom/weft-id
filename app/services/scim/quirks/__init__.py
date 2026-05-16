"""Quirk-module registry.

Maps `service_providers.scim_kind` values to a module that implements the
quirk contract documented in `generic.py`. Unknown kinds resolve to `generic`
with a logged warning so a misconfigured SP degrades safely rather than
crashing the worker.
"""

from __future__ import annotations

import logging
from types import ModuleType

from . import atlassian, generic, github, gitlab, slack

_logger = logging.getLogger(__name__)

# Registered vendor modules. Add new entries here when a quirk module lands
# (iteration 6 fills in the four day-one modules' transforms; the registry
# entries themselves do not change).
_REGISTRY: dict[str, ModuleType] = {
    "generic": generic,
    "slack": slack,
    "github": github,
    "atlassian": atlassian,
    "gitlab": gitlab,
}


def get_quirk_module(scim_kind: str | None) -> ModuleType:
    """Return the quirk module for `scim_kind`, or `generic` on unknown values.

    Unknown or empty `scim_kind` values log a warning and fall back to the
    generic module. The client never raises on this path -- the design
    decision is "safe degradation, not refusal."
    """
    if not scim_kind:
        _logger.warning("scim_kind is empty or null; falling back to generic quirk module")
        return generic
    module = _REGISTRY.get(scim_kind)
    if module is None:
        _logger.warning(
            "Unknown scim_kind %r; falling back to generic quirk module",
            scim_kind,
        )
        return generic
    return module


__all__ = ["get_quirk_module"]
