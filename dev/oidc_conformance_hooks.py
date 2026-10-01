#!/usr/bin/env python3
"""Run the suite's ``run-test-plan.py`` with WeftID's operator hooks.

Some conformance modules pause for a human operator. The suite's runner
cannot act for one, so it starts them anyway and they fail. This wrapper runs
the unmodified runner in-process after patching its ``Conformance`` client:

* ``oidcc-server-rotate-keys`` stops in CONFIGURED and asks the operator to
  rotate the OP's signing keys, then waits for "start". The runner's only
  ``start_test`` call is for that module, so the patched ``start_test``
  rotates the testbed tenant's key (through the app container) first.

``dev/oidc_conformance.py`` invokes this with the runner's arguments and the
scripts directory as the working directory, which is where
``run-test-plan.py`` and its ``conformance`` module live.
"""

from __future__ import annotations

import asyncio
import json
import runpy
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

# The runner module sits next to this file; reuse its compose command.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from oidc_conformance import DOCKER_COMPOSE, TESTBED_SCRIPT  # noqa: E402

ROTATE_KEYS_MODULE = "oidcc-server-rotate-keys"


class HookError(Exception):
    """An operator step could not be completed."""


def rotate_signing_key(run=subprocess.run) -> dict:
    """Rotate the conformance tenant's OIDC signing key; return the new kids."""
    cmd = [*DOCKER_COMPOSE, "exec", "-T", "app", "python", TESTBED_SCRIPT]
    result = run([*cmd, "--rotate-signing-key-flag"], capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise HookError(f"signing-key rotation failed (rc={result.returncode}): {result.stderr}")
    rotated = json.loads(result.stdout)
    print(f"Rotated WeftID signing key: {rotated['previous_kid']} -> {rotated['kid']}")
    return rotated


def install_hooks(conformance_cls: type, rotate: Callable[[], object]) -> None:
    """Patch ``conformance_cls.start_test`` to rotate keys for the rotation module."""
    original = conformance_cls.start_test

    async def start_test(self, module_id):
        info = await self.get_module_info(module_id)
        if info.get("testName") == ROTATE_KEYS_MODULE:
            await asyncio.to_thread(rotate)
        return await original(self, module_id)

    conformance_cls.start_test = start_test


def main(argv: list[str]) -> None:
    scripts_dir = Path.cwd()
    sys.path.insert(0, str(scripts_dir))
    import conformance  # the suite's client module, downloaded next to the runner

    install_hooks(conformance.Conformance, rotate_signing_key)
    runner = scripts_dir / "run-test-plan.py"
    sys.argv = [str(runner), *argv]
    runpy.run_path(str(runner), run_name="__main__")


if __name__ == "__main__":
    main(sys.argv[1:])
