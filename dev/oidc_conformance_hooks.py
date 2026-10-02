#!/usr/bin/env python3
"""Run the suite's ``run-test-plan.py`` with WeftID's operator hooks.

Some conformance modules pause for a human operator. The suite's runner
cannot act for one, so it starts them anyway and they fail. This wrapper runs
the unmodified runner in-process after patching its ``Conformance`` client:

* ``oidcc-server-rotate-keys`` stops in CONFIGURED and asks the operator to
  rotate the OP's signing keys, then waits for "start". The runner's only
  ``start_test`` call is for that module, so the patched ``start_test``
  rotates the testbed tenant's key (through the app container) first.
* RP modules (``oidcc-client-test*``: the suite plays the OpenID Provider and
  WeftID's upstream connector is the client) sit in WAITING until a client
  starts a sign-in; the runner only knows how to launch the suite's own
  sample clients. When the runner starts waiting for such a module to
  finish, the patched ``wait_for_state`` first ages the connector's
  discovery result past its TTL (each module publishes its own keys and
  ``jwks_uri``) and then walks a WeftID sign-in through the connector: GET
  the connection's login URL and follow the redirects (WeftID -> the suite's
  authorization endpoint, which answers straight away -> WeftID's callback,
  where WeftID exchanges the code and calls userinfo). Everything WeftID does
  after that is between WeftID and the suite; the module judges it.
  The two RP Config discovery modules (``DISCOVERY_ONLY_MODULES``) end as
  soon as the client has fetched discovery (and the JWKS); a sign-in would
  go on to call a finished module, which the suite fails. For them the hook
  runs the admin Test Connection action instead, which fetches exactly those
  two documents.

``dev/oidc_conformance.py`` invokes this with the runner's arguments and the
scripts directory as the working directory, which is where
``run-test-plan.py`` and its ``conformance`` module live.
"""

from __future__ import annotations

import asyncio
import json
import os
import runpy
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

# The runner module sits next to this file; reuse its compose command.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from oidc_conformance import DOCKER_COMPOSE, TESTBED_SCRIPT  # noqa: E402

ROTATE_KEYS_MODULE = "oidcc-server-rotate-keys"
RP_MODULE_PREFIX = "oidcc-client-test"
# RP modules that finish on the discovery (and JWKS) fetch alone; see the
# module docstring.
DISCOVERY_ONLY_MODULES = frozenset(
    {"oidcc-client-test-discovery-openid-config", "oidcc-client-test-discovery-jwks-uri-keys"}
)
# Redirect hops a sign-in may take (WeftID login -> suite authorize -> WeftID
# callback -> WeftID landing page, with room to spare).
MAX_RP_HOPS = 8


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


def expire_rp_discovery(run=subprocess.run) -> None:
    """Age the RP connection's discovery result past the TTL (through the app)."""
    cmd = [*DOCKER_COMPOSE, "exec", "-T", "app", "python", TESTBED_SCRIPT]
    result = run([*cmd, "--expire-rp-discovery-flag"], capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise HookError(f"expiring RP discovery failed (rc={result.returncode}): {result.stderr}")


def test_rp_connection(run=subprocess.run) -> dict:
    """Run the admin Test Connection action on the RP connection (through the app)."""
    cmd = [*DOCKER_COMPOSE, "exec", "-T", "app", "python", TESTBED_SCRIPT]
    result = run([*cmd, "--test-rp-connection-flag"], capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise HookError(f"RP Test Connection failed (rc={result.returncode}): {result.stderr}")
    return json.loads(result.stdout)


def drive_rp_login(login_url: str, client: httpx.Client | None = None) -> list[str]:
    """Walk a WeftID sign-in through the upstream connector; return the hops.

    Follows redirects by hand (no browser: none of the hops renders a page
    that needs one) and stops at the first non-redirect response. The result
    is only logged; the suite module decides pass or fail from what WeftID
    sent it.
    """
    # The dev reverse proxy and the suite both use self-signed certificates.
    owned = client is None
    client = client or httpx.Client(verify=False, timeout=30.0)  # noqa: S501 - dev only
    hops = [login_url]
    try:
        url = login_url
        for _ in range(MAX_RP_HOPS):
            response = client.get(url, follow_redirects=False)
            location = response.headers.get("location")
            if not response.is_redirect or not location:
                hops.append(f"HTTP {response.status_code}")
                break
            url = urljoin(url, location)
            hops.append(url)
    finally:
        if owned:
            client.close()
    return hops


def _describe(url: str) -> str:
    parts = urlsplit(url)
    if not parts.netloc:
        return url
    return f"{parts.netloc}{parts.path}" + ("?" + parts.query[:80] if "error" in parts.query else "")


def run_rp_module(
    module: str,
    login_url: str,
    expire: Callable[[], None] = expire_rp_discovery,
    test_connection: Callable[[], dict] = test_rp_connection,
    sign_in: Callable[[str], list[str]] = drive_rp_login,
) -> None:
    """Drive WeftID for one RP module; failures are reported, not raised.

    The suite module times out and records the failure itself.
    """
    try:
        if module in DISCOVERY_ONLY_MODULES:
            print(f"RP Test Connection: {test_connection()}")
            return
        expire()
        hops = sign_in(login_url)
    except Exception as exc:  # noqa: BLE001 - the module times out and reports it
        print(f"RP module could not be driven: {exc}")
        return
    print("RP sign-in: " + " -> ".join(_describe(hop) for hop in hops))


def install_hooks(
    conformance_cls: type,
    rotate: Callable[[], object],
    rp_driver: Callable[[str], None] | None = None,
) -> None:
    """Patch the suite client for the operator steps (see the module docstring)."""
    original_start = conformance_cls.start_test
    original_wait = conformance_cls.wait_for_state
    driven: set[str] = set()

    async def start_test(self, module_id):
        info = await self.get_module_info(module_id)
        if info.get("testName") == ROTATE_KEYS_MODULE:
            await asyncio.to_thread(rotate)
        return await original_start(self, module_id)

    async def wait_for_state(self, module_id, required_states, *args, **kwargs):
        if rp_driver is not None and list(required_states) == ["FINISHED"]:
            if module_id not in driven:
                info = await self.get_module_info(module_id)
                name = str(info.get("testName", ""))
                if name.startswith(RP_MODULE_PREFIX):
                    driven.add(module_id)
                    await asyncio.to_thread(rp_driver, name)
        return await original_wait(self, module_id, required_states, *args, **kwargs)

    conformance_cls.start_test = start_test
    conformance_cls.wait_for_state = wait_for_state


def main(argv: list[str]) -> None:
    scripts_dir = Path.cwd()
    sys.path.insert(0, str(scripts_dir))
    import conformance  # the suite's client module, downloaded next to the runner

    login_url = os.environ.get("WEFTID_RP_LOGIN_URL", "")
    rp_driver = (lambda module: run_rp_module(module, login_url)) if login_url else None
    install_hooks(conformance.Conformance, rotate_signing_key, rp_driver)
    runner = scripts_dir / "run-test-plan.py"
    sys.argv = [str(runner), *argv]
    runpy.run_path(str(runner), run_name="__main__")


if __name__ == "__main__":
    main(sys.argv[1:])
