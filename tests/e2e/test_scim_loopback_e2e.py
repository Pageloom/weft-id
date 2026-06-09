"""Closed-loop SCIM E2E test (WeftID outbound -> WeftID inbound).

Points WeftID's outbound SCIM at WeftID's own inbound SCIM endpoint for a
separate receiving tenant, closing the loop entirely inside the Docker E2E
stack with no external receiver. It is a self-consistency check (the Generic
SCIM 2.0 payloads we emit must parse cleanly in our own inbound parser) and a
regression guard against either side drifting from the contract.

Provisioning is via the headless `dev/scim_loopback_testbed.py` script (run
inside the app container). The worker drain is triggered on demand via
`docker compose exec worker`. All assertions are SQL via `psql` (no browser).

Iteration 1 covers the provision (POST) path:
  - source members provisioned as active users in the receiving tenant
  - the granted group materialised as `group_type='idp'` in the receiver
  - `sp_scim_remote_ids` rows captured for users + group
  - every push reaches `done`; none dead-lettered

Iteration 2 walks the rest of the lifecycle against the SAME module-scoped
test bed (E2E runs sequentially, `-n 0`, so class/method definition order is
the execution order):
  - update: an attribute change propagates via PUT /Users/<remote_id> reusing
    the captured remote id (no duplicate POST)
  - membership round-trip: the receiver idp group's members match the source
    group's members, compared by remote id
  - deprovision: removing the grant drives DELETE /Users/<remote_id> and the
    receiver user is soft-deleted (is_inactivated=true) with MFA/history kept
  - across provision->update->deprovision, zero dead-letters (the headline
    self-consistency check)

Test ordering is load-bearing: `TestScimLoopbackProvision` must run first,
then the update/membership tests, then deprovision, then the lifecycle
dead-letter sweep. Pytest preserves definition order within a module, so the
classes are defined in that sequence.
"""

import json
import subprocess
import time

import pytest

from tests.e2e.conftest import DOCKER_COMPOSE

SRC_SUBDOMAIN = "e2e-scim-src"
DST_SUBDOMAIN = "e2e-scim-dst"

_TESTBED = "./dev/scim_loopback_testbed.py"


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------


def _run_sql(sql: str) -> str:
    """Execute a single SQL statement against the dev DB, return stdout."""
    result = subprocess.run(
        [
            *DOCKER_COMPOSE,
            "exec",
            "-T",
            "db",
            "psql",
            "-U",
            "postgres",
            "-d",
            "appdb",
            "-At",  # tuples-only, unaligned
            "-c",
            sql,
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(f"SQL failed (rc={result.returncode}): {result.stderr}\nSQL: {sql}")
    return result.stdout.strip()


def _run_testbed(*extra_args: str, timeout: int = 90) -> str:
    """Run the loopback testbed inside the app container; return stdout."""
    cmd = [
        *DOCKER_COMPOSE,
        "exec",
        "-T",
        "app",
        "python",
        _TESTBED,
        "--src-subdomain",
        SRC_SUBDOMAIN,
        "--dst-subdomain",
        DST_SUBDOMAIN,
        *extra_args,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"loopback testbed failed (rc={result.returncode}):\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result.stdout


def _drain_scim_queue() -> dict:
    """Trigger one worker drain pass on demand; return the summary dict.

    Invokes `process_scim_push_queue()` in the worker container (which shares
    the app image/source). The worker resolves outbound tokens from
    `sp_scim_credentials`, so the credential must already be stored.
    """
    cmd = [
        *DOCKER_COMPOSE,
        "exec",
        "-T",
        "worker",
        "python",
        "-c",
        "from jobs.process_scim_push_queue import process_scim_push_queue; "
        "import json; print(json.dumps(process_scim_push_queue()))",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(
            f"drain failed (rc={result.returncode}):\nstdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )
    # The worker logs to stdout too; the JSON summary is the last line.
    last_line = result.stdout.strip().splitlines()[-1]
    return json.loads(last_line)


def _drain_until_idle(src_tenant_id: str, max_passes: int = 6) -> None:
    """Drain repeatedly until no ready queue rows remain for the source tenant.

    A single drain pass may push a group before its members have remote ids
    (the member rows are then re-enqueued), so we drain in a short bounded
    loop rather than once. Stops when the queue is empty of ready rows or
    `max_passes` is exhausted (the caller asserts on terminal state).
    """
    for _ in range(max_passes):
        _drain_scim_queue()
        ready = _run_sql(
            "SELECT count(*) FROM scim_push_queue "
            f"WHERE tenant_id = '{src_tenant_id}' "
            "AND dead_letter_at IS NULL "
            "AND (next_attempt_at IS NULL OR next_attempt_at <= now());"
        )
        if ready == "0":
            return
        time.sleep(0.5)


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def loopback_config():
    """Provision the closed-loop SCIM test bed; yield its JSON config.

    Tears down before (clearing stale data from any interrupted run) and
    after the module. Module-scoped so iteration 2 can layer update/
    deprovision tests on the same fixture.
    """
    try:
        _run_testbed("--teardown")
    except Exception:
        pass

    stdout = _run_testbed("--json-output")
    config = json.loads(stdout)

    yield config

    try:
        _run_testbed("--teardown")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Provision (POST) path
# ---------------------------------------------------------------------------


class TestScimLoopbackProvision:
    """Outbound POST /Users and POST /Groups land in the receiving tenant."""

    def test_provision_creates_users_group_and_remote_ids(self, loopback_config):
        src = loopback_config["source"]
        receiver = loopback_config["receiver"]
        src_tenant_id = src["tenant_id"]
        dst_tenant_id = receiver["tenant_id"]
        sp_id = src["sp_id"]

        # Drain the grant fan-out to completion.
        _drain_until_idle(src_tenant_id)

        # --- Users: both granted members exist as ACTIVE users in receiver ---
        member_emails = src["member_emails"]
        for email in member_emails:
            active = _run_sql(
                "SELECT u.is_inactivated FROM users u "
                "JOIN user_emails ue ON ue.user_id = u.id "
                f"WHERE u.tenant_id = '{dst_tenant_id}' AND ue.email = '{email}';"
            )
            assert active == "f", (
                f"Receiving tenant must contain active user {email}; got is_inactivated={active!r}"
            )

        user_count = _run_sql(
            "SELECT count(*) FROM users u "
            "JOIN user_emails ue ON ue.user_id = u.id "
            f"WHERE u.tenant_id = '{dst_tenant_id}' "
            f"AND ue.email IN ({', '.join(repr(e) for e in member_emails)});"
        )
        assert user_count == str(len(member_emails)), (
            f"Expected {len(member_emails)} provisioned users; got {user_count}"
        )

        # --- Group: materialised as group_type='idp' in the receiver ---
        group_name = loopback_config["group_name"]
        group_type = _run_sql(
            "SELECT group_type FROM groups "
            f"WHERE tenant_id = '{dst_tenant_id}' AND name = '{group_name}';"
        )
        assert group_type == "idp", (
            f"Provisioned group must be group_type='idp'; got {group_type!r}"
        )

        # The IdP group must be bound to the receiving IdP.
        has_idp = _run_sql(
            "SELECT idp_id IS NOT NULL FROM groups "
            f"WHERE tenant_id = '{dst_tenant_id}' AND name = '{group_name}';"
        )
        assert has_idp == "t", "Provisioned idp group must reference an idp_id"

        # --- Remote ids captured on the source side for users + group ---
        user_remote_ids = _run_sql(
            "SELECT count(*) FROM sp_scim_remote_ids "
            f"WHERE sp_id = '{sp_id}' AND resource_type = 'user';"
        )
        assert user_remote_ids == str(len(member_emails)), (
            f"Expected {len(member_emails)} user remote-id rows; got {user_remote_ids}"
        )
        group_remote_ids = _run_sql(
            "SELECT count(*) FROM sp_scim_remote_ids "
            f"WHERE sp_id = '{sp_id}' AND resource_type = 'group';"
        )
        assert group_remote_ids == "1", f"Expected 1 group remote-id row; got {group_remote_ids}"

    def test_provision_pushes_all_succeeded_none_dead_lettered(self, loopback_config):
        src = loopback_config["source"]
        src_tenant_id = src["tenant_id"]
        sp_id = src["sp_id"]

        # Ensure the queue is fully drained (idempotent if the prior test ran).
        _drain_until_idle(src_tenant_id)

        # No sync-log row may be dead-lettered: a dead-letter would mean the
        # payload we emit failed our own inbound parser.
        dead = _run_sql(
            "SELECT count(*) FROM scim_sync_log "
            f"WHERE sp_id = '{sp_id}' AND status = 'dead_letter';"
        )
        assert dead == "0", f"No push may be dead-lettered; got {dead} dead-letter row(s)"

        # No queue row may carry a dead_letter_at marker.
        dead_queue = _run_sql(
            "SELECT count(*) FROM scim_push_queue "
            f"WHERE sp_id = '{sp_id}' AND dead_letter_at IS NOT NULL;"
        )
        assert dead_queue == "0", (
            f"No queue row may be dead-lettered; got {dead_queue} marked row(s)"
        )

        # At least one push reached terminal success.
        done = _run_sql(
            f"SELECT count(*) FROM scim_sync_log WHERE sp_id = '{sp_id}' AND status = 'done';"
        )
        assert int(done) >= 1, f"Expected >=1 successful push; got {done}"


# ---------------------------------------------------------------------------
# Lifecycle helpers (remote-id lookups)
# ---------------------------------------------------------------------------


def _user_remote_id(sp_id: str, weftid_user_id: str) -> str:
    """Return the receiver-side remote id captured for a source user.

    `sp_scim_remote_ids.weftid_id` is the source UUID; `.remote_id` is the
    id the receiver assigned (its own users.id). Used to prove PUT reuse and
    to join source members to receiver group membership.
    """
    return _run_sql(
        "SELECT remote_id FROM sp_scim_remote_ids "
        f"WHERE sp_id = '{sp_id}' AND resource_type = 'user' "
        f"AND weftid_id = '{weftid_user_id}';"
    )


# ---------------------------------------------------------------------------
# Update (PUT) path
# ---------------------------------------------------------------------------


class TestScimLoopbackUpdate:
    """An attribute change propagates via PUT /Users/<remote_id> (no re-POST)."""

    def test_update_propagates_via_put_reusing_remote_id(self, loopback_config):
        src = loopback_config["source"]
        receiver = loopback_config["receiver"]
        src_tenant_id = src["tenant_id"]
        dst_tenant_id = receiver["tenant_id"]
        sp_id = src["sp_id"]

        # Make sure the provision wave is fully drained before mutating.
        _drain_until_idle(src_tenant_id)

        # The mutate helper targets the first source member. Resolve its source
        # UUID and capture the remote id BEFORE the mutation.
        target_email = src["member_emails"][0]
        target_user_id = _run_sql(
            "SELECT u.id FROM users u JOIN user_emails ue ON ue.user_id = u.id "
            f"WHERE u.tenant_id = '{src_tenant_id}' AND ue.email = '{target_email}';"
        )
        remote_id_before = _user_remote_id(sp_id, target_user_id)
        assert remote_id_before, "Target user must have a captured remote id before update"

        # Drive the update through the service layer (logs user_updated ->
        # enqueue_user_self -> PUT). The helper returns the new first name.
        out = _run_testbed("--mutate-user", "--json-output")
        mutation = json.loads(out)
        new_first_name = mutation["first_name"]

        _drain_until_idle(src_tenant_id)

        # The receiving user row reflects the new given name.
        recv_first_name = _run_sql(
            "SELECT u.first_name FROM users u JOIN user_emails ue ON ue.user_id = u.id "
            f"WHERE u.tenant_id = '{dst_tenant_id}' AND ue.email = '{target_email}';"
        )
        assert recv_first_name == new_first_name, (
            f"Receiver user first_name must reflect the update; "
            f"expected {new_first_name!r}, got {recv_first_name!r}"
        )

        # The SAME remote id is reused -- this proves PUT, not a duplicate POST.
        remote_id_after = _user_remote_id(sp_id, target_user_id)
        assert remote_id_after == remote_id_before, (
            f"Remote id must be reused on update (PUT, not re-POST); "
            f"before={remote_id_before!r} after={remote_id_after!r}"
        )

        # Exactly one remote-id row still exists for this user (no duplicate).
        row_count = _run_sql(
            "SELECT count(*) FROM sp_scim_remote_ids "
            f"WHERE sp_id = '{sp_id}' AND resource_type = 'user' "
            f"AND weftid_id = '{target_user_id}';"
        )
        assert row_count == "1", f"Expected exactly 1 remote-id row for the user; got {row_count}"


# ---------------------------------------------------------------------------
# Group membership round-trip
# ---------------------------------------------------------------------------


class TestScimLoopbackMembership:
    """The receiver idp group's members match the source group (by remote id)."""

    def test_group_membership_round_trips_by_remote_id(self, loopback_config):
        src = loopback_config["source"]
        receiver = loopback_config["receiver"]
        src_tenant_id = src["tenant_id"]
        dst_tenant_id = receiver["tenant_id"]
        sp_id = src["sp_id"]
        group_name = loopback_config["group_name"]

        _drain_until_idle(src_tenant_id)

        # Source members -> their receiver-side remote ids (= receiver user ids).
        expected_remote_ids = set()
        for email in src["member_emails"]:
            weftid_user_id = _run_sql(
                "SELECT u.id FROM users u JOIN user_emails ue ON ue.user_id = u.id "
                f"WHERE u.tenant_id = '{src_tenant_id}' AND ue.email = '{email}';"
            )
            remote_id = _user_remote_id(sp_id, weftid_user_id)
            assert remote_id, f"Source member {email} must have a captured remote id"
            expected_remote_ids.add(remote_id)

        # Receiver idp group's membership: group_memberships.user_id holds the
        # RECEIVER user ids, which are exactly the remote ids captured above.
        receiver_members_raw = _run_sql(
            "SELECT gm.user_id FROM group_memberships gm "
            "JOIN groups g ON g.id = gm.group_id "
            f"WHERE g.tenant_id = '{dst_tenant_id}' AND g.name = '{group_name}' "
            "AND g.group_type = 'idp';"
        )
        receiver_member_ids = {
            line.strip() for line in receiver_members_raw.splitlines() if line.strip()
        }

        assert receiver_member_ids == expected_remote_ids, (
            "Receiver idp group membership must match the source group members "
            f"(by remote id); expected {expected_remote_ids}, got {receiver_member_ids}"
        )


# ---------------------------------------------------------------------------
# Deprovision (DELETE) path
# ---------------------------------------------------------------------------


class TestScimLoopbackDeprovision:
    """Removing the grant drives DELETE /Users/<remote_id> -> soft-delete."""

    def test_deprovision_soft_deletes_users_preserving_mfa_and_history(self, loopback_config):
        src = loopback_config["source"]
        receiver = loopback_config["receiver"]
        src_tenant_id = src["tenant_id"]
        dst_tenant_id = receiver["tenant_id"]

        _drain_until_idle(src_tenant_id)

        member_emails = src["member_emails"]

        # Seed an MFA row on one receiver user so we can prove the soft-delete
        # preserves MFA (does NOT cascade-delete it). Capture an existing event
        # log count for the same user to prove history is preserved too.
        guard_email = member_emails[0]
        recv_user_id = _run_sql(
            "SELECT u.id FROM users u JOIN user_emails ue ON ue.user_id = u.id "
            f"WHERE u.tenant_id = '{dst_tenant_id}' AND ue.email = '{guard_email}';"
        )
        assert recv_user_id, "Receiver user must exist before deprovision"

        _run_sql(
            "INSERT INTO mfa_totp (tenant_id, user_id, secret_encrypted, method, verified_at) "
            f"VALUES ('{dst_tenant_id}', '{recv_user_id}', 'loopback-test-secret', 'totp', now()) "
            "ON CONFLICT (user_id, method) DO NOTHING;"
        )
        mfa_before = _run_sql(f"SELECT count(*) FROM mfa_totp WHERE user_id = '{recv_user_id}';")
        assert int(mfa_before) >= 1, "MFA row must exist before deprovision"

        history_before = _run_sql(
            f"SELECT count(*) FROM event_logs WHERE tenant_id = '{dst_tenant_id}' "
            f"AND artifact_id = '{recv_user_id}';"
        )

        # Remove the grant via the service layer (logs sp_group_unassigned ->
        # enqueue_grant_fan_out -> the worker emits DELETE for lost-access users).
        _run_testbed("--remove-grant", "--json-output")

        _drain_until_idle(src_tenant_id)

        # Every provisioned receiver user is now soft-deleted (inactivated).
        for email in member_emails:
            inactivated = _run_sql(
                "SELECT u.is_inactivated FROM users u "
                "JOIN user_emails ue ON ue.user_id = u.id "
                f"WHERE u.tenant_id = '{dst_tenant_id}' AND ue.email = '{email}';"
            )
            assert inactivated == "t", (
                f"Receiver user {email} must be soft-deleted (is_inactivated=true); "
                f"got {inactivated!r}"
            )

        # The receiver user row still exists (soft, not hard, delete).
        still_exists = _run_sql(f"SELECT count(*) FROM users WHERE id = '{recv_user_id}';")
        assert still_exists == "1", "Soft-delete must keep the receiver user row"

        # MFA preserved (not cascade-deleted with a hard delete).
        mfa_after = _run_sql(f"SELECT count(*) FROM mfa_totp WHERE user_id = '{recv_user_id}';")
        assert mfa_after == mfa_before, (
            f"MFA rows must be preserved across soft-delete; before={mfa_before} after={mfa_after}"
        )

        # History (event logs) preserved.
        history_after = _run_sql(
            f"SELECT count(*) FROM event_logs WHERE tenant_id = '{dst_tenant_id}' "
            f"AND artifact_id = '{recv_user_id}';"
        )
        assert int(history_after) >= int(history_before), (
            f"Event-log history must be preserved across soft-delete; "
            f"before={history_before} after={history_after}"
        )


# ---------------------------------------------------------------------------
# Lifecycle-wide self-consistency: zero dead-letters
# ---------------------------------------------------------------------------


class TestScimLoopbackLifecycleNoDeadLetters:
    """Headline check: provision->update->deprovision emitted zero dead-letters."""

    def test_no_dead_letters_across_full_lifecycle(self, loopback_config):
        src = loopback_config["source"]
        receiver = loopback_config["receiver"]
        src_tenant_id = src["tenant_id"]
        dst_tenant_id = receiver["tenant_id"]
        sp_id = src["sp_id"]

        _drain_until_idle(src_tenant_id)

        # No sync-log row may be dead-lettered across the WHOLE lifecycle: a
        # dead-letter at any step (POST, PUT, or DELETE) means a payload we
        # emitted failed our own inbound parser. (The push verb is not recorded
        # on the sync log; the receiver-side effects in the update/deprovision
        # tests prove PUT and DELETE were emitted and accepted.)
        dead = _run_sql(
            "SELECT count(*) FROM scim_sync_log "
            f"WHERE sp_id = '{sp_id}' AND status = 'dead_letter';"
        )
        assert dead == "0", f"No push may be dead-lettered across the lifecycle; got {dead}"

        # No queue row may carry a dead_letter_at marker.
        dead_queue = _run_sql(
            "SELECT count(*) FROM scim_push_queue "
            f"WHERE sp_id = '{sp_id}' AND dead_letter_at IS NOT NULL;"
        )
        assert dead_queue == "0", (
            f"No queue row may be dead-lettered across the lifecycle; got {dead_queue}"
        )

        # The deprovision DELETE landed: every provisioned receiver user is
        # inactivated. This confirms the lifecycle reached its terminal step
        # (not just that nothing dead-lettered).
        for email in src["member_emails"]:
            inactivated = _run_sql(
                "SELECT u.is_inactivated FROM users u "
                "JOIN user_emails ue ON ue.user_id = u.id "
                f"WHERE u.tenant_id = '{dst_tenant_id}' AND ue.email = '{email}';"
            )
            assert inactivated == "t", (
                f"Lifecycle must end with {email} deprovisioned (is_inactivated=true); "
                f"got {inactivated!r}"
            )
