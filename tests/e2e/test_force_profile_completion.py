"""E2E: force_profile_completion gate (Iteration 7).

The admin todo flow lets an admin flag selected users for forced
profile completion. Flagged users are funneled to ``/account/profile``
on every subsequent navigation until the missing attributes are
populated. This file exercises two end-to-end scenarios:

* Variant A -- user-fixable: an enabled+required+unlocked attribute is
  missing on an admin user. The flag is set on the admin. Login lands
  on /account/profile; direct navigation to /dashboard bounces back.
  After submitting the profile form the gate is cleared and /dashboard
  is reachable.

* Variant B -- locked-required: the only missing required attribute
  is locked. ``bulk_set_force_profile_completion`` MUST skip the user
  (otherwise the gate would loop forever) and the user remains free
  to navigate normally.

Setup uses direct SQL via psql for speed and determinism. The
``e2e_config`` testbed provisions a super_admin per tenant. Variant A
exercises the gate against the testbed super_admin and clears it via
the standard profile form. Variant B uses a fresh member user, which
keeps the assertion focused on the gate-off path.
"""

from __future__ import annotations

import subprocess
import uuid

from tests.e2e.conftest import DOCKER_COMPOSE

# ---------------------------------------------------------------------------
# psql helpers
# ---------------------------------------------------------------------------


def _psql(sql: str) -> str:
    """Run a single SQL statement via psql in the db container."""
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
            "-tA",
            "-c",
            sql,
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, (
        f"psql failed (rc={result.returncode}):\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}\nsql: {sql}"
    )
    return result.stdout.strip()


def _tenant_id_for(subdomain: str) -> str:
    return _psql(f"SELECT id FROM tenants WHERE subdomain = '{subdomain}';")


def _user_id_for_email(tenant_id: str, email: str) -> str:
    return _psql(
        f"SELECT u.id FROM users u "
        f"JOIN user_emails ue ON ue.user_id = u.id "
        f"WHERE u.tenant_id = '{tenant_id}' AND ue.email = '{email}';"
    )


def _set_attribute_config(
    tenant_id: str,
    attribute_key: str,
    *,
    enabled: bool,
    required: bool,
    locked_for_users: bool,
) -> None:
    """Force an attribute config row to the desired flags."""
    sql = (
        f"UPDATE tenant_attribute_config SET "
        f"enabled = {str(enabled).lower()}, "
        f"required = {str(required).lower()}, "
        f"locked_for_users = {str(locked_for_users).lower()} "
        f"WHERE tenant_id = '{tenant_id}' AND attribute_key = '{attribute_key}';"
    )
    _psql(sql)


def _reset_attribute_config(tenant_id: str, attribute_key: str) -> None:
    sql = (
        f"UPDATE tenant_attribute_config SET "
        f"enabled = false, required = false, locked_for_users = false "
        f"WHERE tenant_id = '{tenant_id}' AND attribute_key = '{attribute_key}';"
    )
    _psql(sql)


def _delete_user_attribute(tenant_id: str, user_id: str, attribute_key: str) -> None:
    sql = (
        f"DELETE FROM user_attributes "
        f"WHERE tenant_id = '{tenant_id}' AND user_id = '{user_id}' "
        f"AND attribute_key = '{attribute_key}';"
    )
    _psql(sql)


def _set_force_profile_completion(tenant_id: str, user_id: str, value: bool) -> None:
    sql = (
        f"UPDATE users SET force_profile_completion = {str(value).lower()} "
        f"WHERE tenant_id = '{tenant_id}' AND id = '{user_id}';"
    )
    _psql(sql)


def _get_force_profile_completion(tenant_id: str, user_id: str) -> bool:
    out = _psql(
        f"SELECT force_profile_completion FROM users "
        f"WHERE tenant_id = '{tenant_id}' AND id = '{user_id}';"
    )
    return out.strip().lower() == "t"


def _create_member_user(tenant_id: str, email: str) -> str:
    """Create a fresh member user with a primary email. Returns user_id.

    The user has no password hash (NULL is allowed) -- the E2E test
    authenticates via the dev-only ``/dev/login`` endpoint which sets
    the session directly and never touches the password column.
    """
    user_id = str(uuid.uuid4())
    _psql(
        f"INSERT INTO users (id, tenant_id, first_name, last_name, role) "
        f"VALUES ('{user_id}', '{tenant_id}', 'Force', 'Tester', 'member');"
    )
    _psql(
        f"INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at) "
        f"VALUES ('{tenant_id}', '{user_id}', '{email}', true, now());"
    )
    return user_id


def _delete_user(tenant_id: str, user_id: str) -> None:
    _psql(f"DELETE FROM users WHERE tenant_id = '{tenant_id}' AND id = '{user_id}';")


# ---------------------------------------------------------------------------
# Variant A -- user-fixable
# ---------------------------------------------------------------------------


class TestForceProfileCompletionUserFixable:
    """Flagged user is redirected to /account/profile and released after submit."""

    def test_user_redirected_to_profile_and_released_after_submit(self, page, idp_config):
        base_url = idp_config["base_url"]
        subdomain = idp_config["subdomain"]
        admin_email = idp_config["admin_email"]
        tenant_id = _tenant_id_for(subdomain)
        admin_id = _user_id_for_email(tenant_id, admin_email)

        # Use a free-text professional attribute. The profile page renders
        # the standard-attribute section for admin / super_admin callers.
        attr_key = "job_title"

        _set_attribute_config(
            tenant_id, attr_key, enabled=True, required=True, locked_for_users=False
        )
        _delete_user_attribute(tenant_id, admin_id, attr_key)

        try:
            # Flag the admin. The service-layer bulk action does this; the
            # gate behavior is what we are exercising here.
            _set_force_profile_completion(tenant_id, admin_id, True)

            # Dev-only instant login. The endpoint returns 303 -> /dashboard;
            # require_current_user then bounces to /account/profile.
            page.goto(f"{base_url}/dev/login?email={admin_email}")
            page.wait_for_url("**/account/profile**", timeout=10000)
            assert "/account/profile" in page.url

            # Direct navigation to /dashboard snaps back to the profile.
            page.goto(f"{base_url}/dashboard")
            page.wait_for_url("**/account/profile**", timeout=10000)

            # Fill the missing required attribute and submit.
            field = page.locator(f"input[name='attr_{attr_key}']")
            field.wait_for(state="visible", timeout=10000)
            field.fill("Lead Engineer")
            page.locator(
                "form[action='/account/profile/update-attributes'] button[type='submit']"
            ).first.click()

            # POST handler clears force_profile_completion when every required
            # unlocked attribute now has a value, then redirects back to the
            # profile with ?success=attributes_saved.
            page.wait_for_url("**/account/profile**", timeout=10000)

            # Gate cleared: /dashboard is now reachable.
            assert _get_force_profile_completion(tenant_id, admin_id) is False
            page.goto(f"{base_url}/dashboard")
            page.wait_for_url("**/dashboard**", timeout=10000)
            assert "/dashboard" in page.url
        finally:
            # Best-effort teardown: clear the flag, the value, and the config.
            _set_force_profile_completion(tenant_id, admin_id, False)
            _delete_user_attribute(tenant_id, admin_id, attr_key)
            _reset_attribute_config(tenant_id, attr_key)


# ---------------------------------------------------------------------------
# Variant B -- locked-required (gate must NOT be set)
# ---------------------------------------------------------------------------


class TestForceProfileCompletionLockedRequired:
    """A user with only locked-required missing attributes is not gated."""

    def test_locked_only_user_not_redirected(self, page, idp_config):
        base_url = idp_config["base_url"]
        subdomain = idp_config["subdomain"]
        tenant_id = _tenant_id_for(subdomain)

        attr_key = "employee_id"

        suffix = uuid.uuid4().hex[:8]
        member_email = f"forcelocked-{suffix}@e2e.local"
        member_id = _create_member_user(tenant_id, member_email)

        # Configure attribute as enabled+required+LOCKED, ensure no value.
        _set_attribute_config(
            tenant_id, attr_key, enabled=True, required=True, locked_for_users=True
        )
        _delete_user_attribute(tenant_id, member_id, attr_key)

        try:
            # The user is NOT flagged. bulk_set_force_profile_completion
            # would skip locked-only-missing users -- the service-level skip
            # behavior is covered in unit tests; here we verify the gate-off
            # path through a real browser.
            assert _get_force_profile_completion(tenant_id, member_id) is False

            page.goto(f"{base_url}/dev/login?email={member_email}")
            page.wait_for_url("**/dashboard**", timeout=10000)
            assert "/dashboard" in page.url

            # Navigating around is unimpeded.
            page.goto(f"{base_url}/account/profile")
            page.wait_for_url("**/account/profile**", timeout=10000)
            assert "/account/profile" in page.url
        finally:
            _delete_user(tenant_id, member_id)
            _reset_attribute_config(tenant_id, attr_key)
