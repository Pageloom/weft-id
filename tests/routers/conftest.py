"""Shared fixtures for router tests."""

import pytest


@pytest.fixture(autouse=True)
def bypass_saml_acs_ratelimit(mocker):
    """Bypass SAML ACS rate limiting for all router tests.

    Tests run in parallel and share the 'testclient' IP. In CI where Memcached
    is available, the shared counter exhausts the 20-request limit and unrelated
    tests start receiving 429. Tests that specifically test rate limiting override
    this by patching the entire `ratelimit` object with @patch(...ratelimit).
    """
    mocker.patch("routers.saml.authentication.ratelimit.prevent", return_value=1)
