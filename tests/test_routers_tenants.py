"""Comprehensive tests for Tenants router.

This test file covers all tenant router endpoints in routers/tenants.py.
Tests include:
- Root endpoint redirects for authenticated users
- Root endpoint redirects for unauthenticated users
"""

import pytest
from unittest.mock import patch


def test_tenant_root_redirects_to_dashboard_when_authenticated(
    client, test_tenant_host, test_user, test_tenant
):
    """Test that root endpoint redirects authenticated users to dashboard."""
    # Mock get_current_user to return a user
    with patch("routers.tenants.get_current_user") as mock_get_current_user:
        mock_get_current_user.return_value = test_user

        response = client.get(
            "/",
            headers={"Host": test_tenant_host},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"
        mock_get_current_user.assert_called_once()


def test_tenant_root_redirects_to_login_when_unauthenticated(client, test_tenant_host):
    """Test that root endpoint redirects unauthenticated users to login."""
    # Mock get_current_user to return None (not authenticated)
    with patch("routers.tenants.get_current_user") as mock_get_current_user:
        mock_get_current_user.return_value = None

        response = client.get(
            "/",
            headers={"Host": test_tenant_host},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/login"
        mock_get_current_user.assert_called_once()
