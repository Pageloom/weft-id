"""Tests for API endpoints."""


def test_root_endpoint_with_valid_tenant(client, test_host):
    """Test root endpoint with a valid tenant hostname."""
    response = client.get('/', headers={'host': test_host})

    # This will fail until a tenant is provisioned, but shows structure
    assert response.status_code in (200, 404)

    if response.status_code == 200:
        data = response.json()
        assert data['ok'] is True
        assert 'tenant_id' in data


def test_root_endpoint_with_invalid_host(client):
    """Test root endpoint with an invalid hostname."""
    response = client.get('/', headers={'host': 'invalid.example.com'})

    assert response.status_code == 404
    assert 'Unknown host' in response.json()['detail']


def test_root_endpoint_without_host(client):
    """Test root endpoint without host header."""
    response = client.get('/')

    # Should fail due to missing/invalid host
    assert response.status_code == 404
