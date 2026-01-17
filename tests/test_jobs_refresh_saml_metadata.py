"""Tests for SAML IdP metadata refresh job.

Tests the scheduled job that refreshes SAML IdP metadata from configured URLs.
"""

from unittest.mock import patch

from jobs.refresh_saml_metadata import refresh_saml_metadata
from schemas.saml import MetadataRefreshResult, MetadataRefreshSummary


class TestRefreshSamlMetadataJob:
    """Tests for the refresh_saml_metadata job function."""

    def test_refresh_success_logs_and_returns_summary(self):
        """Test successful metadata refresh returns proper summary dict."""
        mock_result = MetadataRefreshSummary(
            total=3,
            successful=2,
            failed=1,
            results=[
                MetadataRefreshResult(
                    idp_id="idp-1",
                    idp_name="Okta IdP",
                    success=True,
                    updated_fields=["certificate_pem"],
                ),
                MetadataRefreshResult(
                    idp_id="idp-2",
                    idp_name="Azure AD",
                    success=True,
                    updated_fields=None,
                ),
                MetadataRefreshResult(
                    idp_id="idp-3",
                    idp_name="Google",
                    success=False,
                    error="Connection timeout",
                ),
            ],
        )

        with patch("jobs.refresh_saml_metadata.saml_service") as mock_service:
            mock_service.refresh_all_idp_metadata.return_value = mock_result

            result = refresh_saml_metadata()

        assert result["total"] == 3
        assert result["successful"] == 2
        assert result["failed"] == 1
        assert len(result["results"]) == 3

        # Check first result structure
        assert result["results"][0]["idp_id"] == "idp-1"
        assert result["results"][0]["idp_name"] == "Okta IdP"
        assert result["results"][0]["success"] is True
        assert result["results"][0]["updated_fields"] == ["certificate_pem"]
        assert result["results"][0]["error"] is None

        # Check failed result
        assert result["results"][2]["success"] is False
        assert result["results"][2]["error"] == "Connection timeout"

    def test_refresh_empty_no_idps_with_urls(self):
        """Test refresh when no IdPs have metadata URLs configured."""
        mock_result = MetadataRefreshSummary(
            total=0,
            successful=0,
            failed=0,
            results=[],
        )

        with patch("jobs.refresh_saml_metadata.saml_service") as mock_service:
            mock_service.refresh_all_idp_metadata.return_value = mock_result

            result = refresh_saml_metadata()

        assert result["total"] == 0
        assert result["successful"] == 0
        assert result["failed"] == 0
        assert result["results"] == []

    def test_refresh_handles_service_exception(self):
        """Test that exceptions in service layer are caught and logged."""
        with patch("jobs.refresh_saml_metadata.saml_service") as mock_service:
            mock_service.refresh_all_idp_metadata.side_effect = Exception(
                "Database connection failed"
            )

            result = refresh_saml_metadata()

        # Should return error result, not raise
        assert result["total"] == 0
        assert result["successful"] == 0
        assert result["failed"] == 0
        assert "error" in result
        assert "Database connection failed" in result["error"]

    def test_refresh_all_successful(self):
        """Test refresh when all IdPs succeed."""
        mock_result = MetadataRefreshSummary(
            total=2,
            successful=2,
            failed=0,
            results=[
                MetadataRefreshResult(
                    idp_id="idp-1",
                    idp_name="Okta",
                    success=True,
                    updated_fields=["sso_url", "certificate_pem"],
                ),
                MetadataRefreshResult(
                    idp_id="idp-2",
                    idp_name="Azure",
                    success=True,
                    updated_fields=None,  # No changes needed
                ),
            ],
        )

        with patch("jobs.refresh_saml_metadata.saml_service") as mock_service:
            mock_service.refresh_all_idp_metadata.return_value = mock_result

            result = refresh_saml_metadata()

        assert result["total"] == 2
        assert result["successful"] == 2
        assert result["failed"] == 0

    def test_refresh_all_failed(self):
        """Test refresh when all IdPs fail."""
        mock_result = MetadataRefreshSummary(
            total=2,
            successful=0,
            failed=2,
            results=[
                MetadataRefreshResult(
                    idp_id="idp-1",
                    idp_name="Okta",
                    success=False,
                    error="Invalid XML",
                ),
                MetadataRefreshResult(
                    idp_id="idp-2",
                    idp_name="Azure",
                    success=False,
                    error="404 Not Found",
                ),
            ],
        )

        with patch("jobs.refresh_saml_metadata.saml_service") as mock_service:
            mock_service.refresh_all_idp_metadata.return_value = mock_result

            result = refresh_saml_metadata()

        assert result["total"] == 2
        assert result["successful"] == 0
        assert result["failed"] == 2

    def test_refresh_logs_info_on_success(self, caplog):
        """Test that successful refresh logs info message."""
        import logging

        mock_result = MetadataRefreshSummary(
            total=1,
            successful=1,
            failed=0,
            results=[
                MetadataRefreshResult(
                    idp_id="idp-1",
                    idp_name="Test",
                    success=True,
                ),
            ],
        )

        with patch("jobs.refresh_saml_metadata.saml_service") as mock_service:
            mock_service.refresh_all_idp_metadata.return_value = mock_result

            with caplog.at_level(logging.INFO):
                refresh_saml_metadata()

        assert "Starting SAML IdP metadata refresh" in caplog.text
        assert "completed" in caplog.text

    def test_refresh_logs_exception_on_error(self, caplog):
        """Test that exceptions are logged with full traceback."""
        import logging

        with patch("jobs.refresh_saml_metadata.saml_service") as mock_service:
            mock_service.refresh_all_idp_metadata.side_effect = ValueError(
                "Unexpected error"
            )

            with caplog.at_level(logging.ERROR):
                refresh_saml_metadata()

        assert "Unexpected error" in caplog.text
