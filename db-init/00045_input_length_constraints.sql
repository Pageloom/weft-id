-- Migration: Add CHECK constraints for input length limits
-- Defense-in-depth: database-level backstop for Pydantic schema validation
--
-- Pattern: CHECK (col IS NULL OR length(col) <= N)
-- Idempotent: checks pg_constraint before adding each constraint

BEGIN;
SET LOCAL ROLE appowner;

-- Safety check: verify no existing data exceeds proposed limits
DO $$
DECLARE
    violations TEXT := '';
BEGIN
    -- tenants
    IF EXISTS (SELECT 1 FROM tenants WHERE length(name) > 255) THEN
        violations := violations || 'tenants.name exceeds 255; ';
    END IF;

    -- saml_identity_providers
    IF EXISTS (SELECT 1 FROM saml_identity_providers WHERE length(name) > 120) THEN
        violations := violations || 'saml_identity_providers.name exceeds 120; ';
    END IF;
    IF EXISTS (SELECT 1 FROM saml_identity_providers WHERE length(entity_id) > 2048) THEN
        violations := violations || 'saml_identity_providers.entity_id exceeds 2048; ';
    END IF;
    IF EXISTS (SELECT 1 FROM saml_identity_providers WHERE length(sso_url) > 2048) THEN
        violations := violations || 'saml_identity_providers.sso_url exceeds 2048; ';
    END IF;
    IF EXISTS (SELECT 1 FROM saml_identity_providers WHERE length(slo_url) > 2048) THEN
        violations := violations || 'saml_identity_providers.slo_url exceeds 2048; ';
    END IF;
    IF EXISTS (SELECT 1 FROM saml_identity_providers WHERE length(certificate_pem) > 16000) THEN
        violations := violations || 'saml_identity_providers.certificate_pem exceeds 16000; ';
    END IF;
    IF EXISTS (SELECT 1 FROM saml_identity_providers WHERE length(metadata_url) > 2048) THEN
        violations := violations || 'saml_identity_providers.metadata_url exceeds 2048; ';
    END IF;
    IF EXISTS (SELECT 1 FROM saml_identity_providers WHERE length(metadata_xml) > 1000000) THEN
        violations := violations || 'saml_identity_providers.metadata_xml exceeds 1000000; ';
    END IF;
    IF EXISTS (SELECT 1 FROM saml_identity_providers WHERE length(metadata_fetch_error) > 10000) THEN
        violations := violations || 'saml_identity_providers.metadata_fetch_error exceeds 10000; ';
    END IF;
    IF EXISTS (SELECT 1 FROM saml_identity_providers WHERE length(sp_entity_id) > 2048) THEN
        violations := violations || 'saml_identity_providers.sp_entity_id exceeds 2048; ';
    END IF;

    -- service_providers
    IF EXISTS (SELECT 1 FROM service_providers WHERE length(name) > 255) THEN
        violations := violations || 'service_providers.name exceeds 255; ';
    END IF;
    IF EXISTS (SELECT 1 FROM service_providers WHERE length(entity_id) > 2048) THEN
        violations := violations || 'service_providers.entity_id exceeds 2048; ';
    END IF;
    IF EXISTS (SELECT 1 FROM service_providers WHERE length(acs_url) > 2048) THEN
        violations := violations || 'service_providers.acs_url exceeds 2048; ';
    END IF;
    IF EXISTS (SELECT 1 FROM service_providers WHERE length(slo_url) > 2048) THEN
        violations := violations || 'service_providers.slo_url exceeds 2048; ';
    END IF;
    IF EXISTS (SELECT 1 FROM service_providers WHERE length(description) > 2000) THEN
        violations := violations || 'service_providers.description exceeds 2000; ';
    END IF;
    IF EXISTS (SELECT 1 FROM service_providers WHERE length(nameid_format) > 255) THEN
        violations := violations || 'service_providers.nameid_format exceeds 50; ';
    END IF;
    IF EXISTS (SELECT 1 FROM service_providers WHERE length(metadata_xml) > 1000000) THEN
        violations := violations || 'service_providers.metadata_xml exceeds 1000000; ';
    END IF;
    IF EXISTS (SELECT 1 FROM service_providers WHERE length(metadata_url) > 2048) THEN
        violations := violations || 'service_providers.metadata_url exceeds 2048; ';
    END IF;
    IF EXISTS (SELECT 1 FROM service_providers WHERE length(certificate_pem) > 16000) THEN
        violations := violations || 'service_providers.certificate_pem exceeds 16000; ';
    END IF;

    -- oauth2_clients
    IF EXISTS (SELECT 1 FROM oauth2_clients WHERE length(name) > 255) THEN
        violations := violations || 'oauth2_clients.name exceeds 255; ';
    END IF;
    IF EXISTS (SELECT 1 FROM oauth2_clients WHERE length(description) > 500) THEN
        violations := violations || 'oauth2_clients.description exceeds 500; ';
    END IF;
    IF EXISTS (SELECT 1 FROM oauth2_clients WHERE length(client_id) > 255) THEN
        violations := violations || 'oauth2_clients.client_id exceeds 255; ';
    END IF;
    IF EXISTS (SELECT 1 FROM oauth2_clients WHERE length(client_secret_hash) > 512) THEN
        violations := violations || 'oauth2_clients.client_secret_hash exceeds 512; ';
    END IF;

    -- oauth2_authorization_codes
    IF EXISTS (SELECT 1 FROM oauth2_authorization_codes WHERE length(code_hash) > 512) THEN
        violations := violations || 'oauth2_authorization_codes.code_hash exceeds 512; ';
    END IF;
    IF EXISTS (SELECT 1 FROM oauth2_authorization_codes WHERE length(redirect_uri) > 2048) THEN
        violations := violations || 'oauth2_authorization_codes.redirect_uri exceeds 2048; ';
    END IF;
    IF EXISTS (SELECT 1 FROM oauth2_authorization_codes WHERE length(code_challenge) > 128) THEN
        violations := violations || 'oauth2_authorization_codes.code_challenge exceeds 128; ';
    END IF;

    -- oauth2_tokens
    IF EXISTS (SELECT 1 FROM oauth2_tokens WHERE length(token_hash) > 512) THEN
        violations := violations || 'oauth2_tokens.token_hash exceeds 512; ';
    END IF;

    -- saml_debug_entries
    IF EXISTS (SELECT 1 FROM saml_debug_entries WHERE length(idp_name) > 255) THEN
        violations := violations || 'saml_debug_entries.idp_name exceeds 255; ';
    END IF;
    IF EXISTS (SELECT 1 FROM saml_debug_entries WHERE length(error_type) > 255) THEN
        violations := violations || 'saml_debug_entries.error_type exceeds 255; ';
    END IF;
    IF EXISTS (SELECT 1 FROM saml_debug_entries WHERE length(error_detail) > 10000) THEN
        violations := violations || 'saml_debug_entries.error_detail exceeds 10000; ';
    END IF;
    IF EXISTS (SELECT 1 FROM saml_debug_entries WHERE length(saml_response_b64) > 1500000) THEN
        violations := violations || 'saml_debug_entries.saml_response_b64 exceeds 1500000; ';
    END IF;
    IF EXISTS (SELECT 1 FROM saml_debug_entries WHERE length(saml_response_xml) > 1000000) THEN
        violations := violations || 'saml_debug_entries.saml_response_xml exceeds 1000000; ';
    END IF;
    IF EXISTS (SELECT 1 FROM saml_debug_entries WHERE length(request_ip) > 45) THEN
        violations := violations || 'saml_debug_entries.request_ip exceeds 45; ';
    END IF;
    IF EXISTS (SELECT 1 FROM saml_debug_entries WHERE length(user_agent) > 1024) THEN
        violations := violations || 'saml_debug_entries.user_agent exceeds 1024; ';
    END IF;

    -- export_files
    IF EXISTS (SELECT 1 FROM export_files WHERE length(filename) > 255) THEN
        violations := violations || 'export_files.filename exceeds 255; ';
    END IF;
    IF EXISTS (SELECT 1 FROM export_files WHERE length(storage_path) > 2048) THEN
        violations := violations || 'export_files.storage_path exceeds 2048; ';
    END IF;
    IF EXISTS (SELECT 1 FROM export_files WHERE length(content_type) > 255) THEN
        violations := violations || 'export_files.content_type exceeds 255; ';
    END IF;

    -- tenant_branding
    IF EXISTS (SELECT 1 FROM tenant_branding WHERE length(site_title) > 30) THEN
        violations := violations || 'tenant_branding.site_title exceeds 30; ';
    END IF;

    -- bg_tasks
    IF EXISTS (SELECT 1 FROM bg_tasks WHERE length(error) > 10000) THEN
        violations := violations || 'bg_tasks.error exceeds 10000; ';
    END IF;

    IF violations != '' THEN
        RAISE EXCEPTION 'Data exceeds proposed limits: %', violations;
    END IF;
END $$;

-- Helper function: add constraint only if it doesn't already exist
CREATE OR REPLACE FUNCTION _add_check_if_not_exists(
    p_table TEXT, p_constraint TEXT, p_check TEXT
) RETURNS VOID AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = p_constraint
        AND conrelid = p_table::regclass
    ) THEN
        EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I CHECK (%s)', p_table, p_constraint, p_check);
    END IF;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- tenants
-- ============================================================================
SELECT _add_check_if_not_exists('tenants', 'chk_tenants_name_length', 'length(name) <= 255');

-- ============================================================================
-- saml_identity_providers
-- ============================================================================
SELECT _add_check_if_not_exists('saml_identity_providers', 'chk_saml_idp_name_length', 'length(name) <= 120');
SELECT _add_check_if_not_exists('saml_identity_providers', 'chk_saml_idp_entity_id_length', 'entity_id IS NULL OR length(entity_id) <= 2048');
SELECT _add_check_if_not_exists('saml_identity_providers', 'chk_saml_idp_sso_url_length', 'sso_url IS NULL OR length(sso_url) <= 2048');
SELECT _add_check_if_not_exists('saml_identity_providers', 'chk_saml_idp_slo_url_length', 'slo_url IS NULL OR length(slo_url) <= 2048');
SELECT _add_check_if_not_exists('saml_identity_providers', 'chk_saml_idp_certificate_pem_length', 'certificate_pem IS NULL OR length(certificate_pem) <= 16000');
SELECT _add_check_if_not_exists('saml_identity_providers', 'chk_saml_idp_metadata_url_length', 'metadata_url IS NULL OR length(metadata_url) <= 2048');
SELECT _add_check_if_not_exists('saml_identity_providers', 'chk_saml_idp_metadata_xml_length', 'metadata_xml IS NULL OR length(metadata_xml) <= 1000000');
SELECT _add_check_if_not_exists('saml_identity_providers', 'chk_saml_idp_metadata_fetch_error_length', 'metadata_fetch_error IS NULL OR length(metadata_fetch_error) <= 10000');
SELECT _add_check_if_not_exists('saml_identity_providers', 'chk_saml_idp_sp_entity_id_length', 'length(sp_entity_id) <= 2048');

-- ============================================================================
-- service_providers
-- ============================================================================
SELECT _add_check_if_not_exists('service_providers', 'chk_sp_name_length', 'length(name) <= 255');
SELECT _add_check_if_not_exists('service_providers', 'chk_sp_entity_id_length', 'entity_id IS NULL OR length(entity_id) <= 2048');
SELECT _add_check_if_not_exists('service_providers', 'chk_sp_acs_url_length', 'acs_url IS NULL OR length(acs_url) <= 2048');
SELECT _add_check_if_not_exists('service_providers', 'chk_sp_slo_url_length', 'slo_url IS NULL OR length(slo_url) <= 2048');
SELECT _add_check_if_not_exists('service_providers', 'chk_sp_description_length', 'description IS NULL OR length(description) <= 2000');
SELECT _add_check_if_not_exists('service_providers', 'chk_sp_nameid_format_length', 'length(nameid_format) <= 255');
SELECT _add_check_if_not_exists('service_providers', 'chk_sp_metadata_xml_length', 'metadata_xml IS NULL OR length(metadata_xml) <= 1000000');
SELECT _add_check_if_not_exists('service_providers', 'chk_sp_metadata_url_length', 'metadata_url IS NULL OR length(metadata_url) <= 2048');
SELECT _add_check_if_not_exists('service_providers', 'chk_sp_certificate_pem_length', 'certificate_pem IS NULL OR length(certificate_pem) <= 16000');

-- ============================================================================
-- oauth2_clients
-- ============================================================================
SELECT _add_check_if_not_exists('oauth2_clients', 'chk_oauth2_clients_name_length', 'length(name) <= 255');
SELECT _add_check_if_not_exists('oauth2_clients', 'chk_oauth2_clients_description_length', 'description IS NULL OR length(description) <= 500');
SELECT _add_check_if_not_exists('oauth2_clients', 'chk_oauth2_clients_client_id_length', 'length(client_id) <= 255');
SELECT _add_check_if_not_exists('oauth2_clients', 'chk_oauth2_clients_client_secret_hash_length', 'length(client_secret_hash) <= 512');

-- ============================================================================
-- oauth2_authorization_codes
-- ============================================================================
SELECT _add_check_if_not_exists('oauth2_authorization_codes', 'chk_oauth2_codes_code_hash_length', 'length(code_hash) <= 512');
SELECT _add_check_if_not_exists('oauth2_authorization_codes', 'chk_oauth2_codes_redirect_uri_length', 'length(redirect_uri) <= 2048');
SELECT _add_check_if_not_exists('oauth2_authorization_codes', 'chk_oauth2_codes_code_challenge_length', 'code_challenge IS NULL OR length(code_challenge) <= 128');

-- ============================================================================
-- oauth2_tokens
-- ============================================================================
SELECT _add_check_if_not_exists('oauth2_tokens', 'chk_oauth2_tokens_token_hash_length', 'length(token_hash) <= 512');

-- ============================================================================
-- saml_debug_entries
-- ============================================================================
SELECT _add_check_if_not_exists('saml_debug_entries', 'chk_debug_idp_name_length', 'idp_name IS NULL OR length(idp_name) <= 255');
SELECT _add_check_if_not_exists('saml_debug_entries', 'chk_debug_error_type_length', 'length(error_type) <= 255');
SELECT _add_check_if_not_exists('saml_debug_entries', 'chk_debug_error_detail_length', 'error_detail IS NULL OR length(error_detail) <= 10000');
SELECT _add_check_if_not_exists('saml_debug_entries', 'chk_debug_saml_response_b64_length', 'saml_response_b64 IS NULL OR length(saml_response_b64) <= 1500000');
SELECT _add_check_if_not_exists('saml_debug_entries', 'chk_debug_saml_response_xml_length', 'saml_response_xml IS NULL OR length(saml_response_xml) <= 1000000');
SELECT _add_check_if_not_exists('saml_debug_entries', 'chk_debug_request_ip_length', 'request_ip IS NULL OR length(request_ip) <= 45');
SELECT _add_check_if_not_exists('saml_debug_entries', 'chk_debug_user_agent_length', 'user_agent IS NULL OR length(user_agent) <= 1024');

-- ============================================================================
-- idp_certificates
-- ============================================================================
SELECT _add_check_if_not_exists('idp_certificates', 'chk_idp_certs_certificate_pem_length', 'length(certificate_pem) <= 16000');
SELECT _add_check_if_not_exists('idp_certificates', 'chk_idp_certs_fingerprint_length', 'length(fingerprint) <= 512');

-- ============================================================================
-- sp_signing_certificates
-- ============================================================================
SELECT _add_check_if_not_exists('sp_signing_certificates', 'chk_sp_sign_cert_pem_length', 'length(certificate_pem) <= 16000');
SELECT _add_check_if_not_exists('sp_signing_certificates', 'chk_sp_sign_privkey_length', 'length(private_key_pem_enc) <= 16000');
SELECT _add_check_if_not_exists('sp_signing_certificates', 'chk_sp_sign_prev_cert_length', 'previous_certificate_pem IS NULL OR length(previous_certificate_pem) <= 16000');
SELECT _add_check_if_not_exists('sp_signing_certificates', 'chk_sp_sign_prev_privkey_length', 'previous_private_key_pem_enc IS NULL OR length(previous_private_key_pem_enc) <= 16000');

-- ============================================================================
-- saml_sp_certificates
-- ============================================================================
SELECT _add_check_if_not_exists('saml_sp_certificates', 'chk_saml_sp_cert_pem_length', 'length(certificate_pem) <= 16000');
SELECT _add_check_if_not_exists('saml_sp_certificates', 'chk_saml_sp_privkey_length', 'length(private_key_pem_enc) <= 16000');
SELECT _add_check_if_not_exists('saml_sp_certificates', 'chk_saml_sp_prev_cert_length', 'previous_certificate_pem IS NULL OR length(previous_certificate_pem) <= 16000');
SELECT _add_check_if_not_exists('saml_sp_certificates', 'chk_saml_sp_prev_privkey_length', 'previous_private_key_pem_enc IS NULL OR length(previous_private_key_pem_enc) <= 16000');

-- ============================================================================
-- saml_idp_sp_certificates
-- ============================================================================
SELECT _add_check_if_not_exists('saml_idp_sp_certificates', 'chk_idp_sp_cert_pem_length', 'length(certificate_pem) <= 16000');
SELECT _add_check_if_not_exists('saml_idp_sp_certificates', 'chk_idp_sp_privkey_length', 'length(private_key_pem_enc) <= 16000');
SELECT _add_check_if_not_exists('saml_idp_sp_certificates', 'chk_idp_sp_prev_cert_length', 'previous_certificate_pem IS NULL OR length(previous_certificate_pem) <= 16000');
SELECT _add_check_if_not_exists('saml_idp_sp_certificates', 'chk_idp_sp_prev_privkey_length', 'previous_private_key_pem_enc IS NULL OR length(previous_private_key_pem_enc) <= 16000');

-- ============================================================================
-- export_files
-- ============================================================================
SELECT _add_check_if_not_exists('export_files', 'chk_export_filename_length', 'length(filename) <= 255');
SELECT _add_check_if_not_exists('export_files', 'chk_export_storage_path_length', 'length(storage_path) <= 2048');
SELECT _add_check_if_not_exists('export_files', 'chk_export_content_type_length', 'length(content_type) <= 255');

-- ============================================================================
-- tenant_branding
-- ============================================================================
SELECT _add_check_if_not_exists('tenant_branding', 'chk_branding_site_title_length', 'site_title IS NULL OR length(site_title) <= 30');

-- ============================================================================
-- bg_tasks
-- ============================================================================
SELECT _add_check_if_not_exists('bg_tasks', 'chk_bg_tasks_error_length', 'error IS NULL OR length(error) <= 10000');

-- ============================================================================
-- mfa_backup_codes
-- ============================================================================
SELECT _add_check_if_not_exists('mfa_backup_codes', 'chk_mfa_backup_code_hash_length', 'length(code_hash) <= 512');

-- ============================================================================
-- mfa_email_codes
-- ============================================================================
SELECT _add_check_if_not_exists('mfa_email_codes', 'chk_mfa_email_code_hash_length', 'length(code_hash) <= 512');

-- ============================================================================
-- mfa_totp
-- ============================================================================
SELECT _add_check_if_not_exists('mfa_totp', 'chk_mfa_totp_secret_enc_length', 'length(secret_encrypted) <= 16000');

-- Clean up helper function
DROP FUNCTION _add_check_if_not_exists(TEXT, TEXT, TEXT);

COMMIT;
