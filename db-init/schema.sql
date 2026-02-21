-- ============================================================================
-- Baseline Schema for Weft-ID
--
-- This file contains the complete database schema. It is applied automatically
-- by migrate.py on a fresh (empty) database. It replaces the original 46
-- sequential migration files (preserved in git history).
--
-- DO NOT wrap in BEGIN/COMMIT -- the migration runner manages transactions.
-- DO NOT use psql directives (\set, \connect, etc.).
-- ============================================================================

-- ============================================================================
-- 1. ROLES
-- ============================================================================
-- Roles are cluster-wide, so pg_dump does not capture them. We recreate them
-- here with IF NOT EXISTS guards so the baseline is safe to rerun.

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'appowner') THEN
        CREATE ROLE appowner NOLOGIN NOBYPASSRLS;
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'migrator') THEN
        CREATE ROLE migrator LOGIN PASSWORD 'migratorpass' NOBYPASSRLS NOSUPERUSER NOCREATEROLE;
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'appuser') THEN
        CREATE ROLE appuser LOGIN PASSWORD 'apppass' NOBYPASSRLS NOSUPERUSER NOCREATEROLE;
    END IF;
END $$;

GRANT appowner TO migrator;

-- ============================================================================
-- 2. DATABASE & SCHEMA OWNERSHIP
-- ============================================================================
ALTER DATABASE appdb OWNER TO appowner;
ALTER DATABASE appdb SET timezone TO 'UTC';

ALTER SCHEMA public OWNER TO appowner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE appdb FROM PUBLIC;

GRANT CONNECT ON DATABASE appdb TO migrator, appuser;
GRANT USAGE ON SCHEMA public TO appuser;
GRANT CREATE ON SCHEMA public TO appowner;

-- ============================================================================
-- 3. DEFAULT PRIVILEGES
-- ============================================================================
ALTER DEFAULT PRIVILEGES FOR ROLE appowner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO appuser;
ALTER DEFAULT PRIVILEGES FOR ROLE appowner IN SCHEMA public
    GRANT SELECT, USAGE ON SEQUENCES TO appuser;

-- ============================================================================
-- 4. EXTENSIONS
-- ============================================================================
CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

-- ============================================================================
-- 5. TYPES
-- ============================================================================
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'logo_mode') THEN
        CREATE TYPE public.logo_mode AS ENUM ('mandala', 'custom');
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN
        CREATE TYPE public.user_role AS ENUM ('super_admin', 'admin', 'member');
    END IF;
END $$;

-- ============================================================================
-- 6. FUNCTIONS
-- ============================================================================
CREATE FUNCTION public.ensure_single_default_idp() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.is_default = true THEN
        UPDATE saml_identity_providers
        SET is_default = false, updated_at = now()
        WHERE tenant_id = NEW.tenant_id
          AND id != NEW.id
          AND is_default = true;
    END IF;
    RETURN NEW;
END;
$$;

ALTER FUNCTION public.ensure_single_default_idp() OWNER TO appowner;

CREATE FUNCTION public.update_saml_idp_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

ALTER FUNCTION public.update_saml_idp_updated_at() OWNER TO appowner;

CREATE FUNCTION public.update_service_providers_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

ALTER FUNCTION public.update_service_providers_updated_at() OWNER TO appowner;

-- ============================================================================
-- 7. TABLES (in dependency order)
-- ============================================================================

-- tenants: root of the multi-tenant hierarchy. No RLS (subdomain lookup
-- must work before app.tenant_id is set).
CREATE TABLE public.tenants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    subdomain text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tenants_pkey PRIMARY KEY (id),
    CONSTRAINT tenants_subdomain_key UNIQUE (subdomain),
    CONSTRAINT chk_tenants_name_length CHECK ((length(name) <= 255)),
    CONSTRAINT tenants_subdomain_check CHECK ((length(subdomain) <= 63))
);

ALTER TABLE public.tenants OWNER TO appowner;

-- users
CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    first_name text NOT NULL,
    last_name text NOT NULL,
    role public.user_role DEFAULT 'member'::public.user_role NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login timestamp with time zone,
    password_hash text,
    mfa_enabled boolean DEFAULT true,
    mfa_method text DEFAULT 'email'::text,
    tz text,
    locale text,
    is_inactivated boolean DEFAULT false NOT NULL,
    is_anonymized boolean DEFAULT false NOT NULL,
    inactivated_at timestamp with time zone,
    anonymized_at timestamp with time zone,
    reactivation_denied_at timestamp with time zone,
    saml_idp_id uuid,
    theme text DEFAULT 'system'::text,
    CONSTRAINT users_pkey PRIMARY KEY (id),
    CONSTRAINT users_id_tenant_unique UNIQUE (id, tenant_id),
    CONSTRAINT users_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT chk_anonymized_implies_inactivated CHECK (((NOT is_anonymized) OR is_inactivated)),
    CONSTRAINT users_first_name_check CHECK ((length(first_name) <= 200)),
    CONSTRAINT users_last_name_check CHECK ((length(last_name) <= 200)),
    CONSTRAINT users_locale_check CHECK ((length(locale) <= 20)),
    CONSTRAINT users_mfa_method_check CHECK ((mfa_method = ANY (ARRAY['passcode'::text, 'totp'::text, 'email'::text]))),
    CONSTRAINT users_password_hash_check CHECK (((password_hash IS NULL) OR ((char_length(password_hash) >= 60) AND (char_length(password_hash) <= 255)))),
    CONSTRAINT users_theme_check CHECK ((theme = ANY (ARRAY['system'::text, 'light'::text, 'dark'::text]))),
    CONSTRAINT users_tz_check CHECK ((length(tz) <= 100))
);

ALTER TABLE public.users OWNER TO appowner;

-- user_emails
CREATE TABLE public.user_emails (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    email public.citext NOT NULL,
    is_primary boolean DEFAULT false NOT NULL,
    verified_at timestamp with time zone,
    verify_nonce integer DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_emails_pkey PRIMARY KEY (id),
    CONSTRAINT user_emails_tenant_id_email_key UNIQUE (tenant_id, email),
    CONSTRAINT fk_user_emails_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE
);

ALTER TABLE public.user_emails OWNER TO appowner;

-- tenant_privileged_domains
CREATE TABLE public.tenant_privileged_domains (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    domain text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    CONSTRAINT tenant_privileged_domains_pkey PRIMARY KEY (id),
    CONSTRAINT tenant_privileged_domains_tenant_id_domain_key UNIQUE (tenant_id, domain),
    CONSTRAINT tenant_privileged_domains_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_created_by_user FOREIGN KEY (created_by, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE SET NULL,
    CONSTRAINT tenant_privileged_domains_domain_check CHECK (((length(domain) > 0) AND (length(domain) <= 253)))
);

ALTER TABLE public.tenant_privileged_domains OWNER TO appowner;

-- tenant_security_settings
CREATE TABLE public.tenant_security_settings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    session_timeout_seconds integer,
    persistent_sessions boolean DEFAULT true NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_by uuid,
    allow_users_edit_profile boolean DEFAULT true NOT NULL,
    allow_users_add_emails boolean DEFAULT true NOT NULL,
    inactivity_threshold_days integer,
    max_certificate_lifetime_years integer DEFAULT 10 NOT NULL,
    certificate_rotation_window_days integer DEFAULT 90 NOT NULL,
    CONSTRAINT tenant_security_settings_pkey PRIMARY KEY (id),
    CONSTRAINT tenant_security_settings_tenant_id_key UNIQUE (tenant_id),
    CONSTRAINT tenant_security_settings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_updated_by_user FOREIGN KEY (updated_by, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE SET NULL,
    CONSTRAINT chk_certificate_lifetime_years CHECK ((max_certificate_lifetime_years = ANY (ARRAY[1, 2, 3, 5, 10]))),
    CONSTRAINT chk_certificate_rotation_window_days CHECK ((certificate_rotation_window_days = ANY (ARRAY[14, 30, 60, 90]))),
    CONSTRAINT tenant_security_settings_inactivity_threshold_days_check CHECK (((inactivity_threshold_days IS NULL) OR (inactivity_threshold_days > 0))),
    CONSTRAINT tenant_security_settings_session_timeout_seconds_check CHECK (((session_timeout_seconds IS NULL) OR (session_timeout_seconds > 0)))
);

ALTER TABLE public.tenant_security_settings OWNER TO appowner;

-- tenant_branding
CREATE TABLE public.tenant_branding (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    logo_light bytea,
    logo_light_mime text,
    logo_dark bytea,
    logo_dark_mime text,
    logo_mode public.logo_mode DEFAULT 'mandala'::public.logo_mode NOT NULL,
    use_logo_as_favicon boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    site_title text,
    show_title_in_nav boolean DEFAULT true NOT NULL,
    CONSTRAINT tenant_branding_pkey PRIMARY KEY (id),
    CONSTRAINT tenant_branding_tenant_id_key UNIQUE (tenant_id),
    CONSTRAINT tenant_branding_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT chk_branding_site_title_length CHECK (((site_title IS NULL) OR (length(site_title) <= 30))),
    CONSTRAINT chk_logo_dark_mime CHECK ((((logo_dark IS NULL) AND (logo_dark_mime IS NULL)) OR ((logo_dark IS NOT NULL) AND (logo_dark_mime IS NOT NULL)))),
    CONSTRAINT chk_logo_dark_mime_valid CHECK (((logo_dark_mime IS NULL) OR (logo_dark_mime = ANY (ARRAY['image/png'::text, 'image/svg+xml'::text])))),
    CONSTRAINT chk_logo_light_mime CHECK ((((logo_light IS NULL) AND (logo_light_mime IS NULL)) OR ((logo_light IS NOT NULL) AND (logo_light_mime IS NOT NULL)))),
    CONSTRAINT chk_logo_light_mime_valid CHECK (((logo_light_mime IS NULL) OR (logo_light_mime = ANY (ARRAY['image/png'::text, 'image/svg+xml'::text]))))
);

ALTER TABLE public.tenant_branding OWNER TO appowner;

-- mfa_totp
CREATE TABLE public.mfa_totp (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    secret_encrypted text NOT NULL,
    method text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    verified_at timestamp with time zone,
    CONSTRAINT mfa_totp_pkey PRIMARY KEY (id),
    CONSTRAINT mfa_totp_user_id_method_key UNIQUE (user_id, method),
    CONSTRAINT fk_mfa_totp_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_mfa_totp_secret_enc_length CHECK ((length(secret_encrypted) <= 16000)),
    CONSTRAINT mfa_totp_method_check CHECK ((method = ANY (ARRAY['passcode'::text, 'totp'::text])))
);

ALTER TABLE public.mfa_totp OWNER TO appowner;

-- mfa_backup_codes
CREATE TABLE public.mfa_backup_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    code_hash text NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mfa_backup_codes_pkey PRIMARY KEY (id),
    CONSTRAINT fk_mfa_backup_codes_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_mfa_backup_code_hash_length CHECK ((length(code_hash) <= 512))
);

ALTER TABLE public.mfa_backup_codes OWNER TO appowner;

-- mfa_email_codes
CREATE TABLE public.mfa_email_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    code_hash text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mfa_email_codes_pkey PRIMARY KEY (id),
    CONSTRAINT fk_mfa_email_codes_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_mfa_email_code_hash_length CHECK ((length(code_hash) <= 512))
);

ALTER TABLE public.mfa_email_codes OWNER TO appowner;

-- saml_identity_providers
CREATE TABLE public.saml_identity_providers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    provider_type text NOT NULL,
    entity_id text,
    sso_url text,
    slo_url text,
    certificate_pem text,
    metadata_url text,
    metadata_last_fetched_at timestamp with time zone,
    metadata_fetch_error text,
    sp_entity_id text NOT NULL,
    attribute_mapping jsonb DEFAULT '{"email": "email", "last_name": "lastName", "first_name": "firstName"}'::jsonb NOT NULL,
    is_enabled boolean DEFAULT false NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    require_platform_mfa boolean DEFAULT false NOT NULL,
    jit_provisioning boolean DEFAULT false NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    metadata_xml text,
    trust_established boolean DEFAULT false NOT NULL,
    CONSTRAINT saml_identity_providers_pkey PRIMARY KEY (id),
    CONSTRAINT uq_saml_idp_tenant_entity_id UNIQUE (tenant_id, entity_id),
    CONSTRAINT saml_identity_providers_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_idp_created_by_user FOREIGN KEY (created_by, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE SET NULL,
    CONSTRAINT chk_saml_idp_certificate_pem_length CHECK (((certificate_pem IS NULL) OR (length(certificate_pem) <= 16000))),
    CONSTRAINT chk_saml_idp_entity_id_length CHECK (((entity_id IS NULL) OR (length(entity_id) <= 2048))),
    CONSTRAINT chk_saml_idp_metadata_fetch_error_length CHECK (((metadata_fetch_error IS NULL) OR (length(metadata_fetch_error) <= 10000))),
    CONSTRAINT chk_saml_idp_metadata_url_length CHECK (((metadata_url IS NULL) OR (length(metadata_url) <= 2048))),
    CONSTRAINT chk_saml_idp_metadata_xml_length CHECK (((metadata_xml IS NULL) OR (length(metadata_xml) <= 1000000))),
    CONSTRAINT chk_saml_idp_name_length CHECK ((length(name) <= 120)),
    CONSTRAINT chk_saml_idp_slo_url_length CHECK (((slo_url IS NULL) OR (length(slo_url) <= 2048))),
    CONSTRAINT chk_saml_idp_sp_entity_id_length CHECK ((length(sp_entity_id) <= 2048)),
    CONSTRAINT chk_saml_idp_sso_url_length CHECK (((sso_url IS NULL) OR (length(sso_url) <= 2048))),
    CONSTRAINT saml_identity_providers_provider_type_check CHECK ((provider_type = ANY (ARRAY['okta'::text, 'azure_ad'::text, 'google'::text, 'generic'::text])))
);

ALTER TABLE public.saml_identity_providers OWNER TO appowner;

-- Add saml_idp_id FK to users (deferred because of circular dependency)
ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_saml_idp_id_fkey FOREIGN KEY (saml_idp_id) REFERENCES public.saml_identity_providers(id) ON DELETE SET NULL;

-- idp_certificates
CREATE TABLE public.idp_certificates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    idp_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    certificate_pem text NOT NULL,
    fingerprint text NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT idp_certificates_pkey PRIMARY KEY (id),
    CONSTRAINT uq_idp_cert_fingerprint UNIQUE (idp_id, fingerprint),
    CONSTRAINT fk_idp_cert_idp FOREIGN KEY (idp_id) REFERENCES public.saml_identity_providers(id) ON DELETE CASCADE,
    CONSTRAINT fk_idp_cert_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT idp_certificates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT chk_idp_certs_certificate_pem_length CHECK ((length(certificate_pem) <= 16000)),
    CONSTRAINT chk_idp_certs_fingerprint_length CHECK ((length(fingerprint) <= 512))
);

ALTER TABLE public.idp_certificates OWNER TO appowner;

-- saml_idp_domain_bindings
CREATE TABLE public.saml_idp_domain_bindings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    idp_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    CONSTRAINT saml_idp_domain_bindings_pkey PRIMARY KEY (id),
    CONSTRAINT uq_saml_domain_binding UNIQUE (tenant_id, domain_id),
    CONSTRAINT saml_idp_domain_bindings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT saml_idp_domain_bindings_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.tenant_privileged_domains(id) ON DELETE CASCADE,
    CONSTRAINT saml_idp_domain_bindings_idp_id_fkey FOREIGN KEY (idp_id) REFERENCES public.saml_identity_providers(id) ON DELETE CASCADE,
    CONSTRAINT fk_saml_domain_binding_created_by FOREIGN KEY (created_by, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE SET NULL
);

ALTER TABLE public.saml_idp_domain_bindings OWNER TO appowner;

-- saml_sp_certificates (tenant-level SAML SP signing certificates)
CREATE TABLE public.saml_sp_certificates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    certificate_pem text NOT NULL,
    private_key_pem_enc text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    previous_certificate_pem text,
    previous_private_key_pem_enc text,
    previous_expires_at timestamp with time zone,
    rotation_grace_period_ends_at timestamp with time zone,
    CONSTRAINT saml_sp_certificates_pkey PRIMARY KEY (id),
    CONSTRAINT saml_sp_certificates_tenant_id_key UNIQUE (tenant_id),
    CONSTRAINT saml_sp_certificates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_sp_cert_created_by_user FOREIGN KEY (created_by, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE SET NULL,
    CONSTRAINT chk_saml_sp_cert_pem_length CHECK ((length(certificate_pem) <= 16000)),
    CONSTRAINT chk_saml_sp_prev_cert_length CHECK (((previous_certificate_pem IS NULL) OR (length(previous_certificate_pem) <= 16000))),
    CONSTRAINT chk_saml_sp_prev_privkey_length CHECK (((previous_private_key_pem_enc IS NULL) OR (length(previous_private_key_pem_enc) <= 16000))),
    CONSTRAINT chk_saml_sp_privkey_length CHECK ((length(private_key_pem_enc) <= 16000))
);

ALTER TABLE public.saml_sp_certificates OWNER TO appowner;

-- saml_idp_sp_certificates (per-IdP signing certificates)
CREATE TABLE public.saml_idp_sp_certificates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    idp_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    certificate_pem text NOT NULL,
    private_key_pem_enc text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    previous_certificate_pem text,
    previous_private_key_pem_enc text,
    previous_expires_at timestamp with time zone,
    rotation_grace_period_ends_at timestamp with time zone,
    CONSTRAINT saml_idp_sp_certificates_pkey PRIMARY KEY (id),
    CONSTRAINT saml_idp_sp_certificates_idp_id_key UNIQUE (idp_id),
    CONSTRAINT saml_idp_sp_certificates_idp_id_fkey FOREIGN KEY (idp_id) REFERENCES public.saml_identity_providers(id) ON DELETE CASCADE,
    CONSTRAINT saml_idp_sp_certificates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT chk_idp_sp_cert_pem_length CHECK ((length(certificate_pem) <= 16000)),
    CONSTRAINT chk_idp_sp_prev_cert_length CHECK (((previous_certificate_pem IS NULL) OR (length(previous_certificate_pem) <= 16000))),
    CONSTRAINT chk_idp_sp_prev_privkey_length CHECK (((previous_private_key_pem_enc IS NULL) OR (length(previous_private_key_pem_enc) <= 16000))),
    CONSTRAINT chk_idp_sp_privkey_length CHECK ((length(private_key_pem_enc) <= 16000))
);

ALTER TABLE public.saml_idp_sp_certificates OWNER TO appowner;

-- saml_debug_entries
CREATE TABLE public.saml_debug_entries (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    idp_id uuid,
    idp_name text,
    error_type text NOT NULL,
    error_detail text,
    saml_response_b64 text,
    saml_response_xml text,
    request_ip text,
    user_agent text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT saml_debug_entries_pkey PRIMARY KEY (id),
    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT saml_debug_entries_idp_id_fkey FOREIGN KEY (idp_id) REFERENCES public.saml_identity_providers(id) ON DELETE SET NULL,
    CONSTRAINT chk_debug_error_detail_length CHECK (((error_detail IS NULL) OR (length(error_detail) <= 10000))),
    CONSTRAINT chk_debug_error_type_length CHECK ((length(error_type) <= 255)),
    CONSTRAINT chk_debug_idp_name_length CHECK (((idp_name IS NULL) OR (length(idp_name) <= 255))),
    CONSTRAINT chk_debug_request_ip_length CHECK (((request_ip IS NULL) OR (length(request_ip) <= 45))),
    CONSTRAINT chk_debug_saml_response_b64_length CHECK (((saml_response_b64 IS NULL) OR (length(saml_response_b64) <= 1500000))),
    CONSTRAINT chk_debug_saml_response_xml_length CHECK (((saml_response_xml IS NULL) OR (length(saml_response_xml) <= 1000000))),
    CONSTRAINT chk_debug_user_agent_length CHECK (((user_agent IS NULL) OR (length(user_agent) <= 1024)))
);

ALTER TABLE public.saml_debug_entries OWNER TO appowner;

-- oauth2_clients
CREATE TABLE public.oauth2_clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    client_id text NOT NULL,
    client_secret_hash text NOT NULL,
    client_type text NOT NULL,
    name text NOT NULL,
    redirect_uris text[],
    service_user_id uuid,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    description text,
    is_active boolean DEFAULT true NOT NULL,
    CONSTRAINT oauth2_clients_pkey PRIMARY KEY (id),
    CONSTRAINT oauth2_clients_client_id_key UNIQUE (client_id),
    CONSTRAINT oauth2_clients_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_created_by_user FOREIGN KEY (created_by, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE SET NULL,
    CONSTRAINT oauth2_clients_service_user_id_fkey FOREIGN KEY (service_user_id) REFERENCES public.users(id) ON DELETE RESTRICT,
    CONSTRAINT chk_oauth2_clients_client_id_length CHECK ((length(client_id) <= 255)),
    CONSTRAINT chk_oauth2_clients_client_secret_hash_length CHECK ((length(client_secret_hash) <= 512)),
    CONSTRAINT chk_oauth2_clients_description_length CHECK (((description IS NULL) OR (length(description) <= 500))),
    CONSTRAINT chk_oauth2_clients_name_length CHECK ((length(name) <= 255)),
    CONSTRAINT oauth2_clients_client_type_check CHECK ((client_type = ANY (ARRAY['normal'::text, 'b2b'::text])))
);

ALTER TABLE public.oauth2_clients OWNER TO appowner;

-- oauth2_authorization_codes
CREATE TABLE public.oauth2_authorization_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    code_hash text NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid NOT NULL,
    redirect_uri text NOT NULL,
    code_challenge text,
    code_challenge_method text,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth2_authorization_codes_pkey PRIMARY KEY (id),
    CONSTRAINT oauth2_authorization_codes_code_hash_key UNIQUE (code_hash),
    CONSTRAINT oauth2_authorization_codes_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT oauth2_authorization_codes_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth2_clients(id) ON DELETE CASCADE,
    CONSTRAINT fk_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_oauth2_codes_code_challenge_length CHECK (((code_challenge IS NULL) OR (length(code_challenge) <= 128))),
    CONSTRAINT chk_oauth2_codes_code_hash_length CHECK ((length(code_hash) <= 512)),
    CONSTRAINT chk_oauth2_codes_redirect_uri_length CHECK ((length(redirect_uri) <= 2048)),
    CONSTRAINT oauth2_authorization_codes_code_challenge_method_check CHECK ((code_challenge_method = ANY (ARRAY['S256'::text, 'plain'::text])))
);

ALTER TABLE public.oauth2_authorization_codes OWNER TO appowner;

-- oauth2_tokens
CREATE TABLE public.oauth2_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    token_hash text NOT NULL,
    token_type text NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    parent_token_id uuid,
    CONSTRAINT oauth2_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT oauth2_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT oauth2_tokens_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT oauth2_tokens_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth2_clients(id) ON DELETE CASCADE,
    CONSTRAINT fk_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT oauth2_tokens_parent_token_id_fkey FOREIGN KEY (parent_token_id) REFERENCES public.oauth2_tokens(id) ON DELETE CASCADE,
    CONSTRAINT chk_oauth2_tokens_token_hash_length CHECK ((length(token_hash) <= 512)),
    CONSTRAINT oauth2_tokens_token_type_check CHECK ((token_type = ANY (ARRAY['access'::text, 'refresh'::text])))
);

ALTER TABLE public.oauth2_tokens OWNER TO appowner;

-- event_log_metadata
CREATE TABLE public.event_log_metadata (
    metadata_hash character varying(32) NOT NULL,
    metadata jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT event_log_metadata_pkey PRIMARY KEY (metadata_hash)
);

ALTER TABLE public.event_log_metadata OWNER TO appowner;

-- event_logs
CREATE TABLE public.event_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    artifact_type text NOT NULL,
    artifact_id uuid NOT NULL,
    event_type text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    metadata_hash character varying(32) NOT NULL,
    CONSTRAINT event_logs_pkey PRIMARY KEY (id),
    CONSTRAINT event_logs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_event_logs_metadata_hash FOREIGN KEY (metadata_hash) REFERENCES public.event_log_metadata(metadata_hash) ON DELETE RESTRICT,
    CONSTRAINT event_logs_artifact_type_check CHECK ((length(artifact_type) <= 100)),
    CONSTRAINT event_logs_event_type_check CHECK ((length(event_type) <= 100))
);

ALTER TABLE public.event_logs OWNER TO appowner;

-- user_activity
CREATE TABLE public.user_activity (
    user_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    last_activity_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_activity_pkey PRIMARY KEY (user_id),
    CONSTRAINT user_activity_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT user_activity_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE
);

ALTER TABLE public.user_activity OWNER TO appowner;

-- bg_tasks
CREATE TABLE public.bg_tasks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    job_type text NOT NULL,
    payload jsonb,
    status text DEFAULT 'pending'::text NOT NULL,
    result jsonb,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    error text,
    CONSTRAINT bg_tasks_pkey PRIMARY KEY (id),
    CONSTRAINT bg_tasks_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT bg_tasks_job_type_check CHECK ((length(job_type) <= 100)),
    CONSTRAINT bg_tasks_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'processing'::text, 'completed'::text, 'failed'::text]))),
    CONSTRAINT chk_bg_tasks_error_length CHECK (((error IS NULL) OR (length(error) <= 10000)))
);

ALTER TABLE public.bg_tasks OWNER TO appowner;

-- export_files
CREATE TABLE public.export_files (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    bg_task_id uuid,
    filename text NOT NULL,
    storage_type text NOT NULL,
    storage_path text NOT NULL,
    file_size bigint,
    content_type text DEFAULT 'application/gzip'::text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    downloaded_at timestamp with time zone,
    CONSTRAINT export_files_pkey PRIMARY KEY (id),
    CONSTRAINT export_files_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT export_files_bg_task_id_fkey FOREIGN KEY (bg_task_id) REFERENCES public.bg_tasks(id) ON DELETE SET NULL,
    CONSTRAINT chk_export_content_type_length CHECK ((length(content_type) <= 255)),
    CONSTRAINT chk_export_filename_length CHECK ((length(filename) <= 255)),
    CONSTRAINT chk_export_storage_path_length CHECK ((length(storage_path) <= 2048)),
    CONSTRAINT export_files_storage_type_check CHECK ((storage_type = ANY (ARRAY['local'::text, 'spaces'::text])))
);

ALTER TABLE public.export_files OWNER TO appowner;

-- reactivation_requests
CREATE TABLE public.reactivation_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    decided_by uuid,
    decided_at timestamp with time zone,
    decision text,
    CONSTRAINT reactivation_requests_pkey PRIMARY KEY (id),
    CONSTRAINT reactivation_requests_tenant_id_user_id_key UNIQUE (tenant_id, user_id),
    CONSTRAINT reactivation_requests_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT reactivation_requests_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE,
    CONSTRAINT reactivation_requests_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES public.users(id),
    CONSTRAINT reactivation_requests_decision_check CHECK ((decision = ANY (ARRAY['approved'::text, 'denied'::text])))
);

ALTER TABLE public.reactivation_requests OWNER TO appowner;

-- groups
CREATE TABLE public.groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    group_type text DEFAULT 'weftid'::text NOT NULL,
    idp_id uuid,
    is_valid boolean DEFAULT true NOT NULL,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT groups_pkey PRIMARY KEY (id),
    CONSTRAINT groups_id_tenant_unique UNIQUE (id, tenant_id),
    CONSTRAINT groups_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_groups_idp FOREIGN KEY (idp_id) REFERENCES public.saml_identity_providers(id) ON DELETE SET NULL,
    CONSTRAINT groups_description_check CHECK (((description IS NULL) OR (length(description) <= 2000))),
    CONSTRAINT groups_group_type_check CHECK ((group_type = ANY (ARRAY['weftid'::text, 'idp'::text]))),
    CONSTRAINT groups_name_check CHECK ((length(name) <= 200))
);

ALTER TABLE public.groups OWNER TO appowner;

-- group_memberships
CREATE TABLE public.group_memberships (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    group_id uuid NOT NULL,
    user_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT group_memberships_pkey PRIMARY KEY (id),
    CONSTRAINT group_memberships_group_id_user_id_key UNIQUE (group_id, user_id),
    CONSTRAINT fk_group_memberships_group FOREIGN KEY (group_id, tenant_id) REFERENCES public.groups(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_group_memberships_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE
);

ALTER TABLE public.group_memberships OWNER TO appowner;

-- group_relationships
CREATE TABLE public.group_relationships (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    parent_group_id uuid NOT NULL,
    child_group_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT group_relationships_pkey PRIMARY KEY (id),
    CONSTRAINT group_relationships_parent_group_id_child_group_id_key UNIQUE (parent_group_id, child_group_id),
    CONSTRAINT fk_group_relationships_parent FOREIGN KEY (parent_group_id, tenant_id) REFERENCES public.groups(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_group_relationships_child FOREIGN KEY (child_group_id, tenant_id) REFERENCES public.groups(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_no_self_relationship CHECK ((parent_group_id <> child_group_id))
);

ALTER TABLE public.group_relationships OWNER TO appowner;

-- group_lineage (closure table for DAG hierarchy)
CREATE TABLE public.group_lineage (
    tenant_id uuid NOT NULL,
    ancestor_id uuid NOT NULL,
    descendant_id uuid NOT NULL,
    depth integer NOT NULL,
    CONSTRAINT group_lineage_pkey PRIMARY KEY (ancestor_id, descendant_id),
    CONSTRAINT fk_group_lineage_ancestor FOREIGN KEY (ancestor_id, tenant_id) REFERENCES public.groups(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_group_lineage_descendant FOREIGN KEY (descendant_id, tenant_id) REFERENCES public.groups(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT group_lineage_depth_check CHECK ((depth >= 0))
);

ALTER TABLE public.group_lineage OWNER TO appowner;

-- service_providers
CREATE TABLE public.service_providers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    entity_id text,
    acs_url text,
    certificate_pem text,
    nameid_format text DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'::text NOT NULL,
    metadata_xml text,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    description text,
    enabled boolean DEFAULT true NOT NULL,
    slo_url text,
    include_group_claims boolean DEFAULT false NOT NULL,
    sp_requested_attributes jsonb,
    attribute_mapping jsonb,
    metadata_url text,
    trust_established boolean DEFAULT false NOT NULL,
    CONSTRAINT service_providers_pkey PRIMARY KEY (id),
    CONSTRAINT uq_sp_tenant_entity_id UNIQUE (tenant_id, entity_id),
    CONSTRAINT service_providers_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_sp_created_by FOREIGN KEY (created_by, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE SET NULL,
    CONSTRAINT chk_sp_acs_url_length CHECK (((acs_url IS NULL) OR (length(acs_url) <= 2048))),
    CONSTRAINT chk_sp_certificate_pem_length CHECK (((certificate_pem IS NULL) OR (length(certificate_pem) <= 16000))),
    CONSTRAINT chk_sp_description_length CHECK (((description IS NULL) OR (length(description) <= 2000))),
    CONSTRAINT chk_sp_entity_id_length CHECK (((entity_id IS NULL) OR (length(entity_id) <= 2048))),
    CONSTRAINT chk_sp_metadata_url_length CHECK (((metadata_url IS NULL) OR (length(metadata_url) <= 2048))),
    CONSTRAINT chk_sp_metadata_xml_length CHECK (((metadata_xml IS NULL) OR (length(metadata_xml) <= 1000000))),
    CONSTRAINT chk_sp_name_length CHECK ((length(name) <= 255)),
    CONSTRAINT chk_sp_nameid_format_length CHECK ((length(nameid_format) <= 255)),
    CONSTRAINT chk_sp_slo_url_length CHECK (((slo_url IS NULL) OR (length(slo_url) <= 2048)))
);

ALTER TABLE public.service_providers OWNER TO appowner;

-- sp_signing_certificates (per-SP signing certificates)
CREATE TABLE public.sp_signing_certificates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sp_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    certificate_pem text NOT NULL,
    private_key_pem_enc text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    previous_certificate_pem text,
    previous_private_key_pem_enc text,
    previous_expires_at timestamp with time zone,
    rotation_grace_period_ends_at timestamp with time zone,
    CONSTRAINT sp_signing_certificates_pkey PRIMARY KEY (id),
    CONSTRAINT sp_signing_certificates_sp_id_key UNIQUE (sp_id),
    CONSTRAINT fk_sp_signing_cert_sp FOREIGN KEY (sp_id) REFERENCES public.service_providers(id) ON DELETE CASCADE,
    CONSTRAINT fk_sp_signing_cert_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT sp_signing_certificates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT chk_sp_sign_cert_pem_length CHECK ((length(certificate_pem) <= 16000)),
    CONSTRAINT chk_sp_sign_prev_cert_length CHECK (((previous_certificate_pem IS NULL) OR (length(previous_certificate_pem) <= 16000))),
    CONSTRAINT chk_sp_sign_prev_privkey_length CHECK (((previous_private_key_pem_enc IS NULL) OR (length(previous_private_key_pem_enc) <= 16000))),
    CONSTRAINT chk_sp_sign_privkey_length CHECK ((length(private_key_pem_enc) <= 16000))
);

ALTER TABLE public.sp_signing_certificates OWNER TO appowner;

-- sp_group_assignments
CREATE TABLE public.sp_group_assignments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    sp_id uuid NOT NULL,
    group_id uuid NOT NULL,
    assigned_by uuid NOT NULL,
    assigned_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT sp_group_assignments_pkey PRIMARY KEY (id),
    CONSTRAINT uq_sp_group_assignment UNIQUE (sp_id, group_id),
    CONSTRAINT sp_group_assignments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT sp_group_assignments_sp_id_fkey FOREIGN KEY (sp_id) REFERENCES public.service_providers(id) ON DELETE CASCADE,
    CONSTRAINT sp_group_assignments_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE
);

ALTER TABLE public.sp_group_assignments OWNER TO appowner;

-- sp_nameid_mappings (per-SP persistent NameID values)
CREATE TABLE public.sp_nameid_mappings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    sp_id uuid NOT NULL,
    nameid_value text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT sp_nameid_mappings_pkey PRIMARY KEY (id),
    CONSTRAINT uq_sp_nameid_mapping UNIQUE (tenant_id, user_id, sp_id),
    CONSTRAINT sp_nameid_mappings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT sp_nameid_mappings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE,
    CONSTRAINT sp_nameid_mappings_sp_id_fkey FOREIGN KEY (sp_id) REFERENCES public.service_providers(id) ON DELETE CASCADE,
    CONSTRAINT chk_sp_nameid_value_length CHECK (length(nameid_value) <= 255)
);

ALTER TABLE public.sp_nameid_mappings OWNER TO appowner;

-- ============================================================================
-- 8. INDEXES
-- ============================================================================

-- users
CREATE INDEX idx_users_tenant ON public.users USING btree (tenant_id);
CREATE INDEX idx_users_tenant_role ON public.users USING btree (tenant_id, role);
CREATE INDEX idx_users_inactivated ON public.users USING btree (tenant_id, is_inactivated) WHERE (is_inactivated = true);
CREATE INDEX idx_users_anonymized ON public.users USING btree (tenant_id, is_anonymized) WHERE (is_anonymized = true);
CREATE INDEX idx_users_saml_idp ON public.users USING btree (saml_idp_id) WHERE (saml_idp_id IS NOT NULL);

-- user_emails
CREATE INDEX idx_user_emails_user_id ON public.user_emails USING btree (user_id);
CREATE UNIQUE INDEX user_emails_primary_per_user ON public.user_emails USING btree (user_id) WHERE is_primary;

-- tenant_privileged_domains
CREATE INDEX idx_tenant_privileged_domains_tenant ON public.tenant_privileged_domains USING btree (tenant_id);

-- tenant_security_settings
CREATE INDEX idx_tenant_security_settings_tenant ON public.tenant_security_settings USING btree (tenant_id);

-- tenant_branding
CREATE INDEX idx_tenant_branding_tenant ON public.tenant_branding USING btree (tenant_id);

-- mfa
CREATE INDEX idx_mfa_totp_user ON public.mfa_totp USING btree (user_id);
CREATE INDEX idx_mfa_backup_codes_user ON public.mfa_backup_codes USING btree (user_id) WHERE (used_at IS NULL);
CREATE INDEX idx_mfa_email_codes_user_expires ON public.mfa_email_codes USING btree (user_id, expires_at) WHERE (used_at IS NULL);

-- saml_identity_providers
CREATE INDEX idx_saml_idp_tenant ON public.saml_identity_providers USING btree (tenant_id);
CREATE INDEX idx_saml_idp_tenant_default ON public.saml_identity_providers USING btree (tenant_id) WHERE (is_default = true);
CREATE INDEX idx_saml_idp_tenant_enabled ON public.saml_identity_providers USING btree (tenant_id) WHERE (is_enabled = true);
CREATE INDEX idx_saml_idp_with_metadata_url ON public.saml_identity_providers USING btree (id) WHERE (metadata_url IS NOT NULL);

-- idp_certificates
CREATE INDEX idx_idp_certificates_idp ON public.idp_certificates USING btree (idp_id);
CREATE INDEX idx_idp_certificates_tenant ON public.idp_certificates USING btree (tenant_id);

-- saml_idp_domain_bindings
CREATE INDEX idx_saml_domain_bindings_tenant ON public.saml_idp_domain_bindings USING btree (tenant_id);
CREATE INDEX idx_saml_domain_bindings_domain ON public.saml_idp_domain_bindings USING btree (domain_id);
CREATE INDEX idx_saml_domain_bindings_idp ON public.saml_idp_domain_bindings USING btree (idp_id);

-- saml_sp_certificates
CREATE INDEX idx_saml_sp_certificates_tenant ON public.saml_sp_certificates USING btree (tenant_id);

-- saml_idp_sp_certificates
CREATE INDEX idx_saml_idp_sp_certificates_tenant ON public.saml_idp_sp_certificates USING btree (tenant_id);

-- saml_debug_entries
CREATE INDEX idx_saml_debug_entries_tenant ON public.saml_debug_entries USING btree (tenant_id, created_at DESC);
CREATE INDEX idx_saml_debug_entries_cleanup ON public.saml_debug_entries USING btree (created_at);

-- oauth2_clients
CREATE INDEX idx_oauth2_clients_tenant ON public.oauth2_clients USING btree (tenant_id);
CREATE INDEX idx_oauth2_clients_service_user ON public.oauth2_clients USING btree (service_user_id) WHERE (service_user_id IS NOT NULL);

-- oauth2_authorization_codes
CREATE INDEX idx_oauth2_codes_tenant ON public.oauth2_authorization_codes USING btree (tenant_id);
CREATE INDEX idx_oauth2_codes_expires ON public.oauth2_authorization_codes USING btree (expires_at);

-- oauth2_tokens
CREATE INDEX idx_oauth2_tokens_tenant ON public.oauth2_tokens USING btree (tenant_id);
CREATE INDEX idx_oauth2_tokens_hash ON public.oauth2_tokens USING btree (token_hash);
CREATE INDEX idx_oauth2_tokens_user ON public.oauth2_tokens USING btree (user_id);
CREATE INDEX idx_oauth2_tokens_expires ON public.oauth2_tokens USING btree (expires_at);

-- event_log_metadata
CREATE INDEX idx_event_log_metadata_created ON public.event_log_metadata USING btree (created_at DESC);

-- event_logs
CREATE INDEX idx_event_logs_tenant_created ON public.event_logs USING btree (tenant_id, created_at DESC);
CREATE INDEX idx_event_logs_actor ON public.event_logs USING btree (tenant_id, actor_user_id, created_at DESC);
CREATE INDEX idx_event_logs_artifact ON public.event_logs USING btree (tenant_id, artifact_type, artifact_id, created_at DESC);
CREATE INDEX idx_event_logs_event_type ON public.event_logs USING btree (tenant_id, event_type, created_at DESC);
CREATE INDEX idx_event_logs_metadata_hash ON public.event_logs USING btree (metadata_hash);

-- user_activity
CREATE INDEX idx_user_activity_tenant_time ON public.user_activity USING btree (tenant_id, last_activity_at DESC);

-- bg_tasks
CREATE INDEX idx_bg_tasks_pending ON public.bg_tasks USING btree (created_at) WHERE (status = 'pending'::text);
CREATE INDEX idx_bg_tasks_tenant_created ON public.bg_tasks USING btree (tenant_id, created_at DESC);
CREATE INDEX idx_bg_tasks_tenant_type ON public.bg_tasks USING btree (tenant_id, job_type, created_at DESC);

-- export_files
CREATE INDEX idx_export_files_tenant_created ON public.export_files USING btree (tenant_id, created_at DESC);
CREATE INDEX idx_export_files_expired ON public.export_files USING btree (expires_at) WHERE (expires_at IS NOT NULL);

-- reactivation_requests
CREATE INDEX idx_reactivation_requests_pending ON public.reactivation_requests USING btree (tenant_id) WHERE (decision IS NULL);

-- groups
CREATE INDEX idx_groups_tenant ON public.groups USING btree (tenant_id);
CREATE INDEX idx_groups_tenant_type ON public.groups USING btree (tenant_id, group_type);
CREATE INDEX idx_groups_idp_id ON public.groups USING btree (idp_id) WHERE (idp_id IS NOT NULL);
CREATE UNIQUE INDEX idx_groups_weftid_name_unique ON public.groups USING btree (tenant_id, name) WHERE (idp_id IS NULL);
CREATE UNIQUE INDEX idx_groups_idp_name_unique ON public.groups USING btree (tenant_id, idp_id, name) WHERE (idp_id IS NOT NULL);

-- group_memberships
CREATE INDEX idx_group_memberships_group ON public.group_memberships USING btree (group_id);
CREATE INDEX idx_group_memberships_user ON public.group_memberships USING btree (user_id);

-- group_relationships
CREATE INDEX idx_group_relationships_parent ON public.group_relationships USING btree (parent_group_id);
CREATE INDEX idx_group_relationships_child ON public.group_relationships USING btree (child_group_id);

-- group_lineage
CREATE INDEX idx_group_lineage_tenant ON public.group_lineage USING btree (tenant_id);
CREATE INDEX idx_group_lineage_ancestor ON public.group_lineage USING btree (ancestor_id);
CREATE INDEX idx_group_lineage_descendant ON public.group_lineage USING btree (descendant_id);

-- service_providers
CREATE INDEX idx_service_providers_tenant ON public.service_providers USING btree (tenant_id);
CREATE INDEX idx_service_providers_tenant_entity_id ON public.service_providers USING btree (tenant_id, entity_id);

-- sp_signing_certificates
CREATE INDEX idx_sp_signing_certificates_sp_id ON public.sp_signing_certificates USING btree (sp_id);
CREATE INDEX idx_sp_signing_certificates_tenant ON public.sp_signing_certificates USING btree (tenant_id);

-- sp_group_assignments
CREATE INDEX idx_sp_group_assignments_tenant_sp ON public.sp_group_assignments USING btree (tenant_id, sp_id);
CREATE INDEX idx_sp_group_assignments_tenant_group ON public.sp_group_assignments USING btree (tenant_id, group_id);

-- sp_nameid_mappings
CREATE INDEX idx_sp_nameid_mappings_tenant ON public.sp_nameid_mappings USING btree (tenant_id);
CREATE INDEX idx_sp_nameid_mappings_user_sp ON public.sp_nameid_mappings USING btree (user_id, sp_id);

-- ============================================================================
-- 9. TRIGGERS
-- ============================================================================
CREATE TRIGGER trg_ensure_single_default_idp
    BEFORE INSERT OR UPDATE OF is_default ON public.saml_identity_providers
    FOR EACH ROW WHEN ((new.is_default = true))
    EXECUTE FUNCTION public.ensure_single_default_idp();

CREATE TRIGGER trg_saml_idp_updated_at
    BEFORE UPDATE ON public.saml_identity_providers
    FOR EACH ROW
    EXECUTE FUNCTION public.update_saml_idp_updated_at();

CREATE TRIGGER trg_service_providers_updated_at
    BEFORE UPDATE ON public.service_providers
    FOR EACH ROW
    EXECUTE FUNCTION public.update_service_providers_updated_at();

-- ============================================================================
-- 10. ROW LEVEL SECURITY
-- ============================================================================

-- users
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY users_tenant_isolation ON public.users
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

-- user_emails
ALTER TABLE public.user_emails ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_emails_tenant_isolation ON public.user_emails
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

-- tenant_privileged_domains
ALTER TABLE public.tenant_privileged_domains ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_privileged_domains_isolation ON public.tenant_privileged_domains
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

-- tenant_security_settings
ALTER TABLE public.tenant_security_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_security_settings_isolation ON public.tenant_security_settings
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

-- tenant_branding
ALTER TABLE public.tenant_branding ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_branding_tenant_isolation ON public.tenant_branding
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

-- mfa_totp
ALTER TABLE public.mfa_totp ENABLE ROW LEVEL SECURITY;
CREATE POLICY mfa_totp_tenant_isolation ON public.mfa_totp
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

-- mfa_backup_codes
ALTER TABLE public.mfa_backup_codes ENABLE ROW LEVEL SECURITY;
CREATE POLICY mfa_backup_codes_tenant_isolation ON public.mfa_backup_codes
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

-- mfa_email_codes
ALTER TABLE public.mfa_email_codes ENABLE ROW LEVEL SECURITY;
CREATE POLICY mfa_email_codes_tenant_isolation ON public.mfa_email_codes
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

-- saml_identity_providers
ALTER TABLE public.saml_identity_providers ENABLE ROW LEVEL SECURITY;
CREATE POLICY saml_idp_tenant_isolation ON public.saml_identity_providers
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

-- idp_certificates
ALTER TABLE public.idp_certificates ENABLE ROW LEVEL SECURITY;
CREATE POLICY idp_certificates_tenant_isolation ON public.idp_certificates
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

-- saml_idp_domain_bindings
ALTER TABLE public.saml_idp_domain_bindings ENABLE ROW LEVEL SECURITY;
CREATE POLICY saml_domain_bindings_isolation ON public.saml_idp_domain_bindings
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

-- saml_sp_certificates
ALTER TABLE public.saml_sp_certificates ENABLE ROW LEVEL SECURITY;
CREATE POLICY saml_sp_certificates_tenant_isolation ON public.saml_sp_certificates
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

-- saml_idp_sp_certificates
ALTER TABLE public.saml_idp_sp_certificates ENABLE ROW LEVEL SECURITY;
CREATE POLICY saml_idp_sp_certificates_tenant_isolation ON public.saml_idp_sp_certificates
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

-- saml_debug_entries (no RLS - accessed by system processes)

-- oauth2_clients
ALTER TABLE public.oauth2_clients ENABLE ROW LEVEL SECURITY;
CREATE POLICY oauth2_clients_tenant_isolation ON public.oauth2_clients
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

-- oauth2_authorization_codes
ALTER TABLE public.oauth2_authorization_codes ENABLE ROW LEVEL SECURITY;
CREATE POLICY oauth2_codes_tenant_isolation ON public.oauth2_authorization_codes
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

-- oauth2_tokens
ALTER TABLE public.oauth2_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY oauth2_tokens_tenant_isolation ON public.oauth2_tokens
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

-- event_logs
ALTER TABLE public.event_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY event_logs_tenant_isolation ON public.event_logs
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

-- user_activity
ALTER TABLE public.user_activity ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_activity_tenant_isolation ON public.user_activity
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

-- bg_tasks (no RLS - worker processes need cross-tenant access)

-- export_files
ALTER TABLE public.export_files ENABLE ROW LEVEL SECURITY;
CREATE POLICY export_files_tenant_isolation ON public.export_files
    USING (
        CASE
            WHEN (NULLIF(current_setting('app.tenant_id'::text, true), ''::text) IS NULL) THEN true
            ELSE (tenant_id = (current_setting('app.tenant_id'::text, true))::uuid)
        END)
    WITH CHECK (
        CASE
            WHEN (NULLIF(current_setting('app.tenant_id'::text, true), ''::text) IS NULL) THEN true
            ELSE (tenant_id = (current_setting('app.tenant_id'::text, true))::uuid)
        END);

-- reactivation_requests
ALTER TABLE public.reactivation_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY reactivation_requests_tenant_isolation ON public.reactivation_requests
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

-- groups
ALTER TABLE public.groups ENABLE ROW LEVEL SECURITY;
CREATE POLICY groups_tenant_isolation ON public.groups
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

-- group_memberships
ALTER TABLE public.group_memberships ENABLE ROW LEVEL SECURITY;
CREATE POLICY group_memberships_tenant_isolation ON public.group_memberships
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

-- group_relationships
ALTER TABLE public.group_relationships ENABLE ROW LEVEL SECURITY;
CREATE POLICY group_relationships_tenant_isolation ON public.group_relationships
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

-- group_lineage
ALTER TABLE public.group_lineage ENABLE ROW LEVEL SECURITY;
CREATE POLICY group_lineage_tenant_isolation ON public.group_lineage
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

-- service_providers
ALTER TABLE public.service_providers ENABLE ROW LEVEL SECURITY;
CREATE POLICY service_providers_tenant_isolation ON public.service_providers
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

-- sp_signing_certificates
ALTER TABLE public.sp_signing_certificates ENABLE ROW LEVEL SECURITY;
CREATE POLICY sp_signing_certificates_tenant_isolation ON public.sp_signing_certificates
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

-- sp_group_assignments
ALTER TABLE public.sp_group_assignments ENABLE ROW LEVEL SECURITY;
CREATE POLICY sp_group_assignments_tenant_isolation ON public.sp_group_assignments
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

-- sp_nameid_mappings
ALTER TABLE public.sp_nameid_mappings ENABLE ROW LEVEL SECURITY;
CREATE POLICY sp_nameid_mappings_tenant_isolation ON public.sp_nameid_mappings
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

-- ============================================================================
-- 11. EXPLICIT GRANTS
-- ============================================================================
-- Default privileges cover future tables, but these were created by postgres
-- (not appowner), so explicit grants are needed.

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.tenants TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.users TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.user_emails TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.tenant_privileged_domains TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.tenant_security_settings TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.tenant_branding TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.mfa_totp TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.mfa_backup_codes TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.mfa_email_codes TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.saml_identity_providers TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.idp_certificates TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.saml_idp_domain_bindings TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.saml_sp_certificates TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.saml_idp_sp_certificates TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.saml_debug_entries TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oauth2_clients TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oauth2_authorization_codes TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oauth2_tokens TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.event_log_metadata TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.event_logs TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.user_activity TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.bg_tasks TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.export_files TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.reactivation_requests TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.groups TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.group_memberships TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.group_relationships TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.group_lineage TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.service_providers TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.sp_signing_certificates TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.sp_group_assignments TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.sp_nameid_mappings TO appuser;

-- ============================================================================
-- 12. SCHEMA MIGRATION LOG
-- ============================================================================
-- System table for tracking migration state. No RLS, no tenant_id.
-- Owned by postgres (infrastructure, not application data).

CREATE TABLE IF NOT EXISTS schema_migration_log (
    id SERIAL PRIMARY KEY,
    version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('success', 'failed')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    error_traceback TEXT
);

-- Record the baseline as successfully applied
INSERT INTO schema_migration_log (version, status, completed_at)
VALUES ('baseline', 'success', now());
