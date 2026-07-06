-- migration-safety: ignore (the table is CREATEd in this same migration, so it
-- starts empty and there are no existing rows or concurrent writers for the
-- index build to block; CONCURRENTLY is unnecessary and cannot run in-transaction.)
--
-- Per-tenant OIDC signing keys.
--
-- WeftID acts as a downstream OIDC provider. Each tenant gets one RSA
-- signing keypair used to sign RS256 ID tokens (issuance lands in a later
-- iteration) and published as a JWKS at /.well-known/jwks.json.
--
-- Shape mirrors sp_signing_certificates (per-SP SAML signing keys): a
-- "current" key plus a "previous" key retained through a rotation grace
-- period, so relying parties can still verify tokens signed by the old key
-- until it is cleaned up. Differences from the SAML table:
--   * scoped per-tenant (UNIQUE tenant_id), not per-SP;
--   * stores an RSA public-key PEM (SubjectPublicKeyInfo) rather than an
--     X.509 certificate -- OIDC JWKS exposes only n/e, there is no cert chain;
--   * carries a stable, JWKS-visible key id (kid) for current and previous;
--   * created_by is nullable because the key is lazily provisioned on first
--     use, which may be an unauthenticated public JWKS fetch (no actor user).
--
-- Private key material is stored encrypted at rest via the same Fernet helper
-- used for SAML private keys (utils.saml.encrypt_private_key); the plaintext
-- private PEM never touches this table.
--
-- RLS mirrors the strict tenant-isolation policy used by sp_signing_certificates
-- (baseline schema): both USING and WITH CHECK require tenant_id to equal the
-- request-scoped app.tenant_id, so lazy provisioning and JWKS reads resolve
-- only the current tenant's key and an UNSCOPED write fails closed.

SET LOCAL ROLE appowner;

CREATE TABLE IF NOT EXISTS public.oidc_signing_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    kid character varying(64) NOT NULL,
    algorithm character varying(10) DEFAULT 'RS256' NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    public_key_pem text NOT NULL,
    private_key_pem_enc text NOT NULL,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    previous_kid character varying(64),
    previous_public_key_pem text,
    previous_private_key_pem_enc text,
    previous_created_at timestamp with time zone,
    rotation_grace_period_ends_at timestamp with time zone,
    CONSTRAINT oidc_signing_keys_pkey PRIMARY KEY (id),
    CONSTRAINT oidc_signing_keys_tenant_id_key UNIQUE (tenant_id),
    CONSTRAINT fk_oidc_signing_key_tenant FOREIGN KEY (tenant_id)
        REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT chk_oidc_key_algorithm CHECK ((algorithm = 'RS256')),
    CONSTRAINT chk_oidc_key_pubkey_length CHECK ((length(public_key_pem) <= 16000)),
    CONSTRAINT chk_oidc_key_privkey_length CHECK ((length(private_key_pem_enc) <= 16000)),
    CONSTRAINT chk_oidc_prev_pubkey_length
        CHECK (((previous_public_key_pem IS NULL) OR (length(previous_public_key_pem) <= 16000))),
    CONSTRAINT chk_oidc_prev_privkey_length
        CHECK (((previous_private_key_pem_enc IS NULL) OR (length(previous_private_key_pem_enc) <= 16000)))
);

ALTER TABLE public.oidc_signing_keys OWNER TO appowner;

CREATE INDEX IF NOT EXISTS idx_oidc_signing_keys_tenant
    ON public.oidc_signing_keys USING btree (tenant_id);

ALTER TABLE public.oidc_signing_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY oidc_signing_keys_tenant_isolation ON public.oidc_signing_keys
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));
