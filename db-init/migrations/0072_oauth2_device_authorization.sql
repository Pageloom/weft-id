-- migration-safety: ignore (the table is CREATEd in this same migration, so it
-- starts empty and there are no existing rows or concurrent writers for the
-- index builds to block; CONCURRENTLY is unnecessary and cannot run
-- in-transaction. The oauth2_clients column has a constant default, a
-- catalog-only change.)
--
-- OAuth 2.0 Device Authorization Grant (RFC 8628).
--
-- * oauth2_clients.device_grant_enabled: an admin opts a normal client into
--   the grant. Off by default; B2B clients never get it (service layer).
--
-- * oauth2_device_codes: one row per device authorization request. The device
--   polls the token endpoint with the device_code; the user approves on
--   /device after typing the user_code. Both are stored hashed:
--     - device_code: 256 bits of entropy, so the indexed SHA-256 lookup plus
--       an Argon2 hash on the one candidate row, like authorization codes.
--     - user_code: 8 characters a person can type (about 34 bits), stored only
--       as its SHA-256 lookup digest. It is useless without the device_code
--       and lives 10 minutes; the unique key makes a collision a retry.
--   status moves pending -> approved | denied, and approved -> redeemed
--   exactly once (conditional update). poll_interval grows by 5 seconds on
--   each slow_down. auth_time is the approving session's login time, for the
--   ID token. Expired rows are swept on the path that adds rows.
--
-- RLS follows the strict NULLIF tenant-isolation policy of the newer tables.

SET LOCAL ROLE appowner;

ALTER TABLE public.oauth2_clients
    ADD COLUMN IF NOT EXISTS device_grant_enabled boolean DEFAULT false NOT NULL;

CREATE TABLE public.oauth2_device_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    device_code_hash text NOT NULL,
    device_code_lookup text NOT NULL,
    user_code_lookup text NOT NULL,
    scope character varying(500),
    status text DEFAULT 'pending'::text NOT NULL,
    user_id uuid,
    auth_time timestamp with time zone,
    poll_interval integer DEFAULT 5 NOT NULL,
    last_polled_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    decided_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth2_device_codes_pkey PRIMARY KEY (id),
    CONSTRAINT uq_oauth2_device_codes_device_lookup UNIQUE (device_code_lookup),
    CONSTRAINT uq_oauth2_device_codes_user_lookup UNIQUE (tenant_id, user_code_lookup),
    CONSTRAINT oauth2_device_codes_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT oauth2_device_codes_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth2_clients(id) ON DELETE CASCADE,
    CONSTRAINT fk_oauth2_device_codes_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_oauth2_device_codes_status CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'denied'::text, 'redeemed'::text]))),
    CONSTRAINT chk_oauth2_device_codes_hash_length CHECK ((length(device_code_hash) <= 512)),
    CONSTRAINT chk_oauth2_device_codes_lookup_length CHECK (((length(device_code_lookup) <= 64) AND (length(user_code_lookup) <= 64))),
    CONSTRAINT chk_oauth2_device_codes_interval CHECK (((poll_interval >= 1) AND (poll_interval <= 300)))
);

ALTER TABLE public.oauth2_device_codes OWNER TO appowner;

CREATE INDEX idx_oauth2_device_codes_tenant_expires ON public.oauth2_device_codes USING btree (tenant_id, expires_at);

ALTER TABLE public.oauth2_device_codes ENABLE ROW LEVEL SECURITY;
CREATE POLICY oauth2_device_codes_tenant_isolation ON public.oauth2_device_codes
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oauth2_device_codes TO appuser;
