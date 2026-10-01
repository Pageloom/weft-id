-- migration-safety: ignore (both oauth2_clients columns are nullable or have a
-- constant default, catalog-only changes; the CHECKs read a table of a few
-- rows per tenant, and every existing row passes them because subject_type
-- starts 'public' and sector_identifier_uri starts NULL.)
--
-- Pairwise subject identifiers (OpenID Connect Core 1.0 section 8.1).
--
-- * oauth2_clients.subject_type: 'public' (sub is the WeftID user id, as
--   before) or 'pairwise' (sub is derived from the user id and the client's
--   sector, so clients in different sectors cannot correlate users). A
--   per-client opt-in; existing clients keep 'public'.
-- * sector_identifier_uri: an https URL serving a JSON array of the client's
--   redirect URIs. When set, its host is the sector; otherwise the sector is
--   the host of the client's redirect URIs (which must then share one host).
--   Only meaningful for a pairwise client.

SET LOCAL ROLE appowner;

ALTER TABLE public.oauth2_clients
    ADD COLUMN IF NOT EXISTS subject_type text DEFAULT 'public'::text NOT NULL,
    ADD COLUMN IF NOT EXISTS sector_identifier_uri text,
    ADD CONSTRAINT chk_oauth2_clients_subject_type
        CHECK ((subject_type = ANY (ARRAY['public'::text, 'pairwise'::text]))),
    ADD CONSTRAINT chk_oauth2_clients_sector_identifier_uri
        CHECK (((sector_identifier_uri IS NULL)
            OR ((subject_type = 'pairwise'::text) AND (length(sector_identifier_uri) <= 2048))));
