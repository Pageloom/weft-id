-- Social sign-in: the column set for consumer identity providers.
--
-- One migration for the whole social sign-in feature, so later iterations
-- need no further change to these tables:
--
-- * oidc_idp_connections.provider_type: the consumer providers join the
--   existing generic/google/entra types. microsoft (personal accounts),
--   linkedin and gitlab are spec OIDC presets; github, discord, facebook and
--   apple need a provider adapter.
-- * oidc_idp_connections.show_on_login: whether the connection gets a
--   "Continue with ..." button on the login page. Off by default, so nothing
--   appears on the login page until an admin opts the connection in.
-- * oidc_idp_connections.github_allowed_orgs: GitHub organizations a user
--   must belong to. NULL or empty means no restriction.
-- * oidc_idp_connections.apple_team_id / apple_key_id /
--   apple_private_key_enc: Apple's client secret is a JWT signed with the
--   admin's .p8 key. The key is stored encrypted like client_secret_enc.
-- * oidc_idp_user_links.last_used_at: a user may hold several links, and
--   email-first sign-in routes to the most recently used one. The existing
--   user_id index serves that lookup (a user holds a handful of links).

SET LOCAL ROLE appowner;

ALTER TABLE public.oidc_idp_connections
    DROP CONSTRAINT oidc_idp_connections_provider_type_check;

ALTER TABLE public.oidc_idp_connections
    ADD CONSTRAINT oidc_idp_connections_provider_type_check
    CHECK ((provider_type = ANY (ARRAY[
        'generic'::text, 'google'::text, 'entra'::text,
        'microsoft'::text, 'linkedin'::text, 'gitlab'::text,
        'github'::text, 'discord'::text, 'facebook'::text, 'apple'::text
    ])));

ALTER TABLE public.oidc_idp_connections
    ADD COLUMN show_on_login boolean DEFAULT false NOT NULL,
    ADD COLUMN github_allowed_orgs text[],
    ADD COLUMN apple_team_id text,
    ADD COLUMN apple_key_id text,
    ADD COLUMN apple_private_key_enc text;

ALTER TABLE public.oidc_idp_connections
    ADD CONSTRAINT chk_oidc_connection_github_allowed_orgs_count
    CHECK ((github_allowed_orgs IS NULL) OR (cardinality(github_allowed_orgs) <= 100)),
    ADD CONSTRAINT chk_oidc_connection_apple_team_id_length
    CHECK ((apple_team_id IS NULL) OR (length(apple_team_id) <= 50)),
    ADD CONSTRAINT chk_oidc_connection_apple_key_id_length
    CHECK ((apple_key_id IS NULL) OR (length(apple_key_id) <= 50)),
    ADD CONSTRAINT chk_oidc_connection_apple_private_key_enc_length
    CHECK ((apple_private_key_enc IS NULL) OR (length(apple_private_key_enc) <= 8192));

ALTER TABLE public.oidc_idp_user_links
    ADD COLUMN last_used_at timestamp with time zone;
