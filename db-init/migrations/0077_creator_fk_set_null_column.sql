-- migration-safety: ignore (DROP NOT NULL is catalog-only; each foreign key is
-- re-created NOT VALID and validated separately, so no long lock is held, and
-- every existing row already satisfies it because the old constraint did.)
--
-- Deleting a user failed when that user had created (or last updated) one of
-- these rows. Each foreign key spans (created_by, tenant_id), and a bare
-- ON DELETE SET NULL nulls both referencing columns: tenant_id is NOT NULL,
-- and most of these created_by columns were NOT NULL too. Null only the
-- creator column, and let it be NULL. Who created the row stays in the audit
-- log. Migration 0070 made the same change for oauth2_clients.

SET LOCAL ROLE appowner;

ALTER TABLE public.tenant_privileged_domains ALTER COLUMN created_by DROP NOT NULL;
ALTER TABLE public.saml_identity_providers ALTER COLUMN created_by DROP NOT NULL;
ALTER TABLE public.saml_idp_domain_bindings ALTER COLUMN created_by DROP NOT NULL;
ALTER TABLE public.saml_sp_certificates ALTER COLUMN created_by DROP NOT NULL;
ALTER TABLE public.service_providers ALTER COLUMN created_by DROP NOT NULL;
ALTER TABLE public.domain_group_links ALTER COLUMN created_by DROP NOT NULL;
ALTER TABLE public.oidc_idp_connections ALTER COLUMN created_by DROP NOT NULL;
ALTER TABLE public.oidc_idp_domain_bindings ALTER COLUMN created_by DROP NOT NULL;

ALTER TABLE public.tenant_privileged_domains DROP CONSTRAINT fk_created_by_user;
ALTER TABLE public.tenant_privileged_domains
    ADD CONSTRAINT fk_created_by_user FOREIGN KEY (created_by, tenant_id)
        REFERENCES public.users(id, tenant_id) ON DELETE SET NULL (created_by) NOT VALID;
ALTER TABLE public.tenant_privileged_domains VALIDATE CONSTRAINT fk_created_by_user;

ALTER TABLE public.tenant_security_settings DROP CONSTRAINT fk_updated_by_user;
ALTER TABLE public.tenant_security_settings
    ADD CONSTRAINT fk_updated_by_user FOREIGN KEY (updated_by, tenant_id)
        REFERENCES public.users(id, tenant_id) ON DELETE SET NULL (updated_by) NOT VALID;
ALTER TABLE public.tenant_security_settings VALIDATE CONSTRAINT fk_updated_by_user;

ALTER TABLE public.saml_identity_providers DROP CONSTRAINT fk_idp_created_by_user;
ALTER TABLE public.saml_identity_providers
    ADD CONSTRAINT fk_idp_created_by_user FOREIGN KEY (created_by, tenant_id)
        REFERENCES public.users(id, tenant_id) ON DELETE SET NULL (created_by) NOT VALID;
ALTER TABLE public.saml_identity_providers VALIDATE CONSTRAINT fk_idp_created_by_user;

ALTER TABLE public.saml_idp_domain_bindings DROP CONSTRAINT fk_saml_domain_binding_created_by;
ALTER TABLE public.saml_idp_domain_bindings
    ADD CONSTRAINT fk_saml_domain_binding_created_by FOREIGN KEY (created_by, tenant_id)
        REFERENCES public.users(id, tenant_id) ON DELETE SET NULL (created_by) NOT VALID;
ALTER TABLE public.saml_idp_domain_bindings VALIDATE CONSTRAINT fk_saml_domain_binding_created_by;

ALTER TABLE public.saml_sp_certificates DROP CONSTRAINT fk_sp_cert_created_by_user;
ALTER TABLE public.saml_sp_certificates
    ADD CONSTRAINT fk_sp_cert_created_by_user FOREIGN KEY (created_by, tenant_id)
        REFERENCES public.users(id, tenant_id) ON DELETE SET NULL (created_by) NOT VALID;
ALTER TABLE public.saml_sp_certificates VALIDATE CONSTRAINT fk_sp_cert_created_by_user;

ALTER TABLE public.service_providers DROP CONSTRAINT fk_sp_created_by;
ALTER TABLE public.service_providers
    ADD CONSTRAINT fk_sp_created_by FOREIGN KEY (created_by, tenant_id)
        REFERENCES public.users(id, tenant_id) ON DELETE SET NULL (created_by) NOT VALID;
ALTER TABLE public.service_providers VALIDATE CONSTRAINT fk_sp_created_by;

ALTER TABLE public.domain_group_links DROP CONSTRAINT fk_domain_group_links_created_by;
ALTER TABLE public.domain_group_links
    ADD CONSTRAINT fk_domain_group_links_created_by FOREIGN KEY (created_by, tenant_id)
        REFERENCES public.users(id, tenant_id) ON DELETE SET NULL (created_by) NOT VALID;
ALTER TABLE public.domain_group_links VALIDATE CONSTRAINT fk_domain_group_links_created_by;

ALTER TABLE public.oidc_idp_connections DROP CONSTRAINT fk_oidc_connection_created_by_user;
ALTER TABLE public.oidc_idp_connections
    ADD CONSTRAINT fk_oidc_connection_created_by_user FOREIGN KEY (created_by, tenant_id)
        REFERENCES public.users(id, tenant_id) ON DELETE SET NULL (created_by) NOT VALID;
ALTER TABLE public.oidc_idp_connections VALIDATE CONSTRAINT fk_oidc_connection_created_by_user;

ALTER TABLE public.oidc_idp_domain_bindings DROP CONSTRAINT fk_oidc_domain_binding_created_by;
ALTER TABLE public.oidc_idp_domain_bindings
    ADD CONSTRAINT fk_oidc_domain_binding_created_by FOREIGN KEY (created_by, tenant_id)
        REFERENCES public.users(id, tenant_id) ON DELETE SET NULL (created_by) NOT VALID;
ALTER TABLE public.oidc_idp_domain_bindings VALIDATE CONSTRAINT fk_oidc_domain_binding_created_by;
