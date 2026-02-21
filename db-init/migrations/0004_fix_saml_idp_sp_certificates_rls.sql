SET LOCAL ROLE appowner;

DROP POLICY tenant_isolation ON public.saml_idp_sp_certificates;

CREATE POLICY saml_idp_sp_certificates_tenant_isolation ON public.saml_idp_sp_certificates
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));
