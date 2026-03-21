-- Add group_assertion_scope to tenant security settings and service providers.
-- Controls which groups are included in SAML assertions: all, trunk (user's
-- topmost memberships), or access_relevant (groups granting SP access).

SET LOCAL ROLE appowner;

ALTER TABLE tenant_security_settings
    ADD COLUMN group_assertion_scope text NOT NULL DEFAULT 'access_relevant'
    CONSTRAINT tenant_security_settings_group_assertion_scope_check
    CHECK (group_assertion_scope IN ('all', 'trunk', 'access_relevant')),
    ADD CONSTRAINT chk_tenant_security_settings_group_assertion_scope_length
    CHECK (length(group_assertion_scope) <= 50);

ALTER TABLE service_providers
    ADD COLUMN group_assertion_scope text DEFAULT NULL
    CONSTRAINT service_providers_group_assertion_scope_check
    CHECK (group_assertion_scope IS NULL OR group_assertion_scope IN ('all', 'trunk', 'access_relevant'));

ALTER TABLE service_providers
    ADD CONSTRAINT chk_service_providers_group_assertion_scope_length
    CHECK (group_assertion_scope IS NULL OR length(group_assertion_scope) <= 50);
