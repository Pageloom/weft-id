"""Event type definitions with human-readable descriptions.

This module is the single source of truth for all event types in the system.
Every event logged via log_event() must have an entry in EVENT_TYPE_DESCRIPTIONS.

To add a new event type:
1. Add the event_type -> description mapping to EVENT_TYPE_DESCRIPTIONS
2. Add the event_type to event_types.lock (run tests to see the diff)

Event types must never be deleted or renamed. Deprecated types should remain
in the map with a description indicating they are deprecated.
"""

# All event types with their human-readable descriptions
EVENT_TYPE_DESCRIPTIONS: dict[str, str] = {
    # Authentication & Login
    "login_failed": "Login attempt failed",
    "password_set": "Password set or changed",
    "user_signed_in": "User signed in successfully",
    "user_signed_in_saml": "User signed in via SAML SSO",
    "user_signed_out": "User signed out",
    # Authorization
    "authorization_denied": "Access denied due to insufficient permissions",
    # User Management
    "user_created": "User account created",
    "user_created_jit": "User created via SAML just-in-time provisioning",
    "user_updated": "User account updated",
    "user_profile_updated": "User profile updated",
    "user_deleted": "User account deleted",
    "user_inactivated": "User account deactivated",
    "user_reactivated": "User account reactivated",
    "user_auto_inactivated": "User automatically inactivated due to inactivity",
    "user_anonymized": "User data anonymized for privacy",
    "super_admin_self_reactivated": "Super admin self-reactivated their account",
    # Email Management
    "email_added": "Email address added to user account",
    "email_deleted": "Email address removed from user account",
    "email_verified": "Email address verified via confirmation link",
    "primary_email_changed": "Primary email address changed",
    # MFA (Multi-Factor Authentication)
    "totp_setup_initiated": "TOTP authenticator setup started",
    "mfa_totp_enabled": "TOTP authenticator MFA enabled",
    "mfa_email_enabled": "Email-based MFA enabled",
    "mfa_downgraded_to_email": "MFA downgraded from TOTP to email-only",
    "mfa_disabled": "Multi-factor authentication disabled",
    "mfa_backup_codes_regenerated": "MFA backup codes regenerated",
    "mfa_reset_by_admin": "MFA reset by administrator",
    # Reactivation Requests
    "reactivation_requested": "Account reactivation requested by user",
    "reactivation_approved": "Account reactivation request approved",
    "reactivation_denied": "Account reactivation request denied",
    # SAML Configuration
    "saml_sp_certificate_created": "SAML service provider certificate created",
    "saml_sp_certificate_rotated": "SAML service provider certificate rotated",
    "saml_idp_created": "SAML identity provider configured",
    "saml_idp_updated": "SAML identity provider configuration updated",
    "saml_idp_deleted": "SAML identity provider removed",
    "saml_idp_enabled": "SAML identity provider enabled",
    "saml_idp_disabled": "SAML identity provider disabled",
    "saml_idp_set_default": "SAML identity provider set as default",
    "saml_idp_metadata_refreshed": "SAML IdP metadata refreshed from URL",
    "idp_certificate_added": "Deprecated: IdP certificate added manually",
    "idp_certificate_activated": "Deprecated: IdP certificate activation",
    "idp_certificate_deactivated": "Deprecated: IdP certificate deactivation",
    "idp_certificate_removed": "Deprecated: IdP certificate removed manually",
    "saml_idp_sp_certificate_auto_rotated": (
        "Per-IdP SP certificate automatically rotated before expiry"
    ),
    "saml_idp_sp_certificate_cleanup_completed": (
        "Previous per-IdP SP certificate removed after grace period"
    ),
    "saml_idp_sp_certificate_created": "Per-IdP SP certificate generated",
    "saml_idp_sp_certificate_rotated": "Per-IdP SP certificate rotated",
    "saml_idp_trust_established": "Trust established with upstream identity provider",
    "saml_domain_bound": "Email domain bound to SAML IdP",
    "saml_domain_unbound": "Email domain unbound from SAML IdP",
    "saml_domain_rebound": "Email domain rebound to different SAML IdP",
    "user_saml_idp_assigned": "User assigned to SAML identity provider",
    # OAuth2
    "oauth2_client_created": "OAuth2 client application registered",
    "oauth2_client_updated": "OAuth2 client application updated",
    "oauth2_client_deleted": "OAuth2 client application removed",
    "oauth2_client_secret_regenerated": "OAuth2 client secret regenerated",
    "oauth2_client_role_changed": "OAuth2 B2B client service role changed",
    "oauth2_client_deactivated": "OAuth2 client application deactivated",
    "oauth2_client_reactivated": "OAuth2 client application reactivated",
    # Settings & Configuration
    "privileged_domain_added": "Privileged email domain added",
    "privileged_domain_deleted": "Privileged email domain removed",
    "tenant_certificate_lifetime_updated": "Certificate lifetime setting changed",
    "tenant_certificate_rotation_window_updated": "Certificate rotation window setting changed",
    "tenant_settings_updated": "Tenant settings updated",
    # Background Tasks & Exports
    "export_task_created": "Background export job created",
    "export_downloaded": "Export file downloaded",
    "jobs_deleted": "Background jobs cleaned up",
    # Groups & Group Management
    "group_created": "Group created",
    "group_updated": "Group updated",
    "group_deleted": "Group deleted",
    "group_member_added": "User added to group",
    "group_member_removed": "User removed from group",
    "group_members_bulk_added": "Multiple users added to group in bulk",
    "group_members_bulk_removed": "Multiple users removed from group in bulk",
    "user_groups_bulk_added": "User added to multiple groups in bulk",
    "group_relationship_created": "Group hierarchy relationship created",
    "group_relationship_deleted": "Group hierarchy relationship removed",
    # SAML IdP / Service Providers
    "service_provider_created": "Downstream service provider registered",
    "service_provider_updated": "Downstream service provider configuration updated",
    "sp_nameid_format_updated": "NameID format changed for downstream service provider",
    "service_provider_enabled": "Downstream service provider enabled",
    "service_provider_disabled": "Downstream service provider disabled",
    "service_provider_deleted": "Downstream service provider removed",
    "sp_access_mode_updated": "Service provider access mode changed",
    "service_provider_trust_established": "Trust established with downstream service provider",
    "sp_metadata_refreshed": "Service provider metadata refreshed from URL",
    "sp_metadata_reimported": "Service provider metadata re-imported from XML",
    "sp_signing_certificate_auto_rotated": (
        "Per-SP signing certificate automatically rotated before expiry"
    ),
    "sp_signing_certificate_cleanup_completed": (
        "Previous SP signing certificate removed after grace period"
    ),
    "sp_signing_certificate_created": "Per-SP signing certificate generated",
    "sp_signing_certificate_rotated": "Per-SP signing certificate rotated",
    # SAML IdP / SP Group Assignments
    "sp_group_assigned": "Group assigned to downstream service provider",
    "sp_group_unassigned": "Group unassigned from downstream service provider",
    "sp_groups_bulk_assigned": "Multiple groups assigned to downstream service provider",
    # SAML IdP / SSO
    "sso_assertion_issued": "SAML SSO assertion issued to downstream service provider",
    "sso_consent_denied": "User denied SSO consent for downstream service provider",
    # SAML IdP / SLO
    "slo_sp_initiated": "SP-initiated single logout processed",
    "slo_idp_propagated": "Logout propagated to downstream service providers",
    # Branding
    "branding_logo_uploaded": "Custom logo uploaded for tenant branding",
    "branding_logo_deleted": "Custom logo removed from tenant branding",
    "branding_settings_updated": "Tenant branding display settings updated",
    "group_logo_uploaded": "Custom logo uploaded for group",
    "group_logo_removed": "Custom logo removed from group",
    "group_avatar_style_updated": "Tenant group avatar style setting updated",
    # IdP Group Integration
    "idp_group_created": "Group auto-created for identity provider",
    "idp_group_discovered": "New group discovered from identity provider",
    "idp_group_invalidated": "IdP group marked invalid after IdP deletion",
    "idp_group_member_added": "User added to IdP group during authentication",
    "idp_group_member_removed": "User removed from IdP group during authentication",
    "idp_group_relationship_created": "IdP group wired as child of umbrella group",
}


def get_event_description(event_type: str) -> str | None:
    """Get the human-readable description for an event type.

    Args:
        event_type: The event type string (e.g., "user_created")

    Returns:
        The description string, or None if the event type is unknown.
    """
    return EVENT_TYPE_DESCRIPTIONS.get(event_type)
