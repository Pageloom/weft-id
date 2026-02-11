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
    "user_groups_bulk_added": "User added to multiple groups in bulk",
    "group_relationship_created": "Group hierarchy relationship created",
    "group_relationship_deleted": "Group hierarchy relationship removed",
    # SAML IdP / Service Providers
    "service_provider_created": "Downstream service provider registered",
    "service_provider_deleted": "Downstream service provider removed",
    # SAML IdP / SSO
    "sso_assertion_issued": "SAML SSO assertion issued to downstream service provider",
    "sso_consent_denied": "User denied SSO consent for downstream service provider",
    # IdP Group Integration
    "idp_group_created": "Group auto-created for identity provider",
    "idp_group_discovered": "New group discovered from identity provider",
    "idp_group_invalidated": "IdP group marked invalid after IdP deletion",
    "idp_group_member_added": "User added to IdP group during authentication",
    "idp_group_member_removed": "User removed from IdP group during authentication",
}


def get_event_description(event_type: str) -> str | None:
    """Get the human-readable description for an event type.

    Args:
        event_type: The event type string (e.g., "user_created")

    Returns:
        The description string, or None if the event type is unknown.
    """
    return EVENT_TYPE_DESCRIPTIONS.get(event_type)
