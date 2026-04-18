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
    "account_recovery_requested": "Account recovery email requested",
    "login_failed": "Login attempt failed",
    "password_set": "Password set or changed",
    "password_changed": "User changed their password",
    "password_reset_forced": "Admin forced password reset for user",
    "password_reset_completed": "User completed forced password reset",
    "password_reset_requested": "Self-service password reset requested",
    "password_self_reset_completed": "User completed self-service password reset",
    "password_breach_detected": "Password found in breach database by HIBP monitor",
    "password_policy_compliance_enforced": "Users flagged for reset after policy tightened",
    "oauth2_user_tokens_revoked": "OAuth2 tokens revoked for user",
    "user_signed_in": "User signed in successfully",
    "user_signed_in_saml": "User signed in via SAML SSO",
    "user_signed_out": "User signed out",
    # User Management
    "user_created": "User account created",
    "user_created_jit": "User created via SAML just-in-time provisioning",
    "user_updated": "User account updated",
    "user_profile_updated": "User profile updated",
    "user_attributes_synced": "User attributes synced from upstream IdP assertion",
    "user_deleted": "User account deleted",
    "user_inactivated": "User account deactivated",
    "user_reactivated": "User account reactivated",
    "user_auto_inactivated": "User automatically inactivated due to inactivity",
    "user_anonymized": "User data anonymized for privacy",
    "user_reactivated_cli": "User account reactivated via CLI",
    "super_admin_self_reactivated": "Super admin self-reactivated their account",
    "invitation_resent": "Invitation email resent to user who has not completed onboarding",
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
    "passkey_registered": "Passkey credential registered",
    "passkey_deleted": "Passkey credential deleted",
    "passkey_renamed": "Passkey credential renamed",
    "passkey_auth_success": "User signed in with passkey",
    "passkey_auth_failure": "Passkey sign-in attempt failed",
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
    "saml_idp_verbose_logging_enabled": "Verbose assertion logging enabled for IdP",
    "saml_idp_verbose_logging_disabled": "Verbose assertion logging disabled for IdP",
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
    "password_policy_updated": "Password strength policy settings changed",
    "tenant_settings_updated": "Tenant settings updated",
    "group_assertion_scope_updated": "Group assertion scope setting changed",
    "tenant_auth_policy_updated": "Tenant authentication strength policy changed",
    "user_enhanced_auth_enrolled": (
        "User enrolled in a strong authentication method under enhanced policy"
    ),
    "domain_group_link_created": "Group linked to privileged domain for auto-assignment",
    "domain_group_link_deleted": "Group unlinked from privileged domain",
    "domain_group_auto_assigned": "User auto-assigned to groups based on email domain",
    # Background Tasks & Exports
    "export_task_created": "Background export job created",
    "export_downloaded": "Export file downloaded",
    "jobs_deleted": "Background jobs cleaned up",
    "bulk_secondary_emails_task_created": (
        "Background job created to add secondary emails in bulk"
    ),
    "bulk_primary_email_preview_task_created": (
        "Background job created to preview bulk primary email changes"
    ),
    "bulk_primary_email_apply_task_created": (
        "Background job created to apply bulk primary email changes"
    ),
    "user_export_task_created": "Background job created to export user audit data",
    "bulk_inactivate_task_created": ("Background job created to inactivate users in bulk"),
    "bulk_reactivate_task_created": ("Background job created to reactivate users in bulk"),
    "bulk_group_assignment_task_created": (
        "Background job created to assign users to a group in bulk"
    ),
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
    "sp_encryption_algorithm_updated": (
        "Assertion encryption algorithm changed for downstream service provider"
    ),
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
    "assertion_preview_viewed": (
        "Super admin previewed assertion attributes for user and service provider"
    ),
    # SAML Verbose Assertion Logging
    "saml_assertion_received": "SAML assertion received from upstream IdP (verbose mode)",
    "saml_assertion_failed": "SAML assertion failed from upstream IdP (verbose mode)",
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
    "sp_logo_uploaded": "Custom logo uploaded for service provider",
    "sp_logo_removed": "Custom logo removed from service provider",
    # IdP Group Integration
    "idp_group_created": "Group auto-created for identity provider",
    "idp_group_discovered": "New group discovered from identity provider",
    "idp_group_invalidated": "IdP group marked invalid after IdP deletion",
    "idp_group_member_added": "User added to IdP group during authentication",
    "idp_group_member_removed": "User removed from IdP group during authentication",
    "idp_group_relationship_created": "IdP group wired as child of umbrella group",
}


# Valid visibility tiers, ordered from most to least security-relevant
VALID_TIERS = ("security", "admin", "operational", "system")

# Default tiers shown in the audit log UI
DEFAULT_TIERS = ("security", "admin")

# Visibility tier for each event type.
# security: authentication, authorization, credential changes, account lifecycle
# admin: configuration changes made by admins (IdP/SP setup, settings, groups, emails, branding)
# operational: high-volume automated activity useful for debugging (SSO, sync, auto-rotation)
# system: internal bookkeeping with no audit value (task creation, job cleanup, setup steps)
EVENT_TYPE_TIERS: dict[str, str] = {
    # Security tier
    "account_recovery_requested": "security",
    "login_failed": "security",
    "password_set": "security",
    "password_changed": "security",
    "password_reset_forced": "security",
    "password_reset_completed": "security",
    "password_reset_requested": "security",
    "password_self_reset_completed": "security",
    "password_breach_detected": "security",
    "password_policy_compliance_enforced": "security",
    "user_signed_in": "security",
    "user_signed_in_saml": "security",
    "user_signed_out": "security",
    "user_created": "security",
    "user_created_jit": "security",
    "user_deleted": "security",
    "user_inactivated": "security",
    "user_reactivated": "security",
    "user_auto_inactivated": "security",
    "user_anonymized": "security",
    "user_reactivated_cli": "security",
    "super_admin_self_reactivated": "security",
    "mfa_totp_enabled": "security",
    "mfa_email_enabled": "security",
    "mfa_downgraded_to_email": "security",
    "mfa_disabled": "security",
    "mfa_backup_codes_regenerated": "security",
    "mfa_reset_by_admin": "security",
    "passkey_registered": "security",
    "passkey_deleted": "security",
    "passkey_renamed": "security",
    "passkey_auth_success": "security",
    "passkey_auth_failure": "security",
    "user_enhanced_auth_enrolled": "security",
    "oauth2_user_tokens_revoked": "security",
    "oauth2_client_secret_regenerated": "security",
    "reactivation_requested": "security",
    "reactivation_approved": "security",
    "reactivation_denied": "security",
    # Admin tier
    "user_updated": "admin",
    "user_profile_updated": "admin",
    "user_attributes_synced": "operational",
    "invitation_resent": "admin",
    "email_added": "admin",
    "email_deleted": "admin",
    "email_verified": "admin",
    "primary_email_changed": "admin",
    "group_created": "admin",
    "group_updated": "admin",
    "group_deleted": "admin",
    "group_member_added": "admin",
    "group_member_removed": "admin",
    "group_members_bulk_added": "admin",
    "group_members_bulk_removed": "admin",
    "user_groups_bulk_added": "admin",
    "group_relationship_created": "admin",
    "group_relationship_deleted": "admin",
    "saml_idp_created": "admin",
    "saml_idp_updated": "admin",
    "saml_idp_deleted": "admin",
    "saml_idp_enabled": "admin",
    "saml_idp_disabled": "admin",
    "saml_idp_set_default": "admin",
    "saml_idp_metadata_refreshed": "admin",
    "saml_idp_verbose_logging_enabled": "admin",
    "saml_idp_verbose_logging_disabled": "admin",
    "saml_idp_trust_established": "admin",
    "saml_idp_sp_certificate_created": "admin",
    "saml_idp_sp_certificate_rotated": "admin",
    "saml_sp_certificate_created": "admin",
    "saml_sp_certificate_rotated": "admin",
    "saml_domain_bound": "admin",
    "saml_domain_unbound": "admin",
    "saml_domain_rebound": "admin",
    "user_saml_idp_assigned": "admin",
    "service_provider_created": "admin",
    "service_provider_updated": "admin",
    "service_provider_deleted": "admin",
    "service_provider_enabled": "admin",
    "service_provider_disabled": "admin",
    "service_provider_trust_established": "admin",
    "sp_nameid_format_updated": "admin",
    "sp_encryption_algorithm_updated": "admin",
    "sp_access_mode_updated": "admin",
    "sp_metadata_refreshed": "admin",
    "sp_metadata_reimported": "admin",
    "sp_signing_certificate_created": "admin",
    "sp_signing_certificate_rotated": "admin",
    "sp_group_assigned": "admin",
    "sp_group_unassigned": "admin",
    "sp_groups_bulk_assigned": "admin",
    "oauth2_client_created": "admin",
    "oauth2_client_updated": "admin",
    "oauth2_client_deleted": "admin",
    "oauth2_client_role_changed": "admin",
    "oauth2_client_deactivated": "admin",
    "oauth2_client_reactivated": "admin",
    "privileged_domain_added": "admin",
    "privileged_domain_deleted": "admin",
    "tenant_certificate_lifetime_updated": "admin",
    "tenant_certificate_rotation_window_updated": "admin",
    "password_policy_updated": "admin",
    "tenant_settings_updated": "admin",
    "group_assertion_scope_updated": "admin",
    "tenant_auth_policy_updated": "admin",
    "domain_group_link_created": "admin",
    "domain_group_link_deleted": "admin",
    "branding_logo_uploaded": "admin",
    "branding_logo_deleted": "admin",
    "branding_settings_updated": "admin",
    "group_logo_uploaded": "admin",
    "group_logo_removed": "admin",
    "group_avatar_style_updated": "admin",
    "sp_logo_uploaded": "admin",
    "sp_logo_removed": "admin",
    "sso_consent_denied": "admin",
    "assertion_preview_viewed": "admin",
    # Operational tier
    "sso_assertion_issued": "operational",
    "slo_sp_initiated": "operational",
    "slo_idp_propagated": "operational",
    "idp_group_created": "operational",
    "idp_group_discovered": "operational",
    "idp_group_invalidated": "operational",
    "idp_group_member_added": "operational",
    "idp_group_member_removed": "operational",
    "idp_group_relationship_created": "operational",
    "saml_assertion_received": "operational",
    "saml_assertion_failed": "security",
    "domain_group_auto_assigned": "operational",
    "saml_idp_sp_certificate_auto_rotated": "operational",
    "saml_idp_sp_certificate_cleanup_completed": "operational",
    "sp_signing_certificate_auto_rotated": "operational",
    "sp_signing_certificate_cleanup_completed": "operational",
    # System tier
    "export_task_created": "system",
    "export_downloaded": "system",
    "jobs_deleted": "system",
    "bulk_secondary_emails_task_created": "system",
    "bulk_primary_email_preview_task_created": "system",
    "bulk_primary_email_apply_task_created": "system",
    "user_export_task_created": "system",
    "bulk_inactivate_task_created": "system",
    "bulk_reactivate_task_created": "system",
    "bulk_group_assignment_task_created": "system",
    "totp_setup_initiated": "system",
    # Deprecated events (system tier)
    "idp_certificate_added": "system",
    "idp_certificate_activated": "system",
    "idp_certificate_deactivated": "system",
    "idp_certificate_removed": "system",
}


def get_event_description(event_type: str) -> str | None:
    """Get the human-readable description for an event type.

    Args:
        event_type: The event type string (e.g., "user_created")

    Returns:
        The description string, or None if the event type is unknown.
    """
    return EVENT_TYPE_DESCRIPTIONS.get(event_type)


def get_event_tier(event_type: str) -> str | None:
    """Get the visibility tier for an event type.

    Args:
        event_type: The event type string (e.g., "user_created")

    Returns:
        The tier string ("security", "admin", "operational", "system"),
        or None if the event type is unknown.
    """
    return EVENT_TYPE_TIERS.get(event_type)


def get_event_types_for_tiers(tiers: list[str]) -> list[str]:
    """Get all event type strings that belong to any of the given tiers.

    Args:
        tiers: List of tier names (e.g., ["security", "admin"])

    Returns:
        List of event type strings matching those tiers.
    """
    tier_set = set(tiers)
    return [et for et, tier in EVENT_TYPE_TIERS.items() if tier in tier_set]
