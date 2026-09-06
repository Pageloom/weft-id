"""301 redirects from pre-restructure admin nav paths to their new homes.

The admin navigation is being restructured around concepts rather than
permissions (see ``.claude/ITERATION_nav_restructure.md``). Every page that
moves gets its own redirect handler here so old bookmarks, emailed links,
and stale documentation keep working. Each handler uses a literal-string
``RedirectResponse`` target -- ``dev/compliance_check.py``'s
``redirect-validation`` check requires the ``url`` argument to be a literal,
so this module is written out one handler per old path rather than built
from a loop over an old->new path table.

This module grows across Iterations 1-4 of the restructure as each section
moves; Iteration 5 audits it for completeness against the full old->new map.
"""

from fastapi import APIRouter
from fastapi.responses import RedirectResponse

router = APIRouter(tags=["legacy-redirects"], include_in_schema=False)


# =============================================================================
# Directory: Groups (moved from /admin/groups)
# =============================================================================


@router.get("/admin/groups")
@router.get("/admin/groups/")
def redirect_admin_groups() -> RedirectResponse:
    return RedirectResponse(url="/groups", status_code=301)


@router.get("/admin/groups/list")
def redirect_admin_groups_list() -> RedirectResponse:
    return RedirectResponse(url="/groups/list", status_code=301)


@router.get("/admin/groups/new")
def redirect_admin_groups_new() -> RedirectResponse:
    return RedirectResponse(url="/groups/new", status_code=301)


# =============================================================================
# Directory: Requests (moved from /admin/todo, renamed)
# =============================================================================


@router.get("/admin/todo")
@router.get("/admin/todo/")
def redirect_admin_todo() -> RedirectResponse:
    return RedirectResponse(url="/directory/requests", status_code=301)


@router.get("/admin/todo/reactivation")
def redirect_admin_todo_reactivation() -> RedirectResponse:
    return RedirectResponse(url="/directory/requests/reactivation", status_code=301)


@router.get("/admin/todo/reactivation/history")
def redirect_admin_todo_reactivation_history() -> RedirectResponse:
    return RedirectResponse(url="/directory/requests/reactivation/history", status_code=301)


@router.get("/admin/todo/user-attributes")
def redirect_admin_todo_user_attributes() -> RedirectResponse:
    return RedirectResponse(url="/directory/requests/user-attributes", status_code=301)


# =============================================================================
# Directory: Attributes (moved from /admin/settings/user-attributes)
# =============================================================================


@router.get("/admin/settings/user-attributes")
def redirect_admin_settings_user_attributes() -> RedirectResponse:
    return RedirectResponse(url="/directory/attributes", status_code=301)


# =============================================================================
# Directory: Exports (moved from /admin/audit/user-export)
# =============================================================================


@router.get("/admin/audit/user-export")
def redirect_admin_audit_user_export() -> RedirectResponse:
    return RedirectResponse(url="/directory/exports", status_code=301)


# =============================================================================
# Identity Providers: SAML (moved from /admin/settings/identity-providers)
#
# Per-instance detail-page bookmarks (e.g. a specific IdP's certificate tab)
# are not individually redirected, matching the precedent set for Groups'
# per-group detail pages in Iteration 1 -- only the static index/list/new
# paths get a redirect.
# =============================================================================


@router.get("/admin/settings/identity-providers")
@router.get("/admin/settings/identity-providers/")
def redirect_admin_settings_identity_providers() -> RedirectResponse:
    return RedirectResponse(url="/identity-providers/saml", status_code=301)


@router.get("/admin/settings/identity-providers/new")
def redirect_admin_settings_identity_providers_new() -> RedirectResponse:
    return RedirectResponse(url="/identity-providers/saml/new", status_code=301)


# =============================================================================
# Identity Providers: OIDC (moved from /admin/settings/oidc-identity-providers)
# =============================================================================


@router.get("/admin/settings/oidc-identity-providers")
@router.get("/admin/settings/oidc-identity-providers/")
def redirect_admin_settings_oidc_identity_providers() -> RedirectResponse:
    return RedirectResponse(url="/identity-providers/oidc", status_code=301)


@router.get("/admin/settings/oidc-identity-providers/new")
def redirect_admin_settings_oidc_identity_providers_new() -> RedirectResponse:
    return RedirectResponse(url="/identity-providers/oidc/new", status_code=301)


# =============================================================================
# Identity Providers: Domain Routing (moved from
# /admin/settings/privileged-domains, renamed)
# =============================================================================


@router.get("/admin/settings/privileged-domains")
def redirect_admin_settings_privileged_domains() -> RedirectResponse:
    return RedirectResponse(url="/identity-providers/domain-routing", status_code=301)


# =============================================================================
# Applications: SAML (moved from /admin/settings/service-providers)
#
# Per-instance detail-page bookmarks are not individually redirected, matching
# the precedent set for Groups' and Identity Providers' per-instance detail
# pages -- only the static index/new paths get a redirect.
# =============================================================================


@router.get("/admin/settings/service-providers")
@router.get("/admin/settings/service-providers/")
def redirect_admin_settings_service_providers() -> RedirectResponse:
    return RedirectResponse(url="/applications/saml", status_code=301)


@router.get("/admin/settings/service-providers/new")
def redirect_admin_settings_service_providers_new() -> RedirectResponse:
    return RedirectResponse(url="/applications/saml/new", status_code=301)


# =============================================================================
# Applications: OAuth2 / OIDC (moved from /admin/integrations/apps)
# =============================================================================


@router.get("/admin/integrations/apps")
def redirect_admin_integrations_apps() -> RedirectResponse:
    return RedirectResponse(url="/applications/oauth", status_code=301)


# =============================================================================
# Applications: Forward Auth (moved from /admin/settings/protected-domains
# and /admin/settings/proxy-apps, merged as Domains | Apps tabs)
# =============================================================================


@router.get("/admin/settings/protected-domains")
def redirect_admin_settings_protected_domains() -> RedirectResponse:
    return RedirectResponse(url="/applications/forward-auth/domains", status_code=301)


@router.get("/admin/settings/proxy-apps")
def redirect_admin_settings_proxy_apps() -> RedirectResponse:
    return RedirectResponse(url="/applications/forward-auth/apps", status_code=301)


# =============================================================================
# Applications: Service Accounts (moved from /admin/integrations/b2b, renamed)
# =============================================================================


@router.get("/admin/integrations/b2b")
def redirect_admin_integrations_b2b() -> RedirectResponse:
    return RedirectResponse(url="/applications/service-accounts", status_code=301)


# =============================================================================
# Applications: bare /admin/integrations container (removed as a concept)
# =============================================================================


@router.get("/admin/integrations")
@router.get("/admin/integrations/")
def redirect_admin_integrations() -> RedirectResponse:
    return RedirectResponse(url="/applications", status_code=301)


# =============================================================================
# Security (promoted to top-level from /admin/settings/security)
# =============================================================================


@router.get("/admin/settings/security")
def redirect_admin_settings_security() -> RedirectResponse:
    return RedirectResponse(url="/security", status_code=301)


@router.get("/admin/settings/security/sessions")
def redirect_admin_settings_security_sessions() -> RedirectResponse:
    return RedirectResponse(url="/security/sessions", status_code=301)


@router.get("/admin/settings/security/certificates")
def redirect_admin_settings_security_certificates() -> RedirectResponse:
    return RedirectResponse(url="/security/certificates", status_code=301)


@router.get("/admin/settings/security/passwords")
def redirect_admin_settings_security_passwords() -> RedirectResponse:
    return RedirectResponse(url="/security/passwords", status_code=301)


@router.get("/admin/settings/security/permissions")
def redirect_admin_settings_security_permissions() -> RedirectResponse:
    return RedirectResponse(url="/security/permissions", status_code=301)


@router.get("/admin/settings/security/authentication")
def redirect_admin_settings_security_authentication() -> RedirectResponse:
    return RedirectResponse(url="/security/authentication", status_code=301)


# =============================================================================
# Audit (promoted to top-level from /admin/audit)
#
# The per-instance dynamic detail routes (event log entry, SAML debug entry)
# are not individually redirected, matching the precedent set for Groups',
# Identity Providers', and Applications' per-instance detail pages -- only
# the static index/list paths get a redirect.
# =============================================================================


@router.get("/admin/audit")
@router.get("/admin/audit/")
def redirect_admin_audit() -> RedirectResponse:
    return RedirectResponse(url="/audit", status_code=301)


@router.get("/admin/audit/events")
def redirect_admin_audit_events() -> RedirectResponse:
    return RedirectResponse(url="/audit/events", status_code=301)


@router.get("/admin/audit/saml-debug")
def redirect_admin_audit_saml_debug() -> RedirectResponse:
    return RedirectResponse(url="/audit/saml-debug", status_code=301)


# =============================================================================
# Settings (narrowed to Branding + About, promoted to top-level from
# /admin/settings)
# =============================================================================


@router.get("/admin/settings")
@router.get("/admin/settings/")
def redirect_admin_settings() -> RedirectResponse:
    return RedirectResponse(url="/settings", status_code=301)


@router.get("/admin/settings/branding")
def redirect_admin_settings_branding() -> RedirectResponse:
    return RedirectResponse(url="/settings/branding", status_code=301)


@router.get("/admin/settings/branding/global")
def redirect_admin_settings_branding_global() -> RedirectResponse:
    return RedirectResponse(url="/settings/branding/global", status_code=301)


@router.get("/admin/settings/branding/groups")
def redirect_admin_settings_branding_groups() -> RedirectResponse:
    return RedirectResponse(url="/settings/branding/groups", status_code=301)


@router.get("/admin/settings/about")
def redirect_admin_settings_about() -> RedirectResponse:
    return RedirectResponse(url="/settings/about", status_code=301)


# =============================================================================
# /admin itself: the top-level wrapper is retired as a concept. Bare /admin
# always redirects to /dashboard regardless of role -- unlike the section
# index redirects above (which are role-dependent and use safe_redirect()),
# this target is fixed, so a literal RedirectResponse is correct here.
# =============================================================================


@router.get("/admin")
@router.get("/admin/")
def redirect_admin() -> RedirectResponse:
    return RedirectResponse(url="/dashboard", status_code=301)
