"""Email sending utilities with branded headers and inline styles.

All HTML uses inline style attributes (no CSS classes or <style> blocks) for
maximum email client compatibility. The shared layout adds a branded header
(tenant logo + name) and a Pageloom footer to every email.
"""

from __future__ import annotations

import html
import logging
from typing import TYPE_CHECKING

from utils.email_backends import get_backend

if TYPE_CHECKING:
    from utils.email_branding import EmailBranding

logger = logging.getLogger(__name__)

# ruff: noqa: E501

# =============================================================================
# Inline style constants (email clients strip <style> blocks)
# =============================================================================

_S_BODY = "font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333333; margin: 0; padding: 0;"
_S_CONTAINER = "max-width: 600px; margin: 0 auto; padding: 20px;"
_S_H1 = "margin: 0 0 16px 0; font-size: 24px; font-weight: 600; color: #111827;"
_S_P = "margin: 0 0 12px 0; font-size: 16px; color: #333333;"
_S_BUTTON = "display: inline-block; background-color: #2563eb; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin: 20px 0; font-weight: 600; font-size: 16px;"
_S_CODE_BOX = "background: #f3f4f6; border: 2px solid #e5e7eb; border-radius: 8px; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 8px; margin: 20px 0; color: #111827;"
_S_INFO_BOX = "background: #f3f4f6; border-left: 4px solid #2563eb; padding: 15px; margin: 20px 0;"
_S_WARNING_BOX = (
    "background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0;"
)
_S_DANGER_BOX = (
    "background: #fef2f2; border-left: 4px solid #ef4444; padding: 15px; margin: 20px 0;"
)
_S_SUCCESS_BOX = (
    "background: #d1fae5; border-left: 4px solid #10b981; padding: 15px; margin: 20px 0;"
)
_S_LINK_FALLBACK = "word-break: break-all; color: #6b7280; font-size: 14px; margin: 0 0 12px 0;"
_S_FOOTER = "margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 13px; color: #9ca3af;"
_S_FOOTER_LINK = "color: #9ca3af; text-decoration: underline;"
_S_HEADER = "padding-bottom: 20px; margin-bottom: 20px; border-bottom: 1px solid #e5e7eb;"
_S_HEADER_TABLE = "border: 0; cellpadding: 0; cellspacing: 0;"
_S_LOGO_IMG = "height: 48px; width: auto; vertical-align: middle;"
_S_TENANT_NAME = (
    "font-size: 18px; font-weight: 600; color: #111827; padding-left: 12px; vertical-align: middle;"
)


# =============================================================================
# Shared email builders
# =============================================================================


def _get_branding(tenant_id: str | None) -> EmailBranding | None:
    """Fetch branding for the given tenant. Returns None on failure or if no tenant_id."""
    if not tenant_id:
        return None
    try:
        from utils.email_branding import get_email_branding

        return get_email_branding(tenant_id)
    except Exception:
        logger.warning("Failed to fetch email branding for tenant %s", tenant_id, exc_info=True)
        return None


def _build_header_html(branding: EmailBranding) -> str:
    """Build the branded header with logo and tenant name."""
    name = html.escape(branding["tenant_name"])
    logo_uri = branding.get("logo_data_uri")

    if logo_uri:
        return f"""<div style="{_S_HEADER}"><table style="{_S_HEADER_TABLE}"><tr><td><img src="{logo_uri}" alt="{name}" style="{_S_LOGO_IMG}"></td><td style="{_S_TENANT_NAME}">{name}</td></tr></table></div>"""
    return f"""<div style="{_S_HEADER}"><p style="{_S_TENANT_NAME} padding-left: 0;">{name}</p></div>"""


def _build_footer_html() -> str:
    """Build the shared footer with automated message notice and Pageloom attribution."""
    return f"""<div style="{_S_FOOTER}"><p style="margin: 0 0 4px 0;">Do not reply.</p><p style="margin: 0;"><a href="https://pageloom.com" style="{_S_FOOTER_LINK}">WeftID by Pageloom</a></p></div>"""


def _wrap_html(body_content: str, branding: EmailBranding | None = None) -> str:
    """Wrap email body content in the standard HTML layout with header and footer."""
    header = _build_header_html(branding) if branding else ""
    footer = _build_footer_html()
    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="{_S_BODY}">
<div style="{_S_CONTAINER}">
{header}{body_content}{footer}</div>
</body>
</html>"""


def _wrap_text(body_content: str, branding: EmailBranding | None = None) -> str:
    """Wrap email body content in the standard plain-text layout."""
    header = (
        f"{branding['tenant_name']}\n{'=' * len(branding['tenant_name'])}\n\n" if branding else ""
    )
    footer = "\n---\nDo not reply.\nWeftID by Pageloom - https://pageloom.com\n"
    return f"{header}{body_content.strip()}{footer}"


# =============================================================================
# Core send function
# =============================================================================


def send_email(to_email: str, subject: str, html_body: str, text_body: str | None = None) -> bool:
    """Send an email using the configured backend.

    Backend is selected via EMAIL_BACKEND environment variable:
    - "smtp" (default): SMTP backend
    - "resend": Resend API backend (HTTPS)
    - "sendgrid": SendGrid API backend (HTTPS)
    """
    backend = get_backend()
    return backend.send(to_email, subject, html_body, text_body)


# =============================================================================
# Email functions
# =============================================================================


def send_email_possession_code(to_email: str, code: str, *, tenant_id: str | None = None) -> bool:
    """Send email possession verification code (for login anti-enumeration)."""
    branding = _get_branding(tenant_id)
    subject = "Your sign-in code"

    text_body = _wrap_text(
        f"""
Your sign-in code is: {code}

This code will expire in 5 minutes.

Enter this code to continue signing in.

If you did not request this code, please ignore this email.
""",
        branding,
    )

    body = f"""<h1 style="{_S_H1}">Your Sign-in Code</h1>
<p style="{_S_P}">Enter this code to continue signing in:</p>
<div style="{_S_CODE_BOX}">{html.escape(code)}</div>
<p style="{_S_P}">This code will expire in <strong>5 minutes</strong>.</p>
<p style="{_S_P}">If you did not request this code, please ignore this email.</p>"""

    html_body = _wrap_html(body, branding)
    return send_email(to_email, subject, html_body, text_body)


def send_mfa_code_email(to_email: str, code: str, *, tenant_id: str | None = None) -> bool:
    """Send MFA verification code via email."""
    branding = _get_branding(tenant_id)
    subject = "Your verification code"

    text_body = _wrap_text(
        f"""
Your verification code is: {code}

This code will expire in 10 minutes.

If you did not request this code, please ignore this email.
""",
        branding,
    )

    body = f"""<h1 style="{_S_H1}">Your Verification Code</h1>
<p style="{_S_P}">Enter this code to continue signing in:</p>
<div style="{_S_CODE_BOX}">{html.escape(code)}</div>
<p style="{_S_P}">This code will expire in <strong>10 minutes</strong>.</p>
<p style="{_S_P}">If you did not request this code, please ignore this email.</p>"""

    html_body = _wrap_html(body, branding)
    return send_email(to_email, subject, html_body, text_body)


def send_email_verification(
    to_email: str, verification_url: str, *, tenant_id: str | None = None
) -> bool:
    """Send email address verification link."""
    branding = _get_branding(tenant_id)
    subject = "Verify your email address"

    text_body = _wrap_text(
        f"""
Please verify your email address by clicking the link below:

{verification_url}

If you did not add this email address to your account, please ignore this email.
""",
        branding,
    )

    url = html.escape(verification_url)
    body = f"""<h1 style="{_S_H1}">Verify Your Email Address</h1>
<p style="{_S_P}">Please verify your email address by clicking the button below:</p>
<a href="{url}" style="{_S_BUTTON}">Verify Email Address</a>
<p style="{_S_P}">Or copy and paste this link into your browser:</p>
<p style="{_S_LINK_FALLBACK}">{url}</p>
<p style="{_S_P}">If you did not add this email address to your account, please ignore this email.</p>"""

    html_body = _wrap_html(body, branding)
    return send_email(to_email, subject, html_body, text_body)


def send_secondary_email_added_notification(
    to_email: str, added_email: str, admin_name: str, *, tenant_id: str | None = None
) -> bool:
    """Send notification when an admin adds a secondary email to an account."""
    branding = _get_branding(tenant_id)
    subject = "Secondary email address added to your account"

    text_body = _wrap_text(
        f"""
A secondary email address has been added to your account by an administrator.

Added email: {added_email}
Added by: {admin_name}

This email address has been automatically verified and can be used to access your account.

If you did not expect this change or have concerns, please contact your administrator immediately.
""",
        branding,
    )

    body = f"""<h1 style="{_S_H1}">Secondary Email Address Added</h1>
<p style="{_S_P}">A secondary email address has been added to your account by an administrator.</p>
<div style="{_S_INFO_BOX}">
<p style="margin: 0 0 8px 0;"><strong>Added email:</strong> {html.escape(added_email)}</p>
<p style="margin: 0;"><strong>Added by:</strong> {html.escape(admin_name)}</p>
</div>
<p style="{_S_P}">This email address has been automatically verified and can be used to access your account.</p>
<div style="{_S_WARNING_BOX}">
<p style="margin: 0;"><strong>Security Notice:</strong> If you did not expect this change or have concerns, please contact your administrator immediately.</p>
</div>"""

    html_body = _wrap_html(body, branding)
    return send_email(to_email, subject, html_body, text_body)


def send_secondary_email_removed_notification(
    to_email: str, removed_email: str, admin_name: str, *, tenant_id: str | None = None
) -> bool:
    """Send notification when an admin removes a secondary email from an account."""
    branding = _get_branding(tenant_id)
    subject = "Secondary email address removed from your account"

    text_body = _wrap_text(
        f"""
A secondary email address has been removed from your account by an administrator.

Removed email: {removed_email}
Removed by: {admin_name}

This email address can no longer be used to access your account.

If you did not expect this change or have concerns, please contact your administrator immediately.
""",
        branding,
    )

    body = f"""<h1 style="{_S_H1}">Secondary Email Address Removed</h1>
<p style="{_S_P}">A secondary email address has been removed from your account by an administrator.</p>
<div style="{_S_INFO_BOX}">
<p style="margin: 0 0 8px 0;"><strong>Removed email:</strong> {html.escape(removed_email)}</p>
<p style="margin: 0;"><strong>Removed by:</strong> {html.escape(admin_name)}</p>
</div>
<p style="{_S_P}">This email address can no longer be used to access your account.</p>
<div style="{_S_WARNING_BOX}">
<p style="margin: 0;"><strong>Security Notice:</strong> If you did not expect this change or have concerns, please contact your administrator immediately.</p>
</div>"""

    html_body = _wrap_html(body, branding)
    return send_email(to_email, subject, html_body, text_body)


def send_primary_email_changed_notification(
    to_email: str, new_primary_email: str, admin_name: str, *, tenant_id: str | None = None
) -> bool:
    """Send notification to the old primary email when it has been changed."""
    branding = _get_branding(tenant_id)
    subject = "Your primary email address has been changed"

    text_body = _wrap_text(
        f"""
Your primary email address has been changed by an administrator.

New primary email: {new_primary_email}
Changed by: {admin_name}

Your account sign-in will now use the new primary email address.

If you did not expect this change or have concerns, please contact your administrator immediately.
""",
        branding,
    )

    body = f"""<h1 style="{_S_H1}">Primary Email Address Changed</h1>
<p style="{_S_P}">Your primary email address has been changed by an administrator.</p>
<div style="{_S_INFO_BOX}">
<p style="margin: 0 0 8px 0;"><strong>New primary email:</strong> {html.escape(new_primary_email)}</p>
<p style="margin: 0;"><strong>Changed by:</strong> {html.escape(admin_name)}</p>
</div>
<p style="{_S_P}">Your account sign-in will now use the new primary email address.</p>
<div style="{_S_WARNING_BOX}">
<p style="margin: 0;"><strong>Security Notice:</strong> If you did not expect this change or have concerns, please contact your administrator immediately.</p>
</div>"""

    html_body = _wrap_html(body, branding)
    return send_email(to_email, subject, html_body, text_body)


def send_new_user_privileged_domain_notification(
    to_email: str,
    admin_name: str,
    org_name: str,
    password_set_url: str,
    *,
    tenant_id: str | None = None,
) -> bool:
    """Send notification to a new user with a privileged domain email (auto-verified)."""
    branding = _get_branding(tenant_id)
    subject = f"Welcome to {org_name}"

    text_body = _wrap_text(
        f"""
Welcome to {org_name}!

Your account has been created by {admin_name}. Since you're using a trusted email domain, your email address has been automatically verified.

To get started, please set your password by visiting:
{password_set_url}

After setting your password, you'll be able to sign in and access your account.

If you have any questions, please contact your administrator.
""",
        branding,
    )

    url = html.escape(password_set_url)
    body = f"""<h1 style="{_S_H1}">Welcome to {html.escape(org_name)}!</h1>
<p style="{_S_P}">Your account has been created by <strong>{html.escape(admin_name)}</strong>.</p>
<p style="{_S_P}">Since you're using a trusted email domain, your email address has been automatically verified.</p>
<p style="{_S_P}">To get started, please set your password:</p>
<a href="{url}" style="{_S_BUTTON}">Set Your Password</a>
<p style="{_S_P}">Or copy and paste this link into your browser:</p>
<p style="{_S_LINK_FALLBACK}">{url}</p>
<p style="{_S_P}">After setting your password, you'll be able to sign in and access your account.</p>"""

    html_body = _wrap_html(body, branding)
    return send_email(to_email, subject, html_body, text_body)


def send_new_user_invitation(
    to_email: str,
    admin_name: str,
    org_name: str,
    verification_url: str,
    *,
    tenant_id: str | None = None,
) -> bool:
    """Send invitation to a new user with non-privileged domain (requires verification)."""
    branding = _get_branding(tenant_id)
    subject = f"You've been invited to join {org_name}"

    text_body = _wrap_text(
        f"""
You've been invited to join {org_name}!

{admin_name} has invited you to join the organization. To accept this invitation and activate your account, please verify your email address by clicking the link below:

{verification_url}

After verifying your email, you'll be able to set your password and access your account.

If you have any questions, please contact your administrator.
""",
        branding,
    )

    url = html.escape(verification_url)
    body = f"""<h1 style="{_S_H1}">You've been invited to join {html.escape(org_name)}!</h1>
<div style="{_S_INFO_BOX}">
<p style="margin: 0;"><strong>{html.escape(admin_name)}</strong> has invited you to join the organization.</p>
</div>
<p style="{_S_P}">To accept this invitation and activate your account, please verify your email address:</p>
<a href="{url}" style="{_S_BUTTON}">Verify Email &amp; Activate Account</a>
<p style="{_S_P}">Or copy and paste this link into your browser:</p>
<p style="{_S_LINK_FALLBACK}">{url}</p>
<p style="{_S_P}">After verifying your email, you'll be able to set your password and access your account.</p>"""

    html_body = _wrap_html(body, branding)
    return send_email(to_email, subject, html_body, text_body)


def send_account_reactivated_notification(
    to_email: str, login_url: str, *, tenant_id: str | None = None
) -> bool:
    """Send notification when an account has been reactivated."""
    branding = _get_branding(tenant_id)
    subject = "Your account has been reactivated"

    text_body = _wrap_text(
        f"""
Your account has been reactivated.

An administrator has approved your reactivation request. You can now sign in to your account:

{login_url}

If you have any questions, please contact your administrator.
""",
        branding,
    )

    url = html.escape(login_url)
    body = f"""<h1 style="{_S_H1}">Your Account Has Been Reactivated</h1>
<div style="{_S_SUCCESS_BOX}">
<p style="margin: 0;">An administrator has approved your reactivation request.</p>
</div>
<p style="{_S_P}">You can now sign in to your account:</p>
<a href="{url}" style="{_S_BUTTON}">Sign In</a>
<p style="{_S_P}">Or copy and paste this link into your browser:</p>
<p style="{_S_LINK_FALLBACK}">{url}</p>"""

    html_body = _wrap_html(body, branding)
    return send_email(to_email, subject, html_body, text_body)


def send_reactivation_denied_notification(to_email: str, *, tenant_id: str | None = None) -> bool:
    """Send notification when a reactivation request has been denied."""
    branding = _get_branding(tenant_id)
    subject = "Your reactivation request was denied"

    text_body = _wrap_text(
        """
Your reactivation request was denied.

An administrator has reviewed your request to reactivate your account and has decided not to approve it at this time.

If you believe this decision was made in error or have questions, please contact your administrator directly.
""",
        branding,
    )

    body = f"""<h1 style="{_S_H1}">Reactivation Request Denied</h1>
<div style="{_S_DANGER_BOX}">
<p style="margin: 0;">An administrator has reviewed your request to reactivate your account and has decided not to approve it at this time.</p>
</div>
<p style="{_S_P}">If you believe this decision was made in error or have questions, please contact your administrator directly.</p>"""

    html_body = _wrap_html(body, branding)
    return send_email(to_email, subject, html_body, text_body)


def send_reactivation_request_admin_notification(
    to_email: str,
    user_name: str,
    user_email: str,
    requests_url: str,
    *,
    tenant_id: str | None = None,
) -> bool:
    """Send notification to admin about new reactivation request."""
    branding = _get_branding(tenant_id)
    subject = "Reactivation request received"

    text_body = _wrap_text(
        f"""
A user has requested account reactivation.

User: {user_name}
Email: {user_email}

Please review this request at:
{requests_url}
""",
        branding,
    )

    url = html.escape(requests_url)
    body = f"""<h1 style="{_S_H1}">Reactivation Request Received</h1>
<div style="{_S_WARNING_BOX}">
<p style="margin: 0 0 8px 0;"><strong>User:</strong> {html.escape(user_name)}</p>
<p style="margin: 0;"><strong>Email:</strong> {html.escape(user_email)}</p>
</div>
<p style="{_S_P}">A user whose account was inactivated has requested reactivation. Please review this request:</p>
<a href="{url}" style="{_S_BUTTON}">Review Request</a>
<p style="{_S_P}">Or copy and paste this link into your browser:</p>
<p style="{_S_LINK_FALLBACK}">{url}</p>"""

    html_body = _wrap_html(body, branding)
    return send_email(to_email, subject, html_body, text_body)


def send_provisioning_invitation(
    to_email: str,
    tenant_name: str,
    verification_url: str,
    *,
    tenant_id: str | None = None,
) -> bool:
    """Send invitation to the founding super admin during tenant provisioning."""
    branding = _get_branding(tenant_id)
    subject = "Set up your organization on WeftID"

    text_body = _wrap_text(
        f"""
You have been designated as the founding administrator for {tenant_name} on WeftID.

As the super admin, you will configure the identity layer for your organization, including authentication providers, user management, and access policies.

To get started, verify your email address:

{verification_url}

After verifying, you will set your password and begin configuring your organization.
""",
        branding,
    )

    url = html.escape(verification_url)
    body = f"""<h1 style="{_S_H1}">Set up {html.escape(tenant_name)} on WeftID</h1>
<div style="{_S_INFO_BOX}">
<p style="margin: 0;">You have been designated as the founding administrator for <strong>{html.escape(tenant_name)}</strong>.</p>
</div>
<p style="{_S_P}">As the super admin, you will configure the identity layer for your organization, including authentication providers, user management, and access policies.</p>
<p style="{_S_P}">To get started, verify your email address:</p>
<a href="{url}" style="{_S_BUTTON}">Verify Email &amp; Get Started</a>
<p style="{_S_P}">Or copy and paste this link into your browser:</p>
<p style="{_S_LINK_FALLBACK}">{url}</p>
<p style="{_S_P}">After verifying, you will set your password and begin configuring your organization.</p>"""

    html_body = _wrap_html(body, branding)
    return send_email(to_email, subject, html_body, text_body)


def send_mfa_reset_notification(
    to_email: str,
    admin_name: str,
    reset_timestamp: str,
    *,
    tenant_id: str | None = None,
) -> bool:
    """Send notification when an admin resets a user's two-step verification.

    Informs the user that their two-step verification was reset, including
    which admin performed the action and when. No action links are included.
    """
    branding = _get_branding(tenant_id)
    subject = "Your two-step verification was reset"

    text_body = _wrap_text(
        f"""
Your two-step verification has been reset by an administrator.

Reset by: {admin_name}
Time: {reset_timestamp}

Your next sign-in will use email verification codes. You can re-enroll in authenticator-based two-step verification from your account settings after signing in.

If you did not expect this change, please contact your administrator.
""",
        branding,
    )

    body = f"""<h1 style="{_S_H1}">Your Two-Step Verification Was Reset</h1>
<div style="{_S_WARNING_BOX}">
<p style="margin: 0;">Your two-step verification has been reset by an administrator.</p>
</div>
<p style="{_S_P}"><strong>Reset by:</strong> {html.escape(admin_name)}</p>
<p style="{_S_P}"><strong>Time:</strong> {html.escape(reset_timestamp)}</p>
<p style="{_S_P}">Your next sign-in will use email verification codes. You can re-enroll in authenticator-based two-step verification from your account settings after signing in.</p>"""

    html_body = _wrap_html(body, branding)
    return send_email(to_email, subject, html_body, text_body)


def send_password_reset_email(
    to_email: str, reset_url: str, *, tenant_id: str | None = None
) -> bool:
    """Send a password reset link."""
    branding = _get_branding(tenant_id)
    subject = "Reset your password"

    text_body = _wrap_text(
        f"""
You requested a password reset. Click the link below to set a new password:

{reset_url}

This link will expire in 30 minutes.

If you did not request this, you can safely ignore this email. Your password will not be changed.
""",
        branding,
    )

    url = html.escape(reset_url)
    body = f"""<h1 style="{_S_H1}">Reset Your Password</h1>
<p style="{_S_P}">You requested a password reset. Click the button below to set a new password:</p>
<a href="{url}" style="{_S_BUTTON}">Reset Password</a>
<p style="{_S_P}">Or copy and paste this link into your browser:</p>
<p style="{_S_LINK_FALLBACK}">{url}</p>
<p style="{_S_P}">This link will expire in <strong>30 minutes</strong>.</p>
<p style="{_S_P}">If you did not request this, you can safely ignore this email. Your password will not be changed.</p>"""

    html_body = _wrap_html(body, branding)
    return send_email(to_email, subject, html_body, text_body)


def send_account_recovery_email(
    to_email: str, recovery_url: str, *, tenant_id: str | None = None
) -> bool:
    """Send a neutral account recovery link.

    Does not reveal account type, status, or any details. Used for both
    password reset and inactivation discovery after the user proves email
    possession by clicking the link.
    """
    branding = _get_branding(tenant_id)
    subject = "Continue to your account"

    text_body = _wrap_text(
        f"""
Click the link below to continue:

{recovery_url}

This link will expire in 30 minutes.

If you did not request this, you can safely ignore this email.
""",
        branding,
    )

    url = html.escape(recovery_url)
    body = f"""<h1 style="{_S_H1}">Continue to Your Account</h1>
<p style="{_S_P}">Click the button below to continue:</p>
<a href="{url}" style="{_S_BUTTON}">Continue</a>
<p style="{_S_P}">Or copy and paste this link into your browser:</p>
<p style="{_S_LINK_FALLBACK}">{url}</p>
<p style="{_S_P}">This link will expire in <strong>30 minutes</strong>.</p>
<p style="{_S_P}">If you did not request this, you can safely ignore this email.</p>"""

    html_body = _wrap_html(body, branding)
    return send_email(to_email, subject, html_body, text_body)


def send_hibp_breach_admin_notification(
    to_email: str,
    breach_count: int,
    *,
    tenant_id: str | None = None,
) -> bool:
    """Send notification to admin about passwords found in HIBP breaches."""
    branding = _get_branding(tenant_id)
    user_word = "user" if breach_count == 1 else "users"
    subject = f"Password breach detected: {breach_count} {user_word} affected"

    text_body = _wrap_text(
        f"""
Password Breach Detection

The automated HIBP (Have I Been Pwned) breach monitor has detected that {breach_count} {user_word} in your organization have passwords that appear in known data breaches.

These users have been automatically flagged and will be required to change their password on their next sign-in. Their active API tokens have been revoked.

No action is required from you. Affected users will see a password reset prompt at their next sign-in.
""",
        branding,
    )

    body = f"""<h1 style="{_S_H1}">Password Breach Detected</h1>
<div style="{_S_DANGER_BOX}">
<p style="margin: 0;"><strong>{breach_count} {user_word}</strong> in your organization have passwords that appear in known data breaches.</p>
</div>
<p style="{_S_P}">The automated HIBP (Have I Been Pwned) breach monitor detected these compromised passwords during its periodic scan.</p>
<p style="{_S_P}"><strong>What has been done:</strong></p>
<ul style="margin: 0 0 12px 0; padding-left: 20px; color: #333333;">
<li style="margin-bottom: 4px;">Affected users have been flagged for a mandatory password reset</li>
<li style="margin-bottom: 4px;">Their active API tokens have been revoked</li>
</ul>
<p style="{_S_P}"><strong>What happens next:</strong></p>
<p style="{_S_P}">Each affected user will be prompted to set a new password at their next sign-in. No action is required from you.</p>"""

    html_body = _wrap_html(body, branding)
    return send_email(to_email, subject, html_body, text_body)
