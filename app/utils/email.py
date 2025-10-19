"""Email sending utilities."""

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def send_email(to_email: str, subject: str, html_body: str, text_body: str | None = None) -> bool:
    """
    Send an email via SMTP.

    In development: uses maildev container (SMTP on port 1025)
    In production: configure with AWS SES, SendGrid, Mailgun, etc.
    """
    # SMTP configuration
    smtp_host = os.getenv("SMTP_HOST", "maildev")  # maildev is the container name
    smtp_port = int(os.getenv("SMTP_PORT", "1025"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    from_email = os.getenv("SMTP_FROM", "noreply@pageloom.localhost")

    try:
        # Create message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = to_email

        # Attach text and HTML parts
        if text_body:
            msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        # Send via SMTP
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            # maildev doesn't need authentication, but production might
            if smtp_user and smtp_pass:
                server.starttls()
                server.login(smtp_user, smtp_pass)

            server.send_message(msg)

        print(f"✓ Email sent to {to_email}: {subject}")
        return True

    except Exception as e:
        print(f"✗ Failed to send email to {to_email}: {e}")
        return False


def send_mfa_code_email(to_email: str, code: str) -> bool:
    """Send MFA verification code via email."""
    # ruff: noqa: E501
    subject = "Your verification code"

    text_body = f"""
Your verification code is: {code}

This code will expire in 10 minutes.

If you did not request this code, please ignore this email.
"""

    # fmt: off
    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .code {{ background: #f3f4f6; border: 2px solid #e5e7eb; border-radius: 8px; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 8px; margin: 20px 0; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 14px; color: #6b7280; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Your Verification Code</h1>
        <p>Use the following code to complete your sign-in:</p>
        <div class="code">{code}</div>
        <p>This code will expire in <strong>10 minutes</strong>.</p>
        <p>If you did not request this code, please ignore this email.</p>
        <div class="footer">
            <p>This is an automated message, please do not reply.</p>
        </div>
    </div>
</body>
</html>
"""
    # fmt: on

    return send_email(to_email, subject, html_body, text_body)


def send_email_verification(to_email: str, verification_url: str) -> bool:
    """Send email address verification link."""
    # ruff: noqa: E501
    subject = "Verify your email address"

    text_body = f"""
Please verify your email address by clicking the link below:

{verification_url}

If you did not add this email address to your account, please ignore this email.
"""

    # fmt: off
    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .button {{ display: inline-block; background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin: 20px 0; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 14px; color: #6b7280; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Verify Your Email Address</h1>
        <p>Please verify your email address by clicking the button below:</p>
        <a href="{verification_url}" class="button">Verify Email Address</a>
        <p>Or copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #6b7280;">{verification_url}</p>
        <p>If you did not add this email address to your account, please ignore this email.</p>
        <div class="footer">
            <p>This is an automated message, please do not reply.</p>
        </div>
    </div>
</body>
</html>
"""
    # fmt: on

    return send_email(to_email, subject, html_body, text_body)


def send_secondary_email_added_notification(
    to_email: str, added_email: str, admin_name: str
) -> bool:
    """Send notification when an admin adds a secondary email to an account."""
    # ruff: noqa: E501
    subject = "Secondary email address added to your account"

    text_body = f"""
A secondary email address has been added to your account by an administrator.

Added email: {added_email}
Added by: {admin_name}

This email address has been automatically verified and can be used to access your account.

If you did not expect this change or have concerns, please contact your administrator immediately.
"""

    # fmt: off
    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .info-box {{ background: #f3f4f6; border-left: 4px solid #2563eb; padding: 15px; margin: 20px 0; }}
        .warning {{ margin-top: 20px; padding: 15px; background: #fef3c7; border-left: 4px solid #f59e0b; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 14px; color: #6b7280; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Secondary Email Address Added</h1>
        <p>A secondary email address has been added to your account by an administrator.</p>
        <div class="info-box">
            <p><strong>Added email:</strong> {added_email}</p>
            <p><strong>Added by:</strong> {admin_name}</p>
        </div>
        <p>This email address has been automatically verified and can be used to access your account.</p>
        <div class="warning">
            <p><strong>Security Notice:</strong> If you did not expect this change or have concerns, please contact your administrator immediately.</p>
        </div>
        <div class="footer">
            <p>This is an automated message, please do not reply.</p>
        </div>
    </div>
</body>
</html>
"""
    # fmt: on

    return send_email(to_email, subject, html_body, text_body)


def send_secondary_email_removed_notification(
    to_email: str, removed_email: str, admin_name: str
) -> bool:
    """Send notification when an admin removes a secondary email from an account."""
    # ruff: noqa: E501
    subject = "Secondary email address removed from your account"

    text_body = f"""
A secondary email address has been removed from your account by an administrator.

Removed email: {removed_email}
Removed by: {admin_name}

This email address can no longer be used to access your account.

If you did not expect this change or have concerns, please contact your administrator immediately.
"""

    # fmt: off
    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .info-box {{ background: #f3f4f6; border-left: 4px solid #2563eb; padding: 15px; margin: 20px 0; }}
        .warning {{ margin-top: 20px; padding: 15px; background: #fef3c7; border-left: 4px solid #f59e0b; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 14px; color: #6b7280; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Secondary Email Address Removed</h1>
        <p>A secondary email address has been removed from your account by an administrator.</p>
        <div class="info-box">
            <p><strong>Removed email:</strong> {removed_email}</p>
            <p><strong>Removed by:</strong> {admin_name}</p>
        </div>
        <p>This email address can no longer be used to access your account.</p>
        <div class="warning">
            <p><strong>Security Notice:</strong> If you did not expect this change or have concerns, please contact your administrator immediately.</p>
        </div>
        <div class="footer">
            <p>This is an automated message, please do not reply.</p>
        </div>
    </div>
</body>
</html>
"""
    # fmt: on

    return send_email(to_email, subject, html_body, text_body)


def send_primary_email_changed_notification(
    to_email: str, new_primary_email: str, admin_name: str
) -> bool:
    """Send notification to the old primary email when it has been changed."""
    # ruff: noqa: E501
    subject = "Your primary email address has been changed"

    text_body = f"""
Your primary email address has been changed by an administrator.

New primary email: {new_primary_email}
Changed by: {admin_name}

Your account login will now use the new primary email address.

If you did not expect this change or have concerns, please contact your administrator immediately.
"""

    # fmt: off
    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .info-box {{ background: #f3f4f6; border-left: 4px solid #2563eb; padding: 15px; margin: 20px 0; }}
        .warning {{ margin-top: 20px; padding: 15px; background: #fef3c7; border-left: 4px solid #f59e0b; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 14px; color: #6b7280; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Primary Email Address Changed</h1>
        <p>Your primary email address has been changed by an administrator.</p>
        <div class="info-box">
            <p><strong>New primary email:</strong> {new_primary_email}</p>
            <p><strong>Changed by:</strong> {admin_name}</p>
        </div>
        <p>Your account login will now use the new primary email address.</p>
        <div class="warning">
            <p><strong>Security Notice:</strong> If you did not expect this change or have concerns, please contact your administrator immediately.</p>
        </div>
        <div class="footer">
            <p>This is an automated message, please do not reply.</p>
        </div>
    </div>
</body>
</html>
"""
    # fmt: on

    return send_email(to_email, subject, html_body, text_body)
