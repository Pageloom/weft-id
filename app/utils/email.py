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
    smtp_host = os.getenv('SMTP_HOST', 'maildev')  # maildev is the container name
    smtp_port = int(os.getenv('SMTP_PORT', '1025'))
    smtp_user = os.getenv('SMTP_USER', '')
    smtp_pass = os.getenv('SMTP_PASS', '')
    from_email = os.getenv('SMTP_FROM', 'noreply@pageloom.localhost')

    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = from_email
        msg['To'] = to_email

        # Attach text and HTML parts
        if text_body:
            msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))

        # Send via SMTP
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            # maildev doesn't need authentication, but production might
            if smtp_user and smtp_pass:
                server.starttls()
                server.login(smtp_user, smtp_pass)

            server.send_message(msg)

        print(f'✓ Email sent to {to_email}: {subject}')
        return True

    except Exception as e:
        print(f'✗ Failed to send email to {to_email}: {e}')
        return False


def send_mfa_code_email(to_email: str, code: str) -> bool:
    """Send MFA verification code via email."""
    subject = 'Your verification code'

    text_body = f'''
Your verification code is: {code}

This code will expire in 10 minutes.

If you did not request this code, please ignore this email.
'''

    html_body = f'''
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
'''

    return send_email(to_email, subject, html_body, text_body)
