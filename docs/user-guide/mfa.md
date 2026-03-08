# Multi-Factor Authentication

Add a second factor to your account for stronger security. WeftId supports authenticator apps (TOTP) and email-based codes.

## Setting up an authenticator app

1. Go to **Account > MFA**
2. Click **Set up TOTP** (or switch to TOTP if email is currently active)
3. Scan the QR code with your authenticator app (Google Authenticator, 1Password, Authy, etc.)
4. Enter the 6-digit code from your app to verify
5. Save the backup codes shown on the next screen

Your authenticator app is now active. You will be prompted for a code on each sign-in.

## Backup codes

Backup codes let you sign in if you lose access to your authenticator app. Ten codes are generated when you enable TOTP. Each code can only be used once.

- View your remaining backup codes on the MFA settings page
- Click **Regenerate** to create a new set (this invalidates all existing codes)

Store backup codes in a safe place. If you run out and lose your authenticator, you will need an admin to reset your MFA.

## Email-based MFA

Email MFA sends a one-time code to your email address on each sign-in. It is simpler than TOTP but depends on access to your email.

## Switching or disabling MFA

1. Go to **Account > MFA**
2. Select the method you want to switch to, or choose to disable
3. Verify your current MFA code
4. The change takes effect immediately

Switching from TOTP to email (or disabling MFA) deletes your backup codes.
