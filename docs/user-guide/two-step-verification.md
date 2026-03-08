# Two-Step Verification

Every sign-in requires a verification code after your password. WeftId supports authenticator apps (TOTP) and email-based codes. Email is the default method.

## Setting up an authenticator app

1. Go to **Account > Two-Step Verification**
2. Click **Authenticator App or Password Manager (TOTP)**
3. Scan the QR code with your authenticator app (Google Authenticator, 1Password, Authy, etc.)
4. Enter the 6-digit code from your app to verify
5. Save the backup codes shown on the next screen

Your authenticator app is now active. You will be prompted for a code on each sign-in.

## Backup codes

Backup codes let you sign in if you lose access to your authenticator app. Ten codes are generated when you enable TOTP. Each code can only be used once.

- View your remaining backup codes on the two-step verification settings page
- Click **Regenerate** to create a new set (this invalidates all existing codes)

Store backup codes in a safe place. If you run out and lose your authenticator, you will need an admin to reset your verification method.

## Email-based verification

Email verification sends a one-time code to your email address on each sign-in. It is the default method. It is simpler than TOTP but depends on access to your email.

## Switching methods

1. Go to **Account > Two-Step Verification**
2. Select the method you want to switch to
3. Verify the change with your current method
4. The change takes effect immediately

Switching from TOTP to email deletes your backup codes.
