# Signing In

WeftId uses an email-first sign-in flow.

## Password sign-in

1. Enter your email address
2. WeftId sends a verification code to your email
3. Enter the verification code
4. Enter your password
5. If MFA is enabled, enter your MFA code (authenticator app or email)

### Trust cookies

After verifying your email once, WeftId sets a trust cookie that lasts 7 days. During this time, you can skip the email verification step and go directly to the password prompt.

## Identity provider sign-in

If your email domain is linked to an identity provider, you may be redirected to your organization's sign-in page (Okta, Entra ID, Google Workspace, etc.) instead of entering a WeftId password.

After authenticating with your IdP, you are returned to WeftId. If your administrator requires WeftId MFA, you complete that step before reaching your dashboard.

## Signing out

Click **Sign Out** in the navigation bar. Your session is terminated and you are returned to the sign-in page.
