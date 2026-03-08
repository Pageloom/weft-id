# Signing In

WeftId uses an email-first sign-in flow with two-step verification.

## Step 1: Email verification

Every sign-in begins by proving you own the email address you entered. WeftId sends a one-time code to that address.

This step lets WeftId identify you securely before revealing anything about your account. Without it, anyone could type your email and learn whether you have an account, which identity provider you use, or that you don't exist in the system at all. With email verification, WeftId can safely guide you to the right sign-in method, or tell you "You don't have an account with this organization."

### Trust cookies

After verifying your email once, WeftId sets a trust cookie that lasts 7 days. On subsequent sign-ins from the same browser, you skip straight to the password or identity provider step.

## Step 2: Password or identity provider

After email verification, WeftId routes you based on your account type:

- **Password users** see the password prompt, then proceed to two-step verification (step 3).
- **IdP users** are redirected to their organization's sign-in page (Okta, Entra ID, Google Workspace, etc.). After authenticating with the IdP, you are returned to WeftId. If your administrator requires WeftId two-step verification for that IdP, you complete that step before reaching your dashboard.

## Step 3: Two-step verification

After your password is accepted, you enter a verification code from your authenticator app or email. This protects your account even if your password is compromised. See [Two-Step Verification](two-step-verification.md) to configure your verification method.

## Why two codes on first sign-in?

On your first sign-in (or when your trust cookie has expired), you enter a code twice. These serve different purposes:

- **Email verification code** (step 1) proves you own the email address. This is an identity check so WeftId can route you correctly.
- **Two-step verification code** (step 3) proves your identity after your password is accepted. This is a security measure.

Once your trust cookie is set, future sign-ins skip step 1 and you only enter one code.

## Signing out

Click **Sign Out** in the navigation bar. WeftId terminates your session and notifies each application you accessed during the session so they can end their sessions too. This is called Single Logout (SLO).

If you signed in through an identity provider (Okta, Entra ID, etc.) that supports SLO, WeftId also redirects you to the identity provider's sign-out page so your IdP session is terminated.

Logout propagation to applications is best-effort. If an application is unreachable, your WeftId session is still terminated and you are returned to the sign-in page. The application's local session expires on its own.
