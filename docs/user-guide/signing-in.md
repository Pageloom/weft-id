# Signing In

WeftID uses an email-first sign-in flow with two-step verification.

## Step 1: Email verification

Every sign-in begins by proving you own the email address you entered. WeftID sends a one-time code to that address.

This step lets WeftID identify you securely before revealing anything about your account. Without it, anyone could type your email and learn whether you have an account, which identity provider you use, or that you don't exist in the system at all. With email verification, WeftID can safely guide you to the right sign-in method, or tell you "You don't have an account with this organization."

### Trust cookies

After verifying your email once, WeftID sets a trust cookie that lasts 7 days. On subsequent sign-ins from the same browser, you skip straight to the password or identity provider step.

## Step 2: Password or identity provider

After email verification, WeftID routes you based on your account type:

- **Password users** see the password prompt, then proceed to two-step verification (step 3). If you have forgotten your password, click **Forgot password?** to receive a reset link by email. See [Password](password.md) for details.
- **IdP users** are redirected to their organization's sign-in page (Okta, Entra ID, Google Workspace, etc.). After authenticating with the IdP, you are returned to WeftID. If your administrator requires WeftID two-step verification for that IdP, you complete that step before reaching your dashboard.

If your administrator has required a password reset, you will be prompted to choose a new password after entering your current one. You must complete this step before reaching the dashboard.

## Step 3: Two-step verification

After your password is accepted, you enter a verification code from your authenticator app or email. This protects your account even if your password is compromised. See [Two-Step Verification](two-step-verification.md) to configure your verification method.

## Why two codes on first sign-in?

On your first sign-in (or when your trust cookie has expired), you enter a code twice. These serve different purposes:

- **Email verification code** (step 1) proves you own the email address. This is an identity check so WeftID can route you correctly.
- **Two-step verification code** (step 3) proves your identity after your password is accepted. This is a security measure.

Once your trust cookie is set, future sign-ins skip step 1 and you only enter one code.

## Signing out

Click **Sign Out** in the navigation bar. WeftID terminates your session and notifies each application you accessed during the session so they can end their sessions too. This is called Single Logout (SLO).

If you signed in through an identity provider (Okta, Entra ID, etc.) that supports SLO, WeftID also redirects you to the identity provider's sign-out page so your IdP session is terminated.

Logout propagation to applications is best-effort. If an application is unreachable, your WeftID session is still terminated and you are returned to the sign-in page. The application's local session expires on its own.
