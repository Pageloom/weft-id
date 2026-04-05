# Signing In

WeftID supports two sign-in flows. Your organization chooses which one is active.

## Default flow (streamlined)

1. Enter your email address.
2. WeftID routes you immediately to your sign-in method:
    - **Password users** see the password prompt.
    - **IdP users** are redirected to their organization's sign-in page (Okta, Entra ID, Google Workspace, etc.).
3. After authenticating, complete two-step verification if required (see step 3 below).

Unknown emails and inactivated accounts are shown the password form with no indication of account status. This prevents information disclosure while keeping the flow fast.

### Forgot password

If you forget your password, click **Forgot password?** on the password form. WeftID sends a neutral email with a link. After clicking the link (proving email ownership), the landing page shows your situation:

- **Password user** — password reset form.
- **Inactivated user** — inactivation disclosure with a reactivation option.
- **No account** — a message to contact your administrator.

See [Password](password.md) for details on password requirements.

## Email-verification flow (opt-in)

Your administrator can enable email verification before sign-in routing. In this flow:

1. Enter your email address.
2. Enter the one-time code sent to that address. This proves email ownership before WeftID reveals anything about your account.
3. WeftID routes you to your sign-in method (password or IdP).
4. Complete two-step verification if required.

### Trust cookies

After verifying your email once, WeftID sets a trust cookie that lasts 7 days. On subsequent sign-ins from the same browser, you skip straight to the password or identity provider step.

### Why two codes?

On your first sign-in with this flow (or when your trust cookie has expired), you enter a code twice:

- **Email verification code** (step 2) proves you own the email address.
- **Two-step verification code** (step 4) proves your identity after your password is accepted.

Once your trust cookie is set, future sign-ins skip step 2 and you only enter one code.

## Two-step verification

After your password is accepted, you enter a verification code from your authenticator app or email. This protects your account even if your password is compromised. See [Two-Step Verification](two-step-verification.md) to configure your verification method.

## Forced password reset

If your administrator has required a password reset, you will be prompted to choose a new password after entering your current one. You must complete this step before reaching the dashboard.

## Signing out

Click **Sign Out** in the navigation bar. WeftID terminates your session and notifies each application you accessed during the session so they can end their sessions too. This is called Single Logout (SLO).

If you signed in through an identity provider that supports SLO, WeftID also redirects you to the identity provider's sign-out page so your IdP session is terminated.

Logout propagation to applications is best-effort. If an application is unreachable, your WeftID session is still terminated and you are returned to the sign-in page.
