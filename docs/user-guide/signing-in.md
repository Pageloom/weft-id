# Signing In

WeftID supports two sign-in flows. Your organization chooses which one is active.

## Default flow (streamlined)

1. Enter your email address.
2. WeftID routes you immediately to your sign-in method:
    - **Password users** see the password prompt.
    - **IdP users** are redirected to their identity provider's sign-in page (Okta, Entra ID, Google, GitHub, etc.). If you sign in with more than one provider, you go to the one you used last.
3. After authenticating, complete two-step verification if required (see step 3 below).

Unknown emails and deactivated accounts are shown the password form with no indication of account status. This prevents information disclosure while keeping the flow fast.

### Forgot password

If you forget your password, click **Forgot password?** on the password form. WeftID sends a neutral email with a link. After clicking the link (proving email ownership), the landing page shows your situation:

- **Password user** — password reset form.
- **Deactivated user** — deactivation disclosure with a reactivation option.
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

## Continue with a provider

Your organization may put **Continue with ...** buttons above the email field, such as **Continue with Google**. Click one to sign in with your account at that provider. You do not enter your email address first.

The first time you use a button, WeftID either finds your existing account, creates one, or tells you no account was found, depending on how your organization set it up. If your account signs in through your organization's single sign-on, use your email address instead.

Once your account is linked to a provider, you can use its button or your email address. Both reach the same account.

Some providers, such as Facebook, do not confirm that your email address is yours. When such a provider creates your account, WeftID emails a code to the address and asks for it before you are signed in. Enter it to finish. You only do this once. If you enter a wrong code too many times, or wait too long, you are sent back to the sign-in page to start again.

If the sign-in page says **Too many attempts**, wait a few minutes and try again.

## Passkey sign-in

If you have a passkey registered, WeftID offers a passkey prompt after you enter your email. Approve with your fingerprint, PIN, or security key tap, and you go straight to the dashboard. No password, no verification code.

If the passkey prompt is dismissed or fails, WeftID falls back to the normal password and two-step verification flow. See [Passkeys](passkeys.md) for details on registering and managing passkeys.

## Two-step verification

After your password is accepted, you enter a verification code from your authenticator app or email. This protects your account even if your password is compromised. See [Two-Step Verification](two-step-verification.md) to configure your verification method.

## Enhanced authentication enrollment

If your organization requires stronger sign-in (enhanced [authentication policy](../admin-guide/security/authentication-policy.md)), users with only email-based verification are redirected to an enrollment page after their next sign-in. The page offers two options: register a passkey or set up an authenticator app (TOTP). Completing either option satisfies the policy and finishes the sign-in.

## Forced password reset

If your administrator has required a password reset, you will be prompted to choose a new password after entering your current one. You must complete this step before reaching the dashboard.

## Signing in on a device

Some apps run on devices where typing a password is awkward, such as a command-line tool or a TV. They show a short code, such as `BCDF-GHJK`, and an address ending in `/device`.

1. Open that address on your phone or computer and sign in to WeftID if asked.
2. Enter the code. Capital letters and the dash are optional.
3. Check that the app and the code match what your device shows, then click **Allow**.

The device signs in a few seconds later. Only allow a code you got from a device in front of you. If someone sends you a code and asks you to enter it, click **Deny**: approving would give them access to your account. You can see and revoke the apps you allowed under [Authorized Apps](authorized-apps.md).

## Signing out

Click **Sign Out** in the navigation bar. WeftID terminates your session and notifies each application you accessed during the session so they can end their sessions too. This is called Single Logout (SLO).

If you signed in through an identity provider, WeftID may also sign you out there, depending on how your organization set up the provider.

Logout propagation to applications is best-effort. If an application is unreachable, your WeftID session is still terminated and you are returned to the sign-in page.

### When an application signs you out

Signing out of an application can also sign you out of WeftID. If WeftID needs your confirmation, it shows a **Sign out?** page with the account you're signed in as. Choose **Sign out** to end your session, or **Stay signed in** to keep it.

If WeftID can't verify the application's request, the page says so, and you are not sent back to the application.

### When an application asks you to sign in again

Some applications require a fresh sign-in, for example before a sensitive action. WeftID shows a **Sign in again?** page. **Sign in again** signs you out of your current session and back to the sign-in page. **Cancel** returns you to the application without signing in.
