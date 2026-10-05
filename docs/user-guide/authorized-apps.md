# Authorized Apps

When you sign in to an application through WeftID for the first time, WeftID shows a consent screen: the application's name, the account you are signed in with, and what the application is asking for (your profile, your email address, your groups, and so on). If you click **Allow**, WeftID remembers your choice. The next time that application sends you to WeftID, you are signed in without seeing the screen again.

The **Authorized Apps** page under User Settings lists every application you have allowed, with the scopes you granted and when you first allowed it. Approving a [device sign-in](signing-in.md#signing-in-on-a-device) also adds the application here. A device sign-in always asks for approval, even for an application you allowed before.

## When the consent screen appears

- The first time you sign in to an application.
- When an application asks for something you have not allowed before. The screen lists everything the application is requesting and marks what you already allowed.
- When an application explicitly asks WeftID to confirm your consent again.
- After you revoke the application on this page, or an administrator revokes it for you.
- After your account or the application has been deactivated and reactivated.

Clicking **Deny** never records anything. You will see the screen again on the next attempt.

## Revoking an application

Click **Revoke** next to an application and confirm. From then on, the application's next sign-in attempt shows the consent screen again, so you can decide afresh.

Revoking does not sign you out of the application or cancel access tokens it already holds. Those expire on their own schedule. If you need an application cut off immediately, contact your administrator, who can deactivate it.

## What administrators can see

Administrators can see which users have allowed an application, and revoke a user's consent from the application's detail page. They cannot allow an application on your behalf: consent is always your own decision on the consent screen.
