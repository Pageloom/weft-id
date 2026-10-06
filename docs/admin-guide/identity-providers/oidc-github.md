# Sign in with GitHub

Connect GitHub so users sign in with their GitHub account. You can let any GitHub account sign in, or only members of the GitHub organizations you list.

GitHub is not an OpenID Connect provider. It uses plain OAuth 2.0, so a GitHub connection has no issuer, discovery document or ID token for you to configure. WeftID knows GitHub's endpoints and reads the user's profile from the GitHub API after they sign in. Everything else (just-in-time provisioning, email linking, platform two-step verification, the sign-in page button) works as described in [OIDC Setup](oidc-setup.md).

## What the preset supplies

Selecting the **GitHub** provider type sets:

* Scopes: `read:user user:email read:org`
* GitHub's fixed authorization, token and API endpoints

The issuer, discovery URL and correlation claim fields are hidden for GitHub. Users are matched on their numeric GitHub account ID, which stays the same when they rename their account or change their email address.

The scopes are what each one is for:

* `read:user`: the profile (name, username, avatar)
* `user:email`: the account's email addresses, so WeftID can find the primary one
* `read:org`: organization and team membership, for allowed organizations and group sync. Drop it if you use neither

## Step 1: Create a GitHub OAuth app

Create the app under a GitHub organization rather than a personal account, so it survives the person who created it leaving.

1. In GitHub, open the organization's **Settings > Developer settings > OAuth Apps** and click **New OAuth app**
2. Fill in:
    * **Application name**: what users see on GitHub's consent screen, for example your product's name
    * **Homepage URL**: your WeftID sign-in page, for example `https://acme.example.com`
    * **Authorization callback URL**: the callback URL from your WeftID connection's Details tab (you can create the WeftID connection first and fill this in afterwards)
3. Click **Register application**
4. Copy the **Client ID**, then click **Generate a new client secret** and copy the secret

A GitHub OAuth app has exactly one callback URL, so each WeftID connection needs its own app.

Use an OAuth app, not a GitHub App. GitHub Apps ignore the requested scopes and need their own permissions set up for email and organization access.

## Step 2: Configure the WeftID connection

1. In WeftID, go to **Identity Providers > OIDC** and create a connection with provider type **GitHub**
2. Paste the client ID and client secret
3. Optionally, list the organizations users must belong to (see below)
4. Save, copy the callback URL from the Details tab into the GitHub app if you haven't yet, and click **Test Connection**
5. Enable the connection, and turn on **Show on Sign-In Page** to add a "Continue with GitHub" button (see [Sign-in page buttons](login-buttons.md))

Test Connection sends the client ID, client secret and callback URL to GitHub. It reports whether GitHub rejects the credentials or the callback URL, without anyone signing in.

## Allowed organizations

With no organizations listed, any GitHub account can sign in (subject to your just-in-time provisioning and email linking settings). To limit sign-in, list one or more organization names on the Details tab under **Allowed Organizations**. A user must belong to at least one of them. Names are matched without regard to case.

A user outside every listed organization is turned away with a message telling them so, and the attempt is recorded in the event log as a failed sign-in with the reason `github_org_not_allowed`.

How GitHub reports membership matters here:

* The `read:org` scope is needed to see private memberships. Without it, only memberships a user has made public count
* If an organization restricts OAuth app access, GitHub may not report membership in it until an organization owner approves your app. Users can request approval on GitHub's consent screen; owners approve it under the organization's **Settings > Third-party access**

## Groups

To sync GitHub organizations and teams into WeftID groups, open the connection's **Claim Mapping** tab and enter `groups` as the [group claim](oidc-setup.md#group-claims). On each sign-in WeftID then reads the user's organizations and teams and keeps their group membership in step:

* An organization becomes a group named after it, for example `acme`
* A team becomes a group named `<organization>/<team>`, for example `acme/platform`

When allowed organizations are set, only those organizations and their teams become groups. An organization a user happens to belong to outside that list never appears in your tenant. Without allowed organizations, every organization and team of every user who signs in becomes a group, which is rarely what you want for a public sign-in page.

## Email and names

WeftID only uses the account's **primary** email address, and only when GitHub has verified it. An account whose primary address is unverified signs in without an email, so it cannot be provisioned or [email-linked](account-linking.md) until the user verifies it on GitHub. A user who already has a linked account still signs in.

GitHub has a single display name. WeftID takes the first word as the first name and the rest as the last name. A user with no display name gets their GitHub username as their first name.

## Sign-out

GitHub has no sign-out endpoint and no back-channel logout, so the related settings are hidden. Signing out of WeftID does not sign the user out of GitHub.

## Troubleshooting

**"The redirect_uri is not associated with this application"**
:   The callback URL on the GitHub app does not exactly match WeftID's. Copy it again from the connection's Details tab. Test Connection reports this too.

**Test Connection: "GitHub rejected the client ID or client secret"**
:   The client ID or secret is wrong, or the secret was deleted on GitHub. Generate a new secret and set it on the connection (see [Changing credentials later](oidc-setup.md#changing-credentials-later)).

**Users see "not a member of an organization that can sign in here" although they are**
:   Their membership is private and the connection lacks the `read:org` scope, or the organization restricts OAuth app access and has not approved the app. See [Allowed organizations](#allowed-organizations).

**Sign-in fails and the event log shows `github_api`**
:   A GitHub API call failed after the user authorized the app. A missing `user:email` scope is the usual cause. Check the connection's scopes on its **Details** tab.
