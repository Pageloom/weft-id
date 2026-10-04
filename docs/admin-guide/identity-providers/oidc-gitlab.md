# OIDC with GitLab

Connect GitLab as an upstream identity provider so users sign in with their GitLab account. This works with gitlab.com and with a self-managed GitLab instance.

The general mechanics are covered in [OIDC Setup](oidc-setup.md). This page covers what is specific to GitLab.

## What the preset supplies

Selecting the **GitLab** provider type pre-fills:

* Issuer and discovery URL: `https://gitlab.com`
* Scopes: `openid profile email`
* Correlation claim: `sub`

GitLab's `sub` is the user's numeric ID. It does not change when the user renames their account or changes their email address.

### Self-managed GitLab

Replace the issuer with your instance's URL, for example `https://gitlab.example.com`, and leave the discovery URL blank. WeftID then reads the discovery document from your instance instead of gitlab.com. The issuer must match the `external_url` your instance is configured with, or the connection test fails with an issuer mismatch.

## Step 1: Create the GitLab application

An application can belong to a user, a group, or (on a self-managed instance) the whole instance. A group or instance application survives the person who created it leaving.

1. Open the application settings:
    * **Group**: the group's **Settings > Applications**
    * **Instance** (self-managed): **Admin area > Applications**
    * **User**: **Edit profile > Applications**
2. Click **Add new application** and give it a name
3. Under **Redirect URI**, paste the redirect URI from your WeftID connection's Details tab
4. Leave **Confidential** checked
5. Under **Scopes**, select `openid`, `profile`, and `email`
6. Click **Save application** and copy the **Application ID** and **Secret**

## Step 2: Configure the WeftID connection

1. In WeftID, go to **Identity Providers > OIDC** and create a connection with provider type **GitLab**
2. For a self-managed instance, replace the issuer (see above)
3. Paste the application ID as the client ID, and the secret as the client secret
4. Click **Test connection**, then enable it

## Email linking

GitLab includes `email_verified` in its tokens, so [email linking](oidc-setup.md#allow-email-linking) can match existing accounts when you turn it on. The security trade-off described there still applies.

## Groups

GitLab returns the full paths of the user's groups, such as `acme/engineering`, in a `groups` claim. Enter `groups` as the connection's [group claim](oidc-setup.md#group-claims) to sync them. To sync only the groups the user belongs to directly, use `groups_direct` instead.

## Troubleshooting

**"The redirect URI included is not valid"**
:   The URI registered on the GitLab application does not exactly match WeftID's. Copy it again from the connection's Details tab.

**Issuer mismatch when testing a self-managed connection**
:   The issuer in WeftID differs from the one your instance publishes. Open `https://<your-instance>/.well-known/openid-configuration` and copy its `issuer` value into the connection.

**"The requested scope is invalid, unknown, or malformed"**
:   The GitLab application lacks one of the `openid`, `profile`, or `email` scopes. Edit the application and add it.
