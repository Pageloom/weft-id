# Pairwise Subject Identifiers

Every ID token, UserInfo response, and introspection response names the user in its `sub` claim. By default an app gets the user's WeftID ID, which is the same at every app (a **public** identifier). If two apps compare notes, they can match up users by `sub`.

With **pairwise** identifiers (OpenID Connect Core section 8), the app gets a value derived from the user and the app's **sector** instead. Apps in different sectors get unrelated values for the same person, so they can't link users by `sub`. Apps in the same sector see the same value, so a company running several apps on one domain can still recognise its users across them.

Pairwise is an opt-in per app. Existing apps keep public identifiers.

## The sector

* By default, the sector is the host of the app's redirect URIs. All of the app's redirect URIs must then use the same host.
* An app whose redirect URIs span several hosts needs a **sector identifier URI**: an `https` URL that returns a JSON array listing every redirect URI of the app, for example `["https://app.example.com/callback", "https://eu.app.example.com/callback"]`. The host of this URL is the sector. WeftID fetches the document when the setting is saved and whenever the app's redirect URIs change, and refuses the change if the document doesn't list every redirect URI.

A pairwise `sub` is 43 URL-safe characters. It stays the same as long as the sector and the user stay the same.

## Turning it on

Open the app, enable **Sign in with WeftID (OIDC)**, and find **Subject Identifiers** in the OpenID Connect section:

1. Choose **Pairwise**.
2. Optionally enter a **Sector identifier URI**.
3. Click **Save Subject Identifiers** and confirm.

!!! warning "Every user gets a new `sub`"
    Switching between public and pairwise, or changing the sector, changes the `sub` of every user at that app. The app sees them as new users unless it matches accounts some other way, such as by verified email. Choose pairwise when you first set up an app, or plan a migration with the app's owner.

While an app uses pairwise identifiers without a sector identifier URI, its redirect URIs must stay on one host. Editing them to add another host is refused.

Through the API, send `PUT /api/v1/oauth2/clients/{client_id}/subject` with `subject_type` (`public` or `pairwise`) and, for pairwise, an optional `sector_identifier_uri`. An application that registers itself can ask for pairwise identifiers with `subject_type` and `sector_identifier_uri` (see [Client Registration](client-registration.md)).

Pairwise identifiers apply to apps only. Service accounts act as their own service user and have no `sub` to protect.

## Where the pairwise value appears

* The ID token's `sub`.
* UserInfo, plain or signed.
* Token introspection, as the `sub` of the token's app.
* Back-channel logout tokens sent to the app.
* An `id_token_hint` the app sends back (at sign-in or sign-out) is matched against the pairwise value.

Admin pages and the audit log always show the WeftID user, never the pairwise value.

## Discovery

The discovery document lists `public` and `pairwise` in `subject_types_supported`.
