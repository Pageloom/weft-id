# Forward Auth for HTTP Apps

Many HTTP applications have no built-in single sign-on: Grafana in viewer mode,
Sonarr, internal dashboards, a static admin panel. WeftID can gate these apps at
your reverse proxy (Traefik, nginx, Caddy) so only signed-in, authorized users
reach them, even when the app itself knows nothing about SAML or OIDC.

This works through **forward auth** (also called external authentication or
`auth_request`). On every request to a protected app, your reverse proxy makes a
small subrequest to WeftID's `/forward-auth/check` endpoint. WeftID answers:

- **200 OK** — allow the request. WeftID adds `X-Forwarded-User`,
  `X-Forwarded-Email`, `X-Forwarded-Groups`, and `X-Forwarded-Display-Name`
  identity headers, which your proxy passes upstream to the app.
- **302 Found** — the user has no valid session for this domain. The proxy
  redirects the browser into the sign-in handshake.
- **403 Forbidden** — the user is signed in but not authorized for this app.

## The multi-domain model

Forward auth in WeftID is designed to protect apps on **domains you already
own**: `grafana.acme-corp.com`, `sonarr.myhomelab.net`. Your apps do **not** have
to live under your WeftID tenant subdomain (`acme.weft.id`).

Browsers forbid one cookie from spanning unrelated domains, so WeftID cannot use
its main session cookie across your app domains. Instead it uses an OAuth-like
redirect handshake that mints a **separate, per-domain forward-auth cookie** (the
same model Authelia and oauth2-proxy use). Your WeftID session cookie is never
touched; it stays scoped to your tenant host.

### The handshake

For an app at `https://grafana.acme-corp.com`, with WeftID reachable at a
**portal host** under that domain (`auth.acme-corp.com`) and your tenant at
`acme.weft.id`:

1. Browser requests `grafana.acme-corp.com`. The reverse proxy calls
   `auth.acme-corp.com/forward-auth/check`.
2. No per-domain cookie yet, so WeftID returns 302 to
   `auth.acme-corp.com/forward-auth/start`.
3. `/start` redirects to your tenant host
   `acme.weft.id/forward-auth/authorize`.
4. At `acme.weft.id` you use your normal WeftID session (or sign in). WeftID
   confirms you may access this app, mints a short-lived single-use token, and
   redirects to `auth.acme-corp.com/forward-auth/callback`.
5. `/callback` validates the token and **sets the per-domain forward-auth
   cookie** (scoped to `acme-corp.com`), then redirects back to the original URL.
6. The next `/check` sees a valid cookie and returns 200 with identity headers.

### The hard requirement: a portal host under each domain

WeftID can only set the `acme-corp.com` cookie and serve `/check` for it if it is
reachable at a hostname **under** `acme-corp.com`. This is a browser rule, not a
WeftID limitation.

So protecting a domain requires pointing **one portal host** (for example
`auth.acme-corp.com`) at your WeftID instance via DNS. If you cannot create any
DNS record under a domain, cookie-based forward auth for it is impossible (the app
would need real OIDC or SAML instead). This is a one-time setup step per domain,
not a defect.

!!! note "Protected domains are not privileged (email) domains"
    A **protected domain** here is a DNS/web domain you control for forward-auth
    infrastructure (portal host, cookies, TLS), proven with a DNS-TXT challenge.
    It is unrelated to a [privileged domain](../identity-providers/privileged-domains.md),
    which is an **email** domain used for identity routing. The same string can be
    registered as both; they are independent concepts.

## Setup

### 1. Register and verify the protected domain

In **Service Providers → Protected Domains**, register the domain (for example
`acme-corp.com`) and its portal host (`auth.acme-corp.com`). WeftID issues a
DNS-TXT challenge:

- Add a TXT record at `_weftid-challenge.acme-corp.com` with the value
  `weftid-domain-verification=<token>` shown in the UI.
- Click **Verify**. WeftID checks the record and marks the domain verified.

Only verified domains can serve forward-auth cookies or receive TLS certificates.

### 2. Point the portal host at WeftID

Create a DNS record for the portal host (`auth.acme-corp.com`) pointing at your
WeftID instance's public IP. WeftID obtains a TLS certificate for it on demand
(see [On-demand TLS](#on-demand-tls)).

### 3. Create the proxy app

In **Service Providers → Proxy Apps**, create an app under the verified domain:

- **External URL** — where the app actually runs, under the protected domain
  (`https://grafana.acme-corp.com`).
- **Public paths** — paths that bypass auth entirely (health checks, login assets,
  webhook receivers). Rooted relative patterns, for example `/healthz` or
  `/static/*`.
- **Forwarded headers** — which `X-Forwarded-*` identity headers to send upstream
  (`user`, `email`, `groups`, `display_name`).
- **Available to all** / **group grants** — who may access the app, using the same
  group model as SAML service providers.

The proxy app's detail page shows a copy-paste reverse-proxy snippet.

### 4. Configure your reverse proxy

Add a forward-auth rule that sends every request to
`https://auth.acme-corp.com/forward-auth/check`, copies the `X-Forwarded-*`
response headers upstream, and **strips the forward-auth cookie before passing the
request upstream** (see [Strip the cookie](#strip-the-forward-auth-cookie)).

## Reverse-proxy configuration

In all three examples, replace `auth.acme-corp.com` with your portal host and
`grafana.acme-corp.com` with your app's host.

### Caddy (`forward_auth`)

```caddy
grafana.acme-corp.com {
	forward_auth https://auth.acme-corp.com {
		uri /forward-auth/check
		# Copy identity headers from the auth response upstream.
		copy_headers X-Forwarded-User X-Forwarded-Email X-Forwarded-Groups X-Forwarded-Display-Name
	}

	# Strip the forward-auth cookie before proxying upstream.
	request_header -Cookie

	reverse_proxy grafana-upstream:3000
}
```

Caddy's `forward_auth` automatically forwards the original method, host, URI, and
cookies to the auth endpoint, and follows the 302 to the sign-in handshake.

### Traefik (`forwardAuth` middleware)

```yaml
http:
  middlewares:
    weftid-auth:
      forwardAuth:
        address: "https://auth.acme-corp.com/forward-auth/check"
        authResponseHeaders:
          - "X-Forwarded-User"
          - "X-Forwarded-Email"
          - "X-Forwarded-Groups"
          - "X-Forwarded-Display-Name"
        # Pass the original host so WeftID can resolve the app.
        # Traefik forwards X-Forwarded-Host automatically.

  routers:
    grafana:
      rule: "Host(`grafana.acme-corp.com`)"
      middlewares:
        - "weftid-auth"
        - "strip-auth-cookie"
      service: "grafana"

    # Remove the forward-auth cookie before the request hits the app.
    # (Use a headers middleware or customRequestHeaders to clear Cookie,
    # or scope the cookie name with a dedicated plugin.)
```

`authResponseHeaders` lists exactly the headers Traefik will copy from the auth
response onto the upstream request. Only the identity headers above are needed.

### nginx (`auth_request`)

nginx needs an extra step that Caddy and Traefik do not. Its `auth_request`
module only understands **2xx** (allow) and **401/403** (deny) from the auth
subrequest; it treats any **3xx** as an error (HTTP 500). WeftID's `/check`
returns a **302** when there is no valid cookie, so you must not let
`auth_request` see that 302 directly. Instead, capture the subrequest's
`Location` header and have **nginx itself** issue the browser redirect into the
handshake:

```nginx
server {
    listen 443 ssl;
    server_name grafana.acme-corp.com;

    location / {
        auth_request /__weftid_auth;

        # Capture the redirect target from the auth subrequest (set only when
        # /check answers 302 -- i.e. no valid cookie yet).
        auth_request_set $weft_redirect $upstream_http_location;

        # Capture identity headers from the auth subrequest...
        auth_request_set $weft_user        $upstream_http_x_forwarded_user;
        auth_request_set $weft_email       $upstream_http_x_forwarded_email;
        auth_request_set $weft_groups      $upstream_http_x_forwarded_groups;
        auth_request_set $weft_displayname $upstream_http_x_forwarded_display_name;

        # ...and pass them upstream.
        proxy_set_header X-Forwarded-User         $weft_user;
        proxy_set_header X-Forwarded-Email        $weft_email;
        proxy_set_header X-Forwarded-Groups       $weft_groups;
        proxy_set_header X-Forwarded-Display-Name $weft_displayname;

        # Strip the forward-auth cookie before proxying upstream.
        proxy_set_header Cookie "";

        proxy_pass http://grafana-upstream:3000;

        # When the subrequest denied with 302, nginx returns 500 to this
        # location; turn that into the browser redirect the handshake needs.
        error_page 500 = @weftid_signin;
    }

    # Issue the browser redirect ourselves, using the Location the auth
    # subrequest produced (falls back to /start if it was empty).
    location @weftid_signin {
        if ($weft_redirect = "") {
            return 302 https://auth.acme-corp.com/forward-auth/start?rd=https://$host$request_uri;
        }
        return 302 https://auth.acme-corp.com$weft_redirect;
    }

    # A signed-in-but-unauthorized user gets a real 403 from /check; surface it.
    error_page 403 = @weftid_denied;
    location @weftid_denied {
        return 403;
    }

    location = /__weftid_auth {
        internal;
        proxy_pass https://auth.acme-corp.com/forward-auth/check;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        # Forward the original host and URL so WeftID resolves the app.
        proxy_set_header X-Forwarded-Host  $host;
        proxy_set_header X-Forwarded-Uri   $request_uri;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Because `auth_request` cannot follow the 302 itself, nginx captures the auth
response's `Location` with `auth_request_set` and re-issues it as a normal
browser redirect from the `@weftid_signin` named location. The `/check` 403
(signed in but not authorized for this app) passes through `auth_request`
natively and is surfaced as a 403 to the browser.

### Strip the forward-auth cookie

The per-domain forward-auth cookie is WeftID's, not the app's. Always strip the
`Cookie` header (or at least the forward-auth cookie) **before proxying upstream**,
so the protected app never sees WeftID's session material. The snippets above do
this with `request_header -Cookie` (Caddy), `proxy_set_header Cookie ""` (nginx),
or a header middleware (Traefik).

## On-demand TLS

WeftID's bundled Caddy reverse proxy issues TLS certificates **on demand** via the
HTTP-01 challenge. When a TLS handshake arrives for a new host, Caddy asks WeftID's
`/caddy/check-domain` endpoint whether that host is admissible. WeftID admits:

- your tenant subdomains under `BASE_DOMAIN`, and
- **verified** protected-domain portal hosts.

So once a protected domain is verified and its portal host's DNS points at your
WeftID instance, a certificate is issued automatically on the first request. No
manual certificate steps and no DNS-provider API needed.

If you run your own reverse proxy in front of WeftID instead of the bundled Caddy,
issue certificates for portal hosts however you normally do; the
`/forward-auth/*` endpoints do not require Caddy specifically.

## Sessions and logout

The per-domain forward-auth cookie has a **fixed 1-hour lifetime**. `/check`
validates the cookie's signature and expiry only; it does not re-check your central
WeftID session on every request (that would require a cross-domain lookup on the
hot path). The practical consequence: after you sign out of WeftID centrally, an
already-issued per-domain cookie remains valid until it expires, up to one hour.
Full cross-domain single logout is a planned future enhancement.

## Troubleshooting

**Cookie not sent / infinite redirect loop.**
The browser must send the `acme-corp.com` forward-auth cookie back on the `/check`
subrequest. This only works if the portal host is genuinely under the protected
domain (`auth.acme-corp.com` for `acme-corp.com`). A portal host on an unrelated
domain can never set a usable cookie, producing a redirect loop. Verify the portal
host is a subdomain of the protected domain and that the domain is verified.

**Identity headers not reaching the app.**
The proxy must both *capture* the `X-Forwarded-*` headers from the auth response
and *set* them on the upstream request. nginx needs the `auth_request_set` +
`proxy_set_header` pair; Traefik needs each header listed under
`authResponseHeaders`; Caddy needs them in `copy_headers`. Also confirm the proxy
app's forwarded-header configuration enables the headers you expect.

**Infinite redirect loop after sign-in.**
Usually a clock skew or a too-short cookie path/domain. Confirm the server clock is
correct (the token is short-lived) and that the cookie is being set for the full
protected domain, not just the portal host.

**Certificate not issued for the portal host.**
On-demand TLS only admits **verified** protected domains. Confirm the domain shows
as verified, the portal host's DNS A/AAAA record points at your WeftID instance,
and ports 80/443 are reachable for the HTTP-01 challenge.

**403 for a user who should have access.**
Access uses the same group model as SAML service providers. Check that the user is
in a group granted to the proxy app (or a descendant of one), or that the app is
marked available to all. `/check` re-checks per-app access on every request (the
per-domain cookie is identity-only and shared across the whole domain), so a 403
can be surfaced both during the sign-in handshake and on `/check` itself.

**App receives WeftID's cookie.**
You did not strip the `Cookie` header before proxying upstream. See
[Strip the cookie](#strip-the-forward-auth-cookie).
