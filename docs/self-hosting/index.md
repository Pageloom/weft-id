# Self-Hosting

Deploy WeftId on your own infrastructure with Docker Compose and Caddy.

## Prerequisites

* Docker Engine 24+ and Docker Compose v2
* A domain name with DNS access (you will create an A record and a wildcard record)
* A server with ports 80 and 443 open (for HTTPS via Let's Encrypt)
* An SMTP server or email API service (Resend, SendGrid) for invitations and MFA codes

## Quick start

The install script downloads the production files, generates secrets, and walks you through
initial configuration:

```bash
curl -sSL https://raw.githubusercontent.com/pageloom/weft-id/main/install.sh | bash
```

This creates three files in the current directory:

* `docker-compose.production.yml` — service definitions
* `Caddyfile` — reverse proxy with automatic HTTPS
* `.env` — your configuration (secrets, domain, SMTP)

### DNS setup

Before starting, point two DNS records at your server:

| Record | Name | Value |
|--------|------|-------|
| A | `id.example.com` | your server IP |
| A (wildcard) | `*.id.example.com` | your server IP |

Replace `id.example.com` with your chosen `BASE_DOMAIN`. Each tenant gets its own subdomain
(for example, `acme.id.example.com`). The wildcard DNS record ensures all subdomains resolve
to your server. TLS certificates are handled separately by Caddy (see
[TLS and reverse proxy](#tls-and-reverse-proxy)).

### Start the services

```bash
docker compose -f docker-compose.production.yml up -d
```

On first start, the `migrate` service applies the database schema, then the app starts. Caddy
obtains a TLS certificate for each subdomain automatically via Let's Encrypt as tenants are
first accessed.

### Provision your first tenant

Once the services are running, create a tenant and its founding super admin:

```bash
docker compose -f docker-compose.production.yml exec app \
  python -m app.cli.provision_tenant \
    --subdomain acme \
    --tenant-name "Acme Corp" \
    --email admin@acme.com \
    --first-name Jane \
    --last-name Smith
```

The super admin receives an invitation email with a link to verify their email address and set
a password. This also validates that email delivery is working before the admin gains access.

!!! note
    If email delivery fails, the command prints a warning and the verification URL as a
    fallback. Fix your SMTP settings in `.env`, restart the app, and visit the printed URL
    to continue setup.

## Architecture

The production stack has six services:

| Service | Image | Purpose |
|---------|-------|---------|
| **caddy** | `caddy:2-alpine` | Reverse proxy with automatic HTTPS (Let's Encrypt) |
| **app** | `ghcr.io/pageloom/weft-id` | Web application (FastAPI) |
| **worker** | `ghcr.io/pageloom/weft-id` | Background job processor |
| **db** | `postgres:16-alpine` | PostgreSQL database |
| **memcached** | `memcached:1.6-alpine` | Activity cache |
| **migrate** | `ghcr.io/pageloom/weft-id` | One-shot schema migration runner |

The `migrate` service runs before `app` starts and exits when done. The `app` service has a
health check that Caddy waits for before routing traffic.

### Docker image

Production images are published to GitHub Container Registry:

```
ghcr.io/pageloom/weft-id
```

Available tags:

* `1.0.0` — exact version (recommended for production)
* `1.0` — latest patch for a minor version
* `1` — latest minor for a major version
* `latest` — newest stable release

## Configuration

All configuration is in `.env`. The install script generates this file interactively, or you
can copy `.env.production.example` and edit it manually.

### Required variables

| Variable | Description |
|----------|-------------|
| `WEFT_VERSION` | Image tag to run (e.g., `1.0.0`). Pin to a specific version for stability. |
| `BASE_DOMAIN` | Root domain for tenant subdomains (e.g., `id.example.com`) |
| `SECRET_KEY` | Master encryption key. Session signing, MFA secrets, SAML key encryption, and email verification tokens are all derived from this value via HKDF. Generate with `openssl rand -base64 32`. |
| `POSTGRES_PASSWORD` | Password for the PostgreSQL superuser. Generate with `openssl rand -base64 32`. |

### Email

Email delivery is required for user invitations, MFA verification codes, and lifecycle
notifications. Choose one backend:

=== "SMTP"

    ```ini
    EMAIL_BACKEND=smtp
    SMTP_HOST=smtp.example.com
    SMTP_PORT=587
    SMTP_USER=apikey
    SMTP_PASS=your-password
    SMTP_TLS=true
    FROM_EMAIL=no-reply@example.com
    ```

    Works with any SMTP provider (Mailgun, Amazon SES, Postfix, etc.).

=== "SendGrid"

    ```ini
    EMAIL_BACKEND=sendgrid
    SENDGRID_API_KEY=SG.xxxxx
    FROM_EMAIL=no-reply@example.com
    ```

    Uses the SendGrid HTTP API. No SMTP configuration needed. Useful on cloud platforms that
    block outbound SMTP ports.

=== "Resend"

    ```ini
    EMAIL_BACKEND=resend
    RESEND_API_KEY=re_xxxxx
    FROM_EMAIL=no-reply@example.com
    ```

    Uses the Resend HTTP API. No SMTP configuration needed.

### Optional variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ENABLE_OPENAPI_DOCS` | Show Swagger UI at `/api/docs` | `false` |
| `STORAGE_BACKEND` | File storage: `local` or `spaces` (DigitalOcean Spaces) | `local` |

### Security defaults

These are set by the production compose file and `.env.production.example`. Do not change them:

| Variable | Value | Purpose |
|----------|-------|---------|
| `IS_DEV` | `False` | Enforces production security validation |
| `BYPASS_OTP` | `false` | Ensures MFA codes are always verified |

## Database

### Schema management

The `migrate` service runs automatically on every `docker compose up`. It applies the baseline
schema on a fresh database and any pending migrations on an existing one. Migrations are
forward-only and logged in the `schema_migration_log` table.

The migrate service connects as the PostgreSQL superuser (`postgres`). The app connects as
`appuser`, a restricted role created by the baseline schema that enforces row-level security.

### Checking migration status

```bash
docker compose -f docker-compose.production.yml exec db \
  psql -U postgres -d appdb \
  -c "SELECT version, status, started_at, completed_at FROM schema_migration_log ORDER BY id"
```

## Upgrading

### Standard upgrade procedure

1. Check the [changelog](https://github.com/pageloom/weft-id/releases) for the target version
2. Edit `WEFT_VERSION` in `.env` to the new version
3. Pull the new image and restart:

```bash
docker compose -f docker-compose.production.yml pull
docker compose -f docker-compose.production.yml up -d
```

The `migrate` service runs automatically and applies any pending schema migrations before the
app starts. If a migration fails, the migrate service exits non-zero and the app will not start.
Fix the issue (check migration logs) and retry.

### Rollback considerations

Migrations are forward-only. Rolling back the image version works only if the new database
schema is backward-compatible with the old application code. This is generally true within a
minor version (1.1 to 1.0), but not guaranteed across major versions (2.0 to 1.x).

Before upgrading across a major version, back up your database (see below).

## Backups

### Database

Use `pg_dump` to create a full database backup:

```bash
docker compose -f docker-compose.production.yml exec db \
  pg_dump -U postgres appdb > backup-$(date +%Y%m%d).sql
```

To restore:

```bash
docker compose -f docker-compose.production.yml exec -T db \
  psql -U postgres appdb < backup-20250315.sql
```

### File storage

If using local storage (the default), the `storage` Docker volume contains uploaded files
(logos, exports). Back it up alongside the database:

```bash
# Replace <project> with your compose project name (usually the directory name)
docker run --rm \
  -v <project>_storage:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/storage-$(date +%Y%m%d).tar.gz -C /data .
```

To find the volume name, run `docker volume ls | grep storage`.

### Configuration

Keep a copy of your `.env` file. It contains your secrets and all configuration. Losing
`SECRET_KEY` invalidates all active sessions, MFA secrets, and SAML signing keys.

## Monitoring

### Health check

The app exposes a health endpoint at `/healthz` that returns:

* **200** — app is healthy and the database is reachable
* **503** — database is unreachable

This endpoint bypasses tenant resolution (no subdomain required) and needs no authentication.
Use it for load balancer probes or uptime monitoring:

```bash
curl -s -o /dev/null -w "%{http_code}" https://id.example.com/healthz
```

### Logs

View logs for all services or a specific one:

```bash
# All services
docker compose -f docker-compose.production.yml logs -f

# App only
docker compose -f docker-compose.production.yml logs -f app

# Migration output
docker compose -f docker-compose.production.yml logs migrate
```

### Service status

```bash
docker compose -f docker-compose.production.yml ps
```

## Provisioning additional tenants

Use the same CLI command to create additional tenants:

```bash
docker compose -f docker-compose.production.yml exec app \
  python -m app.cli.provision_tenant \
    --subdomain newcorp \
    --tenant-name "New Corp" \
    --email admin@newcorp.com \
    --first-name Alice \
    --last-name Johnson
```

If the subdomain already exists, the command reuses the existing tenant and adds a new super
admin to it. If the email already exists in that tenant, the command exits with an error.

## TLS and reverse proxy

Caddy handles TLS automatically using Let's Encrypt HTTP-01 challenges. It uses on-demand TLS,
which means it obtains a separate certificate for each tenant subdomain on first access. This
is not a wildcard certificate. The wildcard DNS record (see [DNS setup](#dns-setup)) handles
routing only. No DNS provider API integration is needed.

Requirements for automatic HTTPS:

* Ports 80 and 443 must be reachable from the internet
* DNS must resolve both the apex domain and wildcard subdomains to your server
* No other process can be listening on ports 80 or 443

The `Caddyfile` is downloaded by the install script. You should not need to modify it for
standard deployments.
