# Self-Hosting

Deploy WeftID on your own infrastructure with Docker Compose and Caddy.

## Prerequisites

* Docker Engine 24+ and Docker Compose v2
* A domain name with DNS access (you will create an A record and a wildcard record)
* A server with ports 80 and 443 open (for HTTPS via Let's Encrypt)
* An SMTP server or email API service (Resend, SendGrid) for invitations and verification codes

## 1. Set up DNS

Before installing, point two DNS records at your server. Each tenant gets its own subdomain
(for example, `acme.id.example.com`), and the wildcard record ensures all subdomains resolve.

| Record | Name | Value |
|--------|------|-------|
| A | `id.example.com` | your server IP |
| A (wildcard) | `*.id.example.com` | your server IP |

Replace `id.example.com` with your chosen domain. Set this up first so DNS has time to
propagate while you configure the rest.

!!! tip
    TLS certificates are separate from DNS. Caddy obtains a per-subdomain certificate
    automatically via Let's Encrypt (see [TLS and reverse proxy](#tls-and-reverse-proxy)).
    You do not need a wildcard certificate.

## 2. Install

Choose a directory for your WeftID installation. All configuration files live here, and you
will run `docker compose` commands from this directory.

```bash
mkdir -p /opt/weftid && cd /opt/weftid
```

Then run the install script, which downloads the production files, generates secrets, and walks
you through initial configuration:

```bash
curl -sSL https://raw.githubusercontent.com/pageloom/weft-id/main/deploy/install.sh | bash
```

This creates three files in the current directory:

* `docker-compose.yml` -- service definitions (downloaded from `deploy/docker-compose.yml` in the repo)
* `Caddyfile` -- reverse proxy with automatic HTTPS
* `.env` -- your configuration (secrets, domain, SMTP)

The script asks for your domain and SMTP settings interactively. If you use SendGrid or Resend
instead of SMTP, press Enter to skip the SMTP prompts. Then edit `.env` to configure your
email backend (see [Email configuration](#email)).

??? note "Manual install"
    If you prefer not to pipe a script, download the files yourself:

    ```bash
    # Download production compose file and rename so docker compose finds it by default
    curl -fsSL https://raw.githubusercontent.com/pageloom/weft-id/main/deploy/docker-compose.yml \
      -o docker-compose.yml
    curl -fsSL https://raw.githubusercontent.com/pageloom/weft-id/main/deploy/Caddyfile -o Caddyfile

    # Copy and edit .env
    curl -fsSL https://raw.githubusercontent.com/pageloom/weft-id/main/deploy/.env.example -o .env
    ```

    Then edit `.env` to fill in all required values. Generate secrets with `openssl rand -base64 32`.

## 3. Configure email {: #email }

Email delivery is required for user invitations, verification codes, and lifecycle
notifications. The install script writes SMTP settings by default. If you use a different
provider, edit `.env` before starting the services.

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

## 4. Start the services

```bash
docker compose up -d
```

On first start, the `migrate` service applies the database schema, then the app starts. Caddy
obtains a TLS certificate for each subdomain automatically as tenants are first accessed.

Check that everything is running:

```bash
docker compose ps
```

All services should show as healthy. If the migrate service failed, check its logs:

```bash
docker compose logs migrate
```

## 5. Verify email delivery

Before provisioning a tenant, verify that email delivery is working. The founding super admin
receives an invitation email, so broken email configuration means they cannot complete setup.

```bash
docker compose exec app python -m app.cli.verify_email --to you@example.com
```

Replace `you@example.com` with an address you can check. The command:

* Sends a test email through the configured backend (SMTP, SendGrid, or Resend)
* Checks DNS records (SPF, DKIM, DMARC) for the `FROM_EMAIL` domain and reports any issues

If the email arrives and DNS checks look good, proceed to tenant provisioning. DNS warnings
are informational and do not block the command. Fix any issues flagged before going to
production to improve deliverability.

## 6. Provision your first tenant

Once the services are running, create a tenant and its founding super admin:

```bash
docker compose exec app python -m app.cli.provision_tenant \
  --subdomain acme \
  --tenant-name "Acme Corp" \
  --email admin@acme.com \
  --first-name Jane \
  --last-name Smith
```

Replace the values with your actual subdomain, tenant name, and super admin details. The
command provisions the tenant and sends an invitation email.

The super admin receives an invitation email with a link to verify their email address and set
a password. This also validates that email delivery is working.

!!! note
    If email delivery fails, the command prints a warning and the verification URL as a
    fallback. Fix your email settings in `.env`, run `docker compose restart`, and visit the
    printed URL to continue setup.

To add more tenants later, run the same command with a different subdomain and tenant name.
If the subdomain already exists, the command reuses the existing tenant and adds a new super
admin.

---

## Upgrading

### Before you upgrade

Always back up before upgrading. Migrations change the database schema and cannot be reversed
automatically. Follow the steps in [Backups](#backups) to create a full backup (database roles,
data, and file storage).

Check available versions at
[github.com/pageloom/weft-id/releases](https://github.com/pageloom/weft-id/releases)
before proceeding. See the [versioning policy](../VERSIONING.md) for what to expect from
patch, minor, and major releases.

### Upgrade procedure

1. Edit `.env` and set `WEFT_VERSION` to the target version (e.g., `1.3.0`).

2. Pull the new image and restart:

    ```bash
    docker compose pull
    docker compose up -d
    ```

    The `migrate` service runs automatically and applies any pending schema migrations before
    the app starts. If a migration fails, the migrate service exits non-zero and the app will
    not start. Check migration logs with `docker compose logs migrate`.

3. Verify the services are healthy:

    ```bash
    docker compose ps
    ```

### Rolling back

Migrations are forward-only. If an upgrade causes problems, restore from the backup you
created before upgrading.

!!! warning
    Rollback is a destructive operation. The current database is deleted and replaced with
    the backup. Any data created or changed since the backup (users, settings, audit logs)
    will be lost. This cannot be undone.

1. Stop all services:

    ```bash
    docker compose down
    ```

2. Remove the database volume:

    ```bash
    docker volume rm "$(docker volume ls -q --filter name=_dbdata | head -1)"
    ```

3. Edit `.env` and set `WEFT_VERSION` back to the previous version (e.g., `1.2.0`).

4. Start the database and wait for it to be ready:

    ```bash
    docker compose up -d db
    # Wait for the database to accept connections
    until docker compose exec -T db pg_isready -U postgres; do sleep 1; done
    ```

5. Restore roles and data:

    ```bash
    docker compose exec -T db psql -U postgres < roles-backup.sql
    docker compose exec -T db psql -U postgres appdb < data-backup.sql
    ```

6. If you backed up file storage, restore it:

    ```bash
    docker run --rm \
      -v "$(docker volume ls -q --filter name=_storage | head -1):/data" \
      -v "$(pwd):/backup" \
      alpine sh -c "rm -rf /data/* && tar xzf /backup/storage-backup.tar.gz -C /data"
    ```

7. Start all services:

    ```bash
    docker compose up -d
    ```

## Backups

Back up regularly. At a minimum, back up before every upgrade. The commands below create
backup files in the current directory.

### Database

```bash
# Roles (required for restoring onto a fresh database)
docker compose exec -T db \
  pg_dumpall -U postgres --roles-only > roles-backup.sql

# Full database dump
docker compose exec -T db \
  pg_dump -U postgres appdb > data-backup.sql

# Restrict permissions (backups contain password hashes, PII)
chmod 600 roles-backup.sql data-backup.sql
```

### File storage

If you use local file storage (the default), back up the storage volume. The command below
finds the compose project's storage volume by name and archives its contents:

```bash
docker run --rm \
  -v "$(docker volume ls -q --filter name=_storage | head -1):/data" \
  -v "$(pwd):/backup" \
  alpine tar czf /backup/storage-backup.tar.gz -C /data .
```

### Restoring

To restore onto a fresh database, apply roles first, then data:

```bash
docker compose exec -T db \
  psql -U postgres < roles-backup.sql

docker compose exec -T db \
  psql -U postgres appdb < data-backup.sql
```

### Configuration

Your `.env` file contains `SECRET_KEY` (the master encryption key), `POSTGRES_PASSWORD`, and
`APPUSER_PASSWORD`. These cannot be recovered or regenerated. Losing `SECRET_KEY` invalidates
all active sessions, two-step verification secrets, and SAML signing keys. Losing either
database password locks you out of the database.

Store a copy of `.env` somewhere secure outside the server (for example, in a password manager
or an encrypted vault). Do not commit it to version control.

## Monitoring

### Health check

The app exposes a health endpoint at `/healthz` that returns:

* **200** -- app is healthy and the database is reachable
* **503** -- database is unreachable

This endpoint bypasses tenant resolution (no subdomain required) and needs no authentication.
Use it for load balancer probes or uptime monitoring:

```bash
curl -s -o /dev/null -w "%{http_code}" https://id.example.com/healthz
```

### Logs

View logs for all services or a specific one:

```bash
# All services
docker compose logs -f

# App only
docker compose logs -f app

# Migration output
docker compose logs migrate
```

### Migration status

Check which migrations have been applied:

```bash
docker compose exec -T db \
  psql -U postgres -d appdb \
  -c "SELECT version, status, started_at, completed_at FROM schema_migration_log ORDER BY id"
```

---

## Reference

### Architecture

The production stack has six services:

| Service | Image | Purpose |
|---------|-------|---------|
| **caddy** | `caddy:2-alpine` | Reverse proxy with automatic HTTPS (Let's Encrypt) |
| **app** | `ghcr.io/pageloom/weft-id` | Web application (FastAPI) |
| **worker** | `ghcr.io/pageloom/weft-id` | Background job processor |
| **db** | `postgres:18-alpine` | PostgreSQL database |
| **memcached** | `memcached:1.6-alpine` | Activity cache |
| **migrate** | `ghcr.io/pageloom/weft-id` | One-shot schema migration runner |

The `migrate` service runs before `app` starts and exits when done. The `app` service has a
health check that Caddy waits for before routing traffic. The `app` and `worker` containers
run as a non-root user for defense in depth.

### Docker image

Production images are published to GitHub Container Registry:

```
ghcr.io/pageloom/weft-id
```

Available tags:

* `1.3.0` -- exact version (recommended for production)
* `1.3` -- latest patch for a minor version
* `1` -- latest minor for a major version
* `latest` -- newest stable release

### Configuration reference

All configuration is in `.env`. The install script generates this file interactively, or you
can copy `deploy/.env.example` and edit it manually.

#### Required variables

| Variable | Description |
|----------|-------------|
| `WEFT_VERSION` | Image tag to run (e.g., `1.3.0`). Pin to a specific version for stability. |
| `BASE_DOMAIN` | Root domain for tenant subdomains (e.g., `id.example.com`) |
| `SECRET_KEY` | Master encryption key. Session signing, two-step verification secrets, SAML key encryption, and email verification tokens are all derived from this value via HKDF. Generate with `openssl rand -base64 32`. |
| `POSTGRES_PASSWORD` | Password for the PostgreSQL superuser. Generate with `openssl rand -base64 32`. |
| `APPUSER_PASSWORD` | Password for the `appuser` database role (used by the app at runtime). The install script generates this automatically. |

#### Optional variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ENABLE_OPENAPI_DOCS` | Show Swagger UI at `/api/docs` | `false` |
| `STORAGE_BACKEND` | File storage: `local` or `spaces` (DigitalOcean Spaces) | `local` |

#### Security defaults

The following settings default to secure values when not set. They are intentionally omitted
from the production compose file and `.env`:

* `IS_DEV` defaults to `False` (enforces production security validation)
* `BYPASS_OTP` defaults to `false` (ensures verification codes are always checked)

If either is set to `true` with `IS_DEV=False`, the app refuses to start.

The install script sets `.env` file permissions to `600` (owner read/write only) to protect
secrets from other users on the system.

### Database

#### Schema management

The `migrate` service runs automatically on every `docker compose up`. It applies the baseline
schema on a fresh database and any pending migrations on an existing one. Migrations are
forward-only and logged in the `schema_migration_log` table.

The migrate service connects as the PostgreSQL superuser (`postgres`). The app connects as
`appuser`, a restricted role created by the baseline schema that enforces row-level security.

### TLS and reverse proxy

Caddy handles TLS automatically using Let's Encrypt HTTP-01 challenges. It uses on-demand TLS,
which means it obtains a separate certificate for each tenant subdomain on first access. This
is not a wildcard certificate. The wildcard DNS record (see [Set up DNS](#1-set-up-dns)) handles
routing only. No DNS provider API integration is needed.

Before issuing a certificate, Caddy validates the requested subdomain against WeftID's tenant
registry. Only direct subdomains of the base domain that correspond to an existing tenant are
allowed. This prevents abuse of the on-demand TLS feature (e.g., an attacker triggering
certificate requests for arbitrary subdomains).

Requirements for automatic HTTPS:

* Ports 80 and 443 must be reachable from the internet
* DNS must resolve both the apex domain and wildcard subdomains to your server
* No other process can be listening on ports 80 or 443

The `Caddyfile` is downloaded by the install script. You should not need to modify it for
standard deployments.
