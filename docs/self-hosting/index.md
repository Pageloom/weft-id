# Self-Hosting

Deploy WeftId on your own infrastructure using Docker Compose.

## Docker Image

Production images are published to GitHub Container Registry:

```
ghcr.io/pageloom/weft-id
```

Available tags:

* `1.0.0` — exact version (recommended for production)
* `1.0` — latest patch for a minor version
* `1` — latest minor for a major version
* `latest` — newest stable release

Pull the image directly or reference it in your compose file instead of building
from source.

## Requirements

- Docker and Docker Compose
- PostgreSQL 16+
- A reverse proxy with TLS (nginx included in the Docker setup)
- An SMTP server or email service (Resend, SendGrid)

## Services

| Service | Purpose |
|---------|---------|
| **app** | FastAPI web application |
| **worker** | Background job processor |
| **db** | PostgreSQL database |
| **memcached** | Session and cache storage |
| **reverse-proxy** | Nginx for TLS termination |
| **migrate** | One-shot schema migration runner |

## Configuration

WeftId is configured through environment variables.

### Required

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Master encryption key. All derived keys (sessions, two-step verification, SAML, email) use HKDF from this value. Generate a random 64-character string. |
| `BASE_DOMAIN` | Base domain for tenant subdomains (e.g., `weftid.example.com`) |
| `POSTGRES_USER` | Database user |
| `POSTGRES_PASSWORD` | Database password |
| `POSTGRES_DB` | Database name (default: `appdb`) |

### Email

| Variable | Description |
|----------|-------------|
| `EMAIL_BACKEND` | Email provider: `smtp`, `resend`, or `sendgrid` |
| `SMTP_HOST` | SMTP server hostname |
| `SMTP_PORT` | SMTP port |
| `SMTP_USER` | SMTP username (optional) |
| `SMTP_PASS` | SMTP password (optional) |
| `SMTP_TLS` | Enable TLS (`true` or `false`) |
| `FROM_EMAIL` | Sender email address |
| `RESEND_API_KEY` | Resend API key (if using Resend) |
| `SENDGRID_API_KEY` | SendGrid API key (if using SendGrid) |

### Optional

| Variable | Description | Default |
|----------|-------------|---------|
| `ENABLE_OPENAPI_DOCS` | Enable Swagger UI and ReDoc at `/api/docs` | `false` |

## Database

The database schema is applied automatically on first startup. The `migrate` service runs the baseline schema followed by any pending migrations.

Subsequent schema changes are applied automatically when you restart with a new version. Migrations are forward-only and logged to the `schema_migration_log` table.

## Getting started

1. Copy the example environment file and fill in your values
2. Run `docker compose up -d`
3. The `migrate` service initializes the database
4. Access WeftId at your configured domain
5. The first user to sign in becomes the super admin
