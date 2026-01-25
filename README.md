# Weft-ID - Identity Federation Layer

Weft-ID is a federation layer that aggregates multiple identity providers into a single, unified interface. It acts as a middleware between your applications and identity systems like Okta, Microsoft Entra ID, Google Workspace, and other SAML/OIDC-compliant providers.

## Setting up a dev-environment

### Prerequisites
- Docker & Docker Compose
- Poetry (for local development)
- mkcert (for local TLS certificates)
  ```bash
  brew install mkcert
  ```
  **Firefox users**: Also install NSS tools for Firefox support, then re-run the cert generation script:
  ```bash
  brew install nss
  ```

### Setup Steps

1. Clone the repo

2. Install dependencies with Poetry (creates `.venv` in project root)
   ```bash
   poetry install
   ```
   **Note**: Poetry is configured to create the virtual environment in `.venv/` at the project root for easy IDE integration.

3. Configure your IDE
   - Point your IDE's Python interpreter to `.venv/bin/python`
   - This should auto-detect in most IDEs (VS Code, PyCharm, etc.)
   - Verify it's using Python 3.12: `poetry run python --version`

4. Generate dev-env certificates
   ```bash
   ./devscripts/mkcert.sh
   ```
   **Note**: This will prompt for your password to install the local certificate authority.

5. Generate an .env file
   ```bash
   cp .env.dev.example .env
   ```

6. Run the app
   ```bash
   make up
   ```

7. Open your browser at https://dev.pageloom.localhost
   (A dev tenant has been automatically provisioned for you)

## Development Commands

### Docker Services
```bash
make up              # Start all services
make down            # Stop services
make reset           # Reset (delete volumes)
make logs            # View all logs
make logs-app        # View app logs
make sh-app          # Shell into app container
```

### Testing & Code Quality
```bash
./test                                      # Run tests (shorthand)
poetry run python -m pytest                 # Run tests (full command)
poetry run ruff check --fix app/ tests/     # Lint and auto-fix
poetry run black app/ tests/                # Format code
poetry run mypy app/                        # Type checking
```

### Frontend/CSS Development
```bash
make build-css       # Build Tailwind CSS after template changes
make watch-css       # Auto-rebuild CSS when templates change (recommended)
```

**Tip**: When actively working on templates/UI, run `make watch-css` in a separate terminal. It will automatically rebuild the CSS whenever you modify any template file.

