# Loom - Multi-tenant FastAPI Application

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
make test            # Run tests
make lint            # Check code quality
make format          # Auto-format code
make typecheck       # Type checking
```

### Database
```bash
make sql-migrations  # Run pending migrations
```

## Project Structure

```
loom/
├── app/                 # Application code
│   ├── main.py          # FastAPI app
│   ├── settings.py      # Configuration
│   ├── database.py      # Database utilities
│   ├── dependencies.py  # FastAPI dependencies
│   ├── routers/         # API routes
│   ├── dev/             # Dev utilities
│   └── utils/           # Helper functions
├── tests/               # Test suite
├── sql-migrations/      # Database migrations
├── docker-compose.yml   # Docker services
└── Makefile             # Dev commands
```

## Documentation

See [REFACTORING.md](REFACTORING.md) for details on recent organizational improvements.
