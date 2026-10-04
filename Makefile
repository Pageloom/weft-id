COMPOSE := docker compose --project-directory . -f dev/docker-compose.yml

TAILWIND_VERSION := 3.4.17
ifeq ($(shell uname -s),Darwin)
  TAILWIND_BIN := tailwindcss-macos-$(if $(filter arm64,$(shell uname -m)),arm64,x64)
else
  TAILWIND_BIN := tailwindcss-linux-$(if $(filter aarch64,$(shell uname -m)),arm64,x64)
endif
TAILWIND_URL := https://github.com/tailwindlabs/tailwindcss/releases/download/v$(TAILWIND_VERSION)/$(TAILWIND_BIN)

.DEFAULT_GOAL := help
.PHONY: help status up down db-init migrate prune restart logs logs-% up-% sh-% build-css watch-css watch-tests seed-sso seed-dev scim-testbed-up scim-testbed-down scim-testbed-destroy scim-testbed-info scim-testbed-status scim-testbed-logs oidc-conformance-up oidc-conformance-down oidc-conformance-destroy oidc-conformance-info oidc-conformance-status oidc-conformance-logs oidc-conformance oidc-conformance-report selfhost-smoke test-db test e2e check fix quality-all coverage docs release-tag

help:
	@awk 'BEGIN{FS=":.*##"} /^## /{printf "\n\033[1m%s\033[0m\n", substr($$0,4)} /^[a-zA-Z0-9\-\_%]+:.*##/ {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo

## Docker
status: ## Show up/down for all services
	@all="$$( $(COMPOSE) config --services )"; \
	run="$$( $(COMPOSE) ps --services --filter status=running )"; \
	for s in $$all; do \
	  if echo "$$run" | grep -Fqx "$$s"; then \
	    printf "%-16s %s\n" "$$s" "✅"; \
	  else \
	    printf "%-16s %s\n" "$$s" "❌"; \
	  fi; \
	done

up: ## Build and start all services (detached)
	$(COMPOSE) up --build -d

down: ## Stop and remove containers (keep volumes)
	$(COMPOSE) down --remove-orphans

db-init: ## Wipe DB and restart (runs baseline + migrations)
	$(COMPOSE) down -v && make up

migrate: ## Run pending migrations on running dev DB
	$(COMPOSE) run --rm migrate

prune: ## Docker prune (containers/images/networks not in use)
	docker system prune -f

restart: ## Restart all containers
	make down && make up

logs: ## Tail logs for all services
	$(COMPOSE) logs -f --tail=200

logs-%: ## Tail logs for one service. Example: make logs-app
	$(COMPOSE) logs -f --tail=200 $*

up-%: ## Rebuild+start just one service (no deps). Example: make up-app
	$(COMPOSE) up -d --build --no-deps $*

sh-%: ## Open a shell to a service. Example: make sh-app
	-$(COMPOSE) exec $* bash || $(COMPOSE) exec $* sh

## Dev
$(TAILWIND_BIN):
	@echo "Downloading Tailwind CSS v$(TAILWIND_VERSION) ($(TAILWIND_BIN))..."
	@curl -sLO $(TAILWIND_URL) && chmod +x $(TAILWIND_BIN)

build-css: $(TAILWIND_BIN) ## Build Tailwind CSS for production
	./$(TAILWIND_BIN) --config dev/tailwind.config.js -i static/css/input.css -o static/css/output.css --minify

watch-css: $(TAILWIND_BIN) ## Watch and rebuild CSS on changes (dev mode)
	./$(TAILWIND_BIN) --config dev/tailwind.config.js -i static/css/input.css -o static/css/output.css --watch

watch-tests: test-db ## Watch and rerun tests on changes (dev mode)
	POSTGRES_DB=$(TEST_DB) poetry run python -m watchfiles 'poetry run python -m pytest --testmon' app tests

seed-sso: ## Set up cross-tenant SSO test bed (dev <-> sp-test)
	$(COMPOSE) exec app python ./dev/sso_testbed.py

seed-dev: ## Seed dev environment with Meridian Health sample data
	$(COMPOSE) exec app python ./dev/seed_dev.py

## SCIM testbed (Authentik, runs OUTSIDE this repo by default)
scim-testbed-up: ## Start the SCIM testbed (Authentik) in ~/.local/share/weft-id/...
	./dev/scim-testbed.sh up

scim-testbed-down: ## Stop the SCIM testbed (keep its DB volume)
	./dev/scim-testbed.sh down

scim-testbed-destroy: ## Stop and wipe the SCIM testbed (volume + dir)
	./dev/scim-testbed.sh destroy

scim-testbed-info: ## Print URLs and the WeftID wire-up walkthrough
	./dev/scim-testbed.sh info

scim-testbed-status: ## Show status of SCIM testbed containers
	./dev/scim-testbed.sh status

scim-testbed-logs: ## Follow combined SCIM testbed logs
	./dev/scim-testbed.sh logs

## OIDC conformance suite (OpenID Foundation, runs OUTSIDE this repo by default)
oidc-conformance-up: ## Start the OIDC conformance suite (joins devnet; run 'make up' first)
	./dev/oidc-conformance.sh up

oidc-conformance-down: ## Stop the conformance suite (keep its Mongo data)
	./dev/oidc-conformance.sh down

oidc-conformance-destroy: ## Stop and wipe the conformance suite (data + dir)
	./dev/oidc-conformance.sh destroy

oidc-conformance-info: ## Print the suite URL and the run walkthrough
	./dev/oidc-conformance.sh info

oidc-conformance-status: ## Show status of conformance suite containers
	./dev/oidc-conformance.sh status

oidc-conformance-logs: ## Follow combined conformance suite logs
	./dev/oidc-conformance.sh logs

oidc-conformance: ## Run the OIDC conformance plans (pass args: ARGS="--verbose")
	poetry run python dev/oidc_conformance.py run $(ARGS)

oidc-conformance-report: ## Results table from the latest run (ARGS="--write-docs" updates the docs page)
	poetry run python dev/oidc_conformance_report.py $(ARGS)

## Self-hosting smoke test (throwaway install on high localhost ports)
selfhost-smoke: ## Install and verify self-hosting (VERSION=2.1.0 for a release, default: this checkout; ARGS="--upgrade-from 2.0.1")
	./dev/selfhost-smoke.sh $(or $(VERSION),local) $(ARGS)

## Docs
docs: ## Build documentation site (output in site/)
	poetry run zensical build

## Release
release-tag: ## Create the release tag from pyproject.toml (local only; prints the push command)
	./dev/release-tag.sh

## Quality
TEST_DB := appdb_test

test-db: ## Create/migrate the unit-test database (appdb_test, which the dev worker never touches)
	poetry run python dev/test_db.py

test: test-db ## Run all tests (pass args: make test ARGS="-v -k my_test")
	POSTGRES_DB=$(TEST_DB) poetry run python -m pytest $(ARGS)

e2e: ## Run E2E tests (pass args: make e2e ARGS="--headed")
	poetry run python -m pytest tests/e2e/ -n 0 -v --tb=short $(ARGS)

check: ## Run code quality checks (lint, format, types, compliance)
	@echo "=== Lint ===" && poetry run ruff check app/ tests/ \
	&& echo "" && echo "=== Formatting ===" && poetry run ruff format --check app/ tests/ \
	&& echo "" && echo "=== Type Check ===" && poetry run python -m mypy app/ \
	&& echo "" && echo "=== Compliance Check ===" && poetry run python -m dev.compliance_check \
	&& echo "" && echo "=== Dependency Security ===" && poetry run python -m dev.deps_check

fix: ## Auto-fix lint/format, then check types and compliance
	@echo "=== Lint ===" && poetry run ruff check --fix app/ tests/ \
	&& echo "" && echo "=== Formatting ===" && poetry run ruff format app/ tests/ \
	&& echo "" && echo "=== Type Check ===" && poetry run python -m mypy app/ \
	&& echo "" && echo "=== Compliance Check ===" && poetry run python -m dev.compliance_check \
	&& echo "" && echo "=== Dependency Security ===" && poetry run python -m dev.deps_check

quality-all: ## Run all QA: code quality + unit tests + E2E tests
	$(MAKE) check && $(MAKE) test && $(MAKE) e2e

coverage: ## Combined coverage report (unit + E2E, pass ARGS="--html" for HTML)
	@COV_DIR=$$(mktemp -d) && trap 'rm -rf "$$COV_DIR"' EXIT \
	&& rm -f .coverage \
	&& echo "=== Running unit tests with coverage ===" \
	&& poetry run python dev/test_db.py \
	&& POSTGRES_DB=$(TEST_DB) COVERAGE_FILE="$$COV_DIR/.coverage.unit" poetry run python -m pytest --cov=app --cov-report= -q --no-header \
	&& echo "" && echo "=== Running E2E tests with coverage ===" \
	&& COVERAGE_FILE="$$COV_DIR/.coverage.e2e" poetry run python -m pytest tests/e2e/ -n 0 --cov=app --cov-report= -q --no-header \
	&& echo "" && echo "=== Combining coverage data ===" \
	&& poetry run python -m coverage combine "$$COV_DIR/.coverage.unit" "$$COV_DIR/.coverage.e2e" \
	&& echo "" && echo "=== Combined Coverage Report ===" \
	&& poetry run python -m coverage report --show-missing \
	&& if echo "$(ARGS)" | grep -q -- "--html"; then \
	     echo "" && echo "=== Generating HTML report ===" \
	     && poetry run python -m coverage html \
	     && echo "HTML report written to htmlcov/index.html"; \
	   fi
