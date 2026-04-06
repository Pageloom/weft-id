COMPOSE := docker compose --project-directory . -f dev/docker-compose.yml
TAILWIND_BIN := tailwindcss-macos-arm64

.DEFAULT_GOAL := help
.PHONY: help status up down db-init migrate prune restart logs logs-% up-% sh-% build-css watch-css watch-tests seed-sso seed-dev test e2e check fix quality-all coverage docs

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
build-css: ## Build Tailwind CSS for production
	./$(TAILWIND_BIN) --config dev/tailwind.config.js -i static/css/input.css -o static/css/output.css --minify

watch-css: ## Watch and rebuild CSS on changes (dev mode)
	./$(TAILWIND_BIN) --config dev/tailwind.config.js -i static/css/input.css -o static/css/output.css --watch

watch-tests: ## Watch and rerun tests on changes (dev mode)
	poetry run python -m watchfiles 'poetry run python -m pytest --testmon' app tests

seed-sso: ## Set up cross-tenant SSO test bed (dev <-> sp-test)
	$(COMPOSE) exec app python ./dev/sso_testbed.py

seed-dev: ## Seed dev environment with Meridian Health sample data
	$(COMPOSE) exec app python ./dev/seed_dev.py

## Docs
docs: ## Build documentation site (output in site/)
	poetry run zensical build

## Quality
test: ## Run all tests (pass args: make test ARGS="-v -k my_test")
	poetry run python -m pytest $(ARGS)

e2e: ## Run E2E tests (pass args: make e2e ARGS="--headed")
	poetry run python -m pytest tests/e2e/ -n 0 -v --tb=short $(ARGS)

check: ## Run code quality checks (lint, format, types, compliance)
	@echo "=== Lint ===" && poetry run ruff check app/ tests/ \
	&& echo "" && echo "=== Formatting ===" && poetry run ruff format --check app/ tests/ \
	&& echo "" && echo "=== Type Check ===" && poetry run python -m mypy app/ \
	&& echo "" && echo "=== Compliance Check ===" && python dev/compliance_check.py \
	&& echo "" && echo "=== Dependency Security ===" && python dev/deps_check.py

fix: ## Auto-fix lint/format, then check types and compliance
	@echo "=== Lint ===" && poetry run ruff check --fix app/ tests/ \
	&& echo "" && echo "=== Formatting ===" && poetry run ruff format app/ tests/ \
	&& echo "" && echo "=== Type Check ===" && poetry run python -m mypy app/ \
	&& echo "" && echo "=== Compliance Check ===" && python dev/compliance_check.py \
	&& echo "" && echo "=== Dependency Security ===" && python dev/deps_check.py

quality-all: ## Run all QA: code quality + unit tests + E2E tests
	$(MAKE) check && $(MAKE) test && $(MAKE) e2e

coverage: ## Combined coverage report (unit + E2E, pass ARGS="--html" for HTML)
	@COV_DIR=$$(mktemp -d) && trap 'rm -rf "$$COV_DIR"' EXIT \
	&& rm -f .coverage \
	&& echo "=== Running unit tests with coverage ===" \
	&& COVERAGE_FILE="$$COV_DIR/.coverage.unit" poetry run python -m pytest --cov=app --cov-report= -q --no-header \
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
