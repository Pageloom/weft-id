COMPOSE := docker compose
WAIT_TIMEOUT ?= 60
POETRY := poetry

.DEFAULT_GOAL := help
.PHONY: help status sql-migrations up down reset prune ps restart-% logs logs-% up-% exec-% sh-% wait-% test lint format

help:
	@awk 'BEGIN{FS=":.*##"; printf "\nDev targets:\n"} /^[a-zA-Z0-9\-\_%]+:.*##/ {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

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

sql-migrations: ## Run pending SQL migrations
	$(COMPOSE) up db-setup

up: ## Build and start all services (detached)
	$(COMPOSE) up --build -d

down: ## Stop and remove containers (keep volumes)
	$(COMPOSE) down --remove-orphans

reset: ## Stop and remove containers + volumes (DB wiped)
	$(COMPOSE) down -v

prune: ## Docker prune (containers/images/networks not in use)
	docker system prune -f

ps: ## Show compose status
	$(COMPOSE) ps

restart-%: ## Restart a specific service. Example: make restart-app
	$(COMPOSE) restart $*

logs: ## Tail logs for all services
	$(COMPOSE) logs -f --tail=200

logs-%: ## Tail logs for one service. Example: make logs-app
	$(COMPOSE) logs -f --tail=200 $*

up-%: ## Rebuild+start just one service (no deps). Example: make up-app
	$(COMPOSE) up -d --build --no-deps $*

sh-%: ## Open a shell to a service. Example: make sh-app
	-$(COMPOSE) exec $* bash || $(COMPOSE) exec $* sh

test: ## Run tests with pytest
	$(POETRY) run pytest

lint: ## Run linting with ruff
	$(POETRY) run ruff check app/ tests/

format: ## Format code with black and ruff
	$(POETRY) run black app/ tests/
	$(POETRY) run ruff check --fix app/ tests/

typecheck: ## Run type checking with mypy
	$(POETRY) run mypy app/

