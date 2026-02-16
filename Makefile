COMPOSE := docker compose
WAIT_TIMEOUT ?= 60
TAILWIND_BIN := tailwindcss-macos-arm64

.DEFAULT_GOAL := help
.PHONY: help status up down db-reset db-init migrate migrate-onprem prune ps restart-% logs logs-% up-% exec-% sh-% build-css watch-css sso-testbed

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

up: ## Build and start all services (detached)
	$(COMPOSE) up --build -d

up-onprem: ## Build and start all onprem services (detached)
	$(COMPOSE) -f docker-compose.onprem.yml up --build -d

down: ## Stop and remove containers (keep volumes)
	$(COMPOSE) down --remove-orphans

db-reset: ## Wipe DB volume to force full reinit
	$(COMPOSE) down -v

db-init: db-reset up ## Wipe DB and restart (runs baseline + migrations)

migrate: ## Run pending migrations on running dev DB
	$(COMPOSE) run --rm migrate

migrate-onprem: ## Run pending migrations on running onprem DB
	$(COMPOSE) -f docker-compose.onprem.yml --profile migrate run --rm migrate

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

build-css: ## Build Tailwind CSS for production
	./$(TAILWIND_BIN) -i static/css/input.css -o static/css/output.css --minify

watch-css: ## Watch and rebuild CSS on changes (dev mode)
	./$(TAILWIND_BIN) -i static/css/input.css -o static/css/output.css --watch

sso-testbed: ## Set up cross-tenant SSO test bed (dev <-> sp-test)
	$(COMPOSE) exec app python ./dev/sso_testbed.py


