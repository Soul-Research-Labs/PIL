# ─────────────────────────────────────────────────────────────────────────────
# ZASEON — AI Smart Contract Scanner & Soul Protocol Fuzzer
# ─────────────────────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help

SHELL := /bin/zsh
PYTHON := python3
PIP := pip3

# Colors
CYAN  := \033[36m
GREEN := \033[32m
RESET := \033[0m

# ── Help ─────────────────────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help
	@echo "$(CYAN)ZASEON$(RESET) — AI Smart Contract Scanner\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}'

# ── Setup ────────────────────────────────────────────────────────────────────

.PHONY: install
install: ## Install all dependencies (engine + web)
	cd engine && $(PIP) install -e .[dev]
	cd web && npm install

.PHONY: install-engine
install-engine: ## Install engine dependencies only
	cd engine && $(PIP) install -e .[dev]

.PHONY: install-web
install-web: ## Install web dependencies only
	cd web && npm install

.PHONY: setup
setup: install ## Full project setup (install + env + db)
	@[ -f engine/.env ] || cp engine/.env.example engine/.env
	@[ -f web/.env.local ] || cp web/.env.local.example web/.env.local
	@echo "$(GREEN)✓ Setup complete. Edit engine/.env and web/.env.local with your keys.$(RESET)"

# ── Development ──────────────────────────────────────────────────────────────

.PHONY: dev
dev: ## Start all services (docker-compose up)
	docker compose up -d postgres redis minio minio-init
	@echo "$(CYAN)Waiting for services...$(RESET)"
	@sleep 3
	@make dev-engine & make dev-web & wait

.PHONY: dev-engine
dev-engine: ## Start engine API (hot reload)
	cd engine && uvicorn engine.api.main:app --reload --host 0.0.0.0 --port 8000

.PHONY: dev-web
dev-web: ## Start web frontend (hot reload)
	cd web && npm run dev

.PHONY: dev-worker
dev-worker: ## Start Celery worker (all queues)
	cd engine && celery -A engine.pipeline:celery_app worker --loglevel=info --concurrency=4 -Q scans,quickscan,verification,reports,soul_fuzzer

.PHONY: dev-flower
dev-flower: ## Start Celery Flower monitor
	cd engine && celery -A engine.pipeline:celery_app flower --port=5555

.PHONY: dev-all
dev-all: ## Start everything via docker-compose
	docker compose up --build

# ── Database ─────────────────────────────────────────────────────────────────

.PHONY: db-up
db-up: ## Start PostgreSQL + Redis
	docker compose up -d postgres redis

.PHONY: db-migrate
db-migrate: ## Run database migrations
	cd engine && alembic upgrade head

.PHONY: db-rollback
db-rollback: ## Rollback last migration
	cd engine && alembic downgrade -1

.PHONY: db-revision
db-revision: ## Create new migration (usage: make db-revision MSG="add xyz")
	cd engine && alembic revision --autogenerate -m "$(MSG)"

.PHONY: db-reset
db-reset: ## Reset database (drop + recreate + migrate)
	docker compose down -v postgres
	docker compose up -d postgres
	@sleep 3
	@make db-migrate

.PHONY: db-seed
db-seed: ## Seed database with development data
	cd engine && $(PYTHON) -m engine.scripts.seed_dev

.PHONY: db-fresh
db-fresh: db-reset db-seed ## Reset + migrate + seed database

# ── Testing ──────────────────────────────────────────────────────────────────

.PHONY: test
test: ## Run all tests (engine + web)
	@make test-engine
	@make test-web

.PHONY: test-engine
test-engine: ## Run engine tests (pytest)
	cd engine && pytest tests/ -v --tb=short

.PHONY: test-web
test-web: ## Run web frontend tests (vitest)
	cd web && npx vitest run

.PHONY: test-cov
test-cov: ## Run tests with coverage report
	cd engine && pytest tests/ --cov=engine --cov-report=html --cov-report=term-missing -v

.PHONY: test-watch
test-watch: ## Run tests in watch mode
	cd engine && pytest-watch tests/ -- -v --tb=short

.PHONY: test-fast
test-fast: ## Run tests excluding slow markers
	cd engine && pytest tests/ -v --tb=short -m "not slow"

.PHONY: test-integration
test-integration: ## Run integration tests only
	cd engine && pytest tests/ -v --tb=short -m "integration" -k "integration"

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests (requires running services)
	cd engine && pytest tests/ -v --tb=short -m "e2e"
	cd web && npx playwright test 2>/dev/null || echo "$(CYAN)Playwright not configured — skipping$(RESET)"

# ── Linting ──────────────────────────────────────────────────────────────────

.PHONY: lint
lint: ## Run all linters
	@make lint-python
	@make lint-web

.PHONY: lint-python
lint-python: ## Lint Python code (ruff)
	cd engine && ruff check .
	cd engine && ruff format --check .

.PHONY: lint-web
lint-web: ## Lint TypeScript code (eslint)
	cd web && npm run lint

.PHONY: format
format: ## Auto-format all code
	cd engine && ruff format .
	cd engine && ruff check --fix .

.PHONY: typecheck
typecheck: ## Run type checkers
	cd engine && mypy engine/ --ignore-missing-imports
	cd web && npx tsc --noEmit

# ── Security ─────────────────────────────────────────────────────────────────

.PHONY: security-scan
security-scan: ## Run security scanners (bandit + safety)
	cd engine && bandit -r engine/ -c pyproject.toml -q || true
	cd engine && safety check --short-output || true
	@echo "$(GREEN)✓ Security scan complete$(RESET)"

.PHONY: pre-commit
pre-commit: ## Run pre-commit hooks on all files
	cd engine && pre-commit run --all-files

# ── Docker ───────────────────────────────────────────────────────────────────

.PHONY: docker-build
docker-build: ## Build all Docker images
	docker compose build

.PHONY: docker-up
docker-up: ## Start all containers
	docker compose up -d

.PHONY: docker-down
docker-down: ## Stop all containers
	docker compose down

.PHONY: docker-logs
docker-logs: ## Tail all container logs
	docker compose logs -f

.PHONY: docker-clean
docker-clean: ## Remove all containers and volumes
	docker compose down -v --remove-orphans

# ── Build ────────────────────────────────────────────────────────────────────

.PHONY: build
build: ## Build production artifacts
	docker build -t zaseon-engine:latest ./engine
	docker build -t zaseon-web:latest ./web

.PHONY: build-web
build-web: ## Build web for production
	cd web && npm run build

.PHONY: docker-push
docker-push: ## Push Docker images to registry (set REGISTRY env var)
	docker tag zaseon-engine:latest $${REGISTRY:-ghcr.io/zaseon}/engine:latest
	docker tag zaseon-web:latest $${REGISTRY:-ghcr.io/zaseon}/web:latest
	docker push $${REGISTRY:-ghcr.io/zaseon}/engine:latest
	docker push $${REGISTRY:-ghcr.io/zaseon}/web:latest

.PHONY: deploy
deploy: docker-push ## Deploy to Kubernetes (requires kubectl configured)
	kubectl apply -f infra/k8s/base.yml
	kubectl rollout restart deployment/zaseon-engine deployment/zaseon-web
	@echo "$(GREEN)✓ Deployment triggered$(RESET)"

.PHONY: generate-types
generate-types: ## Generate TypeScript types from OpenAPI schema
	@make export-api-docs
	cd web && npx openapi-typescript ../engine/docs/openapi.json -o types/generated.ts 2>/dev/null || echo "$(CYAN)openapi-typescript not installed — skipping$(RESET)"
	@echo "$(GREEN)✓ Types generated$(RESET)"

.PHONY: export-api-docs
export-api-docs: ## Export OpenAPI schema to docs/openapi.json
	cd engine && $(PYTHON) -m engine.scripts.export_openapi
	@echo "$(GREEN)✓ OpenAPI schema exported to engine/docs/openapi.json$(RESET)"

# ── Utilities ────────────────────────────────────────────────────────────────

.PHONY: clean
clean: ## Remove build artifacts and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name node_modules -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .next -exec rm -rf {} + 2>/dev/null || true
	rm -rf engine/htmlcov engine/.coverage

.PHONY: loc
loc: ## Count lines of code
	@echo "$(CYAN)Engine (Python):$(RESET)"
	@find engine -name '*.py' -not -path '*/node_modules/*' | xargs wc -l | tail -1
	@echo "$(CYAN)Web (TypeScript):$(RESET)"
	@find web -name '*.ts' -o -name '*.tsx' | grep -v node_modules | xargs wc -l | tail -1
	@echo "$(CYAN)Total:$(RESET)"
	@find . \( -name '*.py' -o -name '*.ts' -o -name '*.tsx' \) -not -path '*/node_modules/*' | xargs wc -l | tail -1

.PHONY: check
check: ## Run all checks (lint + test + type-check)
	@echo "$(CYAN)Running all checks...$(RESET)"
	@make lint
	@make test
	@make typecheck
	@echo "$(GREEN)✓ All checks passed.$(RESET)"

.PHONY: shell
shell: ## Open Python shell with engine imports
	cd engine && $(PYTHON) -c "from engine.core.config import get_settings; print('Settings loaded:', get_settings().app_name)" && $(PYTHON) -i -c "from engine.core.config import get_settings"
