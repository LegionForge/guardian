## legionforge-guardian — standalone development commands
##
## Quickstart:
##   make install-dev   # install package + test deps into current venv
##   make test          # run the full test suite
##   make lint          # check formatting
##
## No external services required — all tests are deterministic and in-process.

PYTHON ?= python3

.PHONY: help install-dev test test-cov test-checks test-sdk test-live test-guardian-live guardian-start guardian-stop lint format build clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

install-dev: ## Install package + all dev dependencies (pytest, respx, black)
	$(PYTHON) -m pip install -e ".[dev]"

test: ## Run the full test suite (no services required)
	$(PYTHON) -m pytest tests/ -v

test-cov: ## Run full test suite with coverage report (fail under 50%)
	$(PYTHON) -m pytest tests/ -v --cov=legionforge_guardian --cov-report=term-missing --cov-fail-under=50

test-checks: ## Run only the 7-check enforcement tests
	$(PYTHON) -m pytest tests/test_checks.py -v

test-sdk: ## Run only the SDK client tests (11 tests)
	$(PYTHON) -m pytest tests/test_sdk.py -v

test-live: ## Run live HTTP tests against GUARDIAN_TEST_URL (must be set)
	$(PYTHON) -m pytest tests/test_live.py -v

test-guardian-live: ## Start Guardian in Docker, run live HTTP tests, tear down
	@echo "▶ Starting Guardian on port 9768 for live tests..."
	@GUARDIAN_DB_PASSWORD=guardian-live-test GUARDIAN_PORT=9768 GUARDIAN_REQUIRE_AUTH=false \
		docker compose up -d --build
	@echo "▶ Waiting for Guardian to be healthy (up to 60s)..."
	@for i in $$(seq 1 30); do \
		curl -sf http://localhost:9768/health > /dev/null 2>&1 && echo "✅ Guardian healthy" && break; \
		[ $$i -eq 30 ] && echo "❌ Guardian did not start" && \
			GUARDIAN_DB_PASSWORD=guardian-live-test GUARDIAN_PORT=9768 docker compose down -v && exit 1; \
		echo "  waiting... ($$i/30)"; sleep 2; \
	done
	@echo "▶ Running live tests..."
	@GUARDIAN_TEST_URL=http://localhost:9768 $(PYTHON) -m pytest tests/test_live.py -v; \
		RESULT=$$?; \
		echo "▶ Tearing down..."; \
		GUARDIAN_DB_PASSWORD=guardian-live-test GUARDIAN_PORT=9768 docker compose down -v; \
		exit $$RESULT

guardian-start: ## Start guardian container using .env.guardian (secrets stay on disk)
	@test -f .env.guardian || (echo "ERROR: .env.guardian not found — copy .env.example and fill in values" && exit 1)
	docker run -d \
		--name legionforge-guardian \
		--restart unless-stopped \
		--network guardian_guardian-net \
		-p 127.0.0.1:9766:9766 \
		--env-file .env.guardian \
		legionforge-guardian:latest
	@echo "Guardian started — check: curl http://localhost:9766/health"

guardian-stop: ## Stop and remove guardian container
	docker rm -f legionforge-guardian 2>/dev/null || true

lint: ## Check formatting with Black (no changes)
	$(PYTHON) -m black --check src/ tests/

format: ## Auto-format with Black
	$(PYTHON) -m black src/ tests/

build: ## Build sdist + wheel distributions
	$(PYTHON) -m pip install build --quiet
	$(PYTHON) -m build
	$(PYTHON) -m pip install twine --quiet
	$(PYTHON) -m twine check dist/*

clean: ## Remove build artifacts
	rm -rf dist/ build/ src/legionforge_guardian.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
