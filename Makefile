# Guardian CLI Testing Makefile
# Provides convenient commands for testing and development

.PHONY: help test test-unit test-integration test-e2e test-fast test-slow coverage lint format clean install-dev

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install-dev: ## Install development dependencies
	pip install -e ".[dev]"
	pip install pytest pytest-asyncio pytest-cov pytest-timeout pytest-mock pytest-benchmark
	pip install ruff black mypy bandit safety
	@echo "✅ Development dependencies installed"

test: ## Run all tests
	pytest tests/ -v

test-unit: ## Run unit tests only
	pytest tests/unit/ -v -m unit

test-integration: ## Run integration tests only
	pytest tests/integration/ -v -m integration

test-e2e: ## Run end-to-end tests only
	pytest tests/e2e/ -v -m e2e

test-fast: ## Run fast tests only (exclude slow tests)
	pytest tests/ -v -m "not slow"

test-slow: ## Run slow tests only
	pytest tests/ -v -m slow

test-watch: ## Run tests in watch mode (auto-rerun on changes)
	pytest-watch -- tests/unit/ -v

coverage: ## Run tests with coverage report
	pytest tests/unit/ --cov=. --cov-report=html --cov-report=term-missing
	@echo "📊 Coverage report generated in htmlcov/index.html"

coverage-open: coverage ## Run coverage and open HTML report
	open htmlcov/index.html || xdg-open htmlcov/index.html

lint: ## Run linters (ruff, black, mypy)
	@echo "Running ruff..."
	ruff check .
	@echo "Running black..."
	black --check .
	@echo "Running mypy..."
	mypy tools/ core/ utils/ --ignore-missing-imports
	@echo "✅ Linting complete"

format: ## Auto-format code with black and ruff
	black .
	ruff check --fix .
	@echo "✅ Code formatted"

security: ## Run security scanners
	@echo "Running Bandit..."
	bandit -r . -ll
	@echo "Running Safety..."
	safety check
	@echo "✅ Security scan complete"

clean: ## Clean up generated files
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf coverage.xml
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "✅ Cleaned up generated files"

benchmark: ## Run performance benchmarks
	pytest tests/performance/ -v -m benchmark --benchmark-only

ci-test: ## Run tests like CI does
	pytest tests/unit/ -v -m unit --cov=. --cov-report=xml --cov-report=term

# Quick shortcuts
t: test-unit ## Shortcut for test-unit
tc: coverage ## Shortcut for coverage
tf: format ## Shortcut for format
