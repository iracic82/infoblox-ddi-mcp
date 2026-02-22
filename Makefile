.PHONY: install dev run run-http docker-build docker-run docker-up docker-down clean lint format test check

# ─── Development ────────────────────────────────────────────────────

install:  ## Install dependencies with uv
	uv pip install -r requirements.txt

dev:  ## Install in editable mode
	uv pip install -e .

run:  ## Run MCP server (stdio transport)
	python mcp_intent.py

run-http:  ## Run MCP server (HTTP transport)
	python mcp_intent.py --http

# ─── Docker ─────────────────────────────────────────────────────────

docker-build:  ## Build Docker image
	docker build -t infoblox-ddi-mcp .

docker-run:  ## Run Docker container (requires INFOBLOX_API_KEY env var)
	docker run --rm -p 4005:4005 \
		-e INFOBLOX_API_KEY=$${INFOBLOX_API_KEY} \
		-e INFOBLOX_BASE_URL=$${INFOBLOX_BASE_URL:-https://csp.infoblox.com} \
		infoblox-ddi-mcp

docker-up:  ## Start with docker compose (reads .env)
	docker compose up -d

docker-down:  ## Stop docker compose
	docker compose down

# ─── Quality ────────────────────────────────────────────────────────

lint:  ## Run ruff linter
	ruff check mcp_intent.py services/

format:  ## Run ruff formatter
	ruff format mcp_intent.py services/

test:  ## Run test suite
	INFOBLOX_API_KEY=test_key_for_ci python -m pytest tests/ -v

check:  ## Verify syntax
	python -c "import py_compile; py_compile.compile('mcp_intent.py', doraise=True); print('Syntax OK')"

clean:  ## Remove build artifacts
	rm -rf __pycache__ services/__pycache__ tests/__pycache__ .pytest_cache .ruff_cache *.pyc *.egg-info dist build

# ─── Help ───────────────────────────────────────────────────────────

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
