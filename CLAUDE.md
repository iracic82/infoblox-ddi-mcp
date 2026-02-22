# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Infoblox DDI MCP Server — exposes 20 high-level "intent" tools for managing Infoblox BloxOne DDI (DNS, DHCP, IPAM, Security, Federation) via the Model Context Protocol. Instead of 98 atomic CRUD operations, AI agents get 20 workflow-level tools that orchestrate multi-step operations automatically.

## Common Commands

```bash
# Install dependencies
uv pip install -r requirements.txt

# Run server (stdio for Claude Desktop / Cursor / Windsurf)
python mcp_intent.py

# Run server (HTTP for remote clients)
python mcp_intent.py --http

# Lint & format
ruff check mcp_intent.py services/
ruff format mcp_intent.py services/

# Run all tests (108 tests, requires INFOBLOX_API_KEY set)
INFOBLOX_API_KEY=test_key_for_ci python -m pytest tests/ -v

# Run a single test file
INFOBLOX_API_KEY=test_key_for_ci python -m pytest tests/test_validation.py -v

# Run a single test by name
INFOBLOX_API_KEY=test_key_for_ci python -m pytest tests/test_tools.py -v -k "test_explore_network"
```

## Architecture

**Single-file intent layer** (`mcp_intent.py`, ~3400 lines): All 20 MCP tools, validation helpers, resolver functions, MCP resources, prompts, and the server entry point live in one file. Sections are delimited by `# === Section Name ===` comment banners.

### Structural sections in `mcp_intent.py` (top to bottom):
1. **Service Client Initialization** — creates `client` (InfobloxClient), `insights_client` (InsightsClient), `atcfw_client` (AtcfwClient) at module level; each may be `None` if API key is missing
2. **Response Helpers** — `intent_response()` builds the standard envelope (`status`, `summary`, `steps`, `result`, `warnings`, `next_actions`); `step_result()` for individual workflow steps
3. **Validation Helpers** — `validate_cidr()`, `validate_ip()`, `validate_mac()`, `validate_fqdn()`, `validate_action()`, `validate_resource_type()`, `sanitize_filter()` (prevents filter injection)
4. **Resolver Functions** — `resolve_space()`, `resolve_zone()`, `resolve_realm()` — convert human-friendly names to Infoblox resource IDs via API lookup (exact match, then fuzzy)
5. **20 `@mcp.tool()` functions** — grouped by domain (Discovery, Provisioning, Troubleshooting, Security, Reporting, IPAM, DNS, DHCP, IP Reservation, Federation, Security Insight Triage)
6. **MCP Resources & Prompts** — static metadata exposed via MCP protocol
7. **OpenTelemetry setup** — optional tracing, guarded by import availability
8. **`main()` entry point** — handles `--http` flag, configures auth, starts FastMCP

### Service clients (`services/`):
- **`infoblox_client.py`** (InfobloxClient) — 85 methods covering IPAM, DNS, DHCP, Federation APIs. Uses `pybreaker` circuit breaker (opens after 5 failures, resets after 60s), `cachetools` TTL caches (5-min), connection pooling via `requests.Session`
- **`insights_client.py`** (InsightsClient) — 13 methods for SOC Insights API (threats, indicators, policy analytics)
- **`atcfw_client.py`** (AtcfwClient) — 11 methods for DNS Security/Threat Firewall. Also has its own circuit breaker and caching
- **`metrics.py`** — thread-safe in-memory MetricsCollector (API call counts, cache hit/miss, circuit breaker state, latency tracking)

### Key patterns:
- **Every tool checks `if not client:`** at the top and returns an error envelope — tools degrade gracefully without a valid API key
- **Resolvers** accept both human names ("prod") and raw IDs ("ipam/ip_space/abc") — they short-circuit on IDs
- **`sanitize_filter()`** must be used on all user input going into BloxOne API filter expressions to prevent injection
- **All destructive operations** (delete, decommission, bulk triage) default to `dry_run=True`
- **stdout is sacred in stdio mode** — all logging goes to stderr via structlog; any stdout print corrupts the JSON-RPC stream
- **`Literal` types for enums** — all enum-like parameters (action, resource_type, depth, record_type, priority, status) use `typing.Literal` so FastMCP emits JSON Schema `enum` constraints. This lets LLMs treat values as hard constraints instead of guessing from docstrings
- **MCP tool annotations** — every `@mcp.tool()` has `annotations={}` with `readOnlyHint`, `destructiveHint`, `idempotentHint`, and/or `openWorldHint` per MCP spec. Read-only tools get `readOnlyHint=True`; tools that CAN delete get `destructiveHint=True`
- **Disambiguation docstrings** — each tool's first 1-3 sentences state what it does, when to use it (USE THIS for...), and which sibling tools to use instead for related tasks

## Testing

Tests are pure unit tests using `unittest.mock` — no real Infoblox API calls. The test suite has 4 files:
- `test_validation.py` — 27 tests for validators/sanitizers (direct function calls)
- `test_resolvers.py` — 18 tests for name→ID resolvers (mock API responses)
- `test_tools.py` — 58 tests for all 20 MCP tools via `fastmcp.Client` (each tool gets happy-path, client-None, and edge case tests; includes enriched output tests)
- `test_resources.py` — 5 tests for MCP resources

Tests monkeypatch `mcp_intent.client`, `mcp_intent.insights_client`, `mcp_intent.atcfw_client` with MagicMocks. Use `conftest.py` fixtures: `mock_infoblox_client`, `mock_insights_client`, `mock_atcfw_client`, `all_clients`, `no_clients`, `mcp_server`. Tool test results are parsed via `parse_tool_result()` which extracts JSON from `CallToolResult.content[0].text`.

**Note on Literal type validation:** Tests for invalid enum values (e.g., `action="drop"`) now expect `fastmcp.exceptions.ToolError` with `match="literal_error"` because Pydantic validates Literal types at the schema level before tool code runs.

## Code Style

- **Ruff** for linting and formatting (config in `pyproject.toml`)
- Line length: 120, target: Python 3.10
- Lint rules: E, W, F, I, UP, B, S (security). `E501` ignored globally; `S101` (assert) ignored in tests; `E402`/`S104`/`S110` ignored in `mcp_intent.py`
- Quote style: double, indent: spaces
- Pre-commit hooks: trailing-whitespace, end-of-file-fixer, check-yaml, check-toml, detect-private-key, ruff check --fix, ruff format

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `INFOBLOX_API_KEY` | Yes | Infoblox CSP API key |
| `INFOBLOX_BASE_URL` | No | CSP portal URL (default: `https://csp.infoblox.com`) |
| `MCP_HOST` | No | HTTP bind address (default: `0.0.0.0`) |
| `MCP_PORT` | No | HTTP port (default: `4005`) |
| `MCP_PATH` | No | HTTP endpoint path (default: `/mcp`) |
| `MCP_AUTH_TOKEN` | No | Bearer token for HTTP transport auth |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | Enables OpenTelemetry tracing |

## CI

GitHub Actions CI (`.github/workflows/ci.yml`) runs on push/PR to main:
- **Lint job**: ruff check + format check (Python 3.12)
- **Test job**: matrix across Python 3.10–3.13, verifies exactly 20 `@mcp.tool(` decorators exist
- **Docker job**: builds image and verifies module import

## Git Commits

- Never add `Co-Authored-By` lines to commit messages
