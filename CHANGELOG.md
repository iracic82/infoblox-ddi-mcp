# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-03-04

### Added

- Auto-IP assignment in `provision_host`: when no `ip` is provided, automatically allocates the next available IP from a subnet via the `nextavailableip` API. New `subnet` parameter allows specifying which subnet to allocate from; auto-selects when only one subnet exists, disambiguates when multiple exist.
- `get_next_available_ip()` method on `InfobloxClient` — queries next available IP from subnets, ranges, or address blocks via the BloxOne DDI `nextavailableip` endpoint.
- `auto_dns` parameter on `provision_host`: when `True` (default), DNS A/PTR records are auto-generated atomically by the API during host creation (matches the "Auto-generate DNS records" UI checkbox). When `False`, DNS records are created as separate API calls for more granular control.
- 4 new tests (125 total): 3 for auto-IP scenarios (single subnet, specific subnet, ambiguous), 1 for auto-DNS with zone, 1 manual-DNS replacement test.

### Changed

- `provision_host` zone resolution now happens before host creation (required for `auto_generate_records` flow)
- `provision_host` docstring instructs the LLM to ask the user whether they prefer auto or manual DNS creation

## [1.3.1] - 2026-03-04

### Fixed

- DNS record creation (A, PTR) no longer passes redundant `view` parameter to the API — the view-specific zone ID is sufficient and passing both caused field validation errors in multi-view environments

## [1.3.0] - 2026-03-04

### Added

- `resolve_view()` helper for DNS view name-to-ID resolution (exact match, fuzzy fallback, ID passthrough)
- `view` parameter on `provision_host`, `provision_dns`, `diagnose_dns`, `manage_dns_record`, and `manage_dns_zone` for multi-view zone disambiguation
- Shared `create_resilient_session()` factory in `services/__init__.py` with retry (3 attempts, exponential backoff on 429/502/503/504) and connection pooling (20 connections, 10 per host)
- 13 new tests (121 total): 6 for `resolve_view`, 4 for `resolve_zone` view behavior, 3 tool-level view tests

### Fixed

- 3 missing `sanitize_filter()` calls in trailing-dot zone fallbacks (filter injection risk)
- 10 bare `except: pass` blocks replaced with proper warning capture
- All AtcfwClient methods now route through `_request()` for circuit breaker protection (previously 11 methods bypassed it)
- `InsightsClient._request()` raises exceptions instead of silently returning `{"error": ...}` dicts
- `assess_security_posture` fails fast when no clients available instead of returning vacuous success
- Metrics percentile `IndexError` on boundary conditions
- `resolve_zone()` no longer silently picks `zones[0]` when multiple views match — returns disambiguation error listing available views

### Changed

- `resolve_zone()` accepts optional `view` parameter to filter by DNS view
- `provision_host` refactored to use `resolve_zone()` instead of inline `list_auth_zones` + `zones[0]`
- `investigate_threat` limit capped at 100, `manage_dns_record` limit capped at 500
- All 3 service clients (`InfobloxClient`, `InsightsClient`, `AtcfwClient`) use shared resilient session factory

## [1.2.0] - 2026-02-22

### Added

- `Literal` types on all enum-like tool parameters — LLMs now see JSON Schema `enum` constraints instead of guessing from docstrings
- MCP tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) on all 20 tools per MCP spec
- `manage_network` now supports `"list"` action for listing subnets, address blocks, ranges, and IP spaces
- `diagnose_ip_conflict` enriched with DHCP usage status and IPAM host associations (Step 4)
- `investigate_threat` enriched with SOC Insight timeline events via `get_insight_events()`
- `assess_security_posture` enriched with category filter coverage and content category counts
- `check_infrastructure_health` enriched with DNS views count
- 7 new tests for enriched tool outputs and list action (108 total, up from 101)

### Changed

- All 20 tool docstrings rewritten with "USE THIS for X / For Y use tool_name()" disambiguation pattern
- 9 existing tests updated to expect `ToolError` (Pydantic schema validation) instead of structured JSON for invalid enum values

### Removed

- `timeframe` parameter from `investigate_threat` (was documented as "Not yet implemented")

## [1.1.1] - 2026-02-22

### Fixed

- `provision_dns` now returns `success` with `already_existed: true` on HTTP 409 (record already exists) instead of failing
- README badge URL corrected to `iracic82` org
- README example paths updated from `infoblox-mcp/` to `infoblox-ddi-mcp/`

### Added

- OpenTelemetry section in README with setup instructions
- Updated project structure in README to include tests, examples, and CI workflows

## [1.1.0] - 2025-02-22

### Added

- Test suite with 101 tests covering validators, resolvers, tools, and resources
- Ruff linting and formatting configuration
- Pre-commit hooks for code quality (`.pre-commit-config.yaml`)
- OpenTelemetry optional integration (`pip install infoblox-ddi-mcp[otel]`)
- Example integrations: Anthropic SDK, OpenAI Agents, LangChain, curl
- CI pipeline with lint, test (Python 3.10-3.13 matrix), and Docker jobs
- PyPI trusted publishing workflow (OIDC) on `v*` tags
- Makefile targets: `make lint`, `make format`, `make test`
- CHANGELOG.md and SECURITY.md
- README badges: CI, Python, License, MCP, PyPI

### Changed

- Applied ruff formatting across all source files
- Fixed 418+ lint violations (import ordering, type annotations, unused imports)

## [1.0.0] - 2025-02-22

### Added

- 20 intent-level workflow tools covering 100% of Infoblox BloxOne DDI API
- Three service clients: `InfobloxClient` (85 methods), `InsightsClient` (13), `AtcfwClient` (11)
- Standard intent response envelope (`status`, `summary`, `steps`, `result`, `warnings`, `next_actions`)
- Input validation helpers: CIDR, IP, MAC, FQDN, action, resource type, filter sanitization
- Resolver functions for IP spaces, DNS zones, and federated realms (name-to-ID)
- Three MCP resources: `infoblox://tools`, `infoblox://status`, `infoblox://dns/record-types`
- Four guided prompts: host provisioning, DNS troubleshooting, security triage, capacity planning
- Dual transport support: stdio (Claude Desktop, Cursor) and HTTP streamable (AEX, remote)
- Bearer token authentication for HTTP transport via `MCP_AUTH_TOKEN`
- Response caching with TTLCache (5-minute TTL for IP spaces, DNS zones, etc.)
- Circuit breaker pattern via pybreaker for API resilience
- Structured logging via structlog (all output to stderr for stdio compatibility)
- Metrics collection: API call counts, cache hit rates, latency percentiles, circuit breaker state
- Docker support with multi-stage build and docker-compose
- CI pipeline with syntax check, tool count verification, and Docker build
- Comprehensive README with quick start, tool reference, and architecture docs
- PyPI-ready packaging via hatchling with `[project.scripts]` entry point
- Ruff linting and formatting configuration
- Pre-commit hooks for code quality
- Test suite with ~110 tests covering validators, resolvers, tools, and resources
- OpenTelemetry optional integration (`pip install infoblox-ddi-mcp[otel]`)
- Example integrations: Anthropic SDK, OpenAI Agents, LangChain, curl
