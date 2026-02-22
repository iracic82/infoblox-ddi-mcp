# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
