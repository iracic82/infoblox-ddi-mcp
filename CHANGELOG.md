# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2026-04-17

### Fixed — Critical safety

- **`dry_run=True` bypassed on 7 tools** (silent mutation bug). `create` and
  `update` actions across `manage_dns_zone`, `manage_network` (subnet/address_block/range),
  `manage_ip_reservation` (reserve), `manage_dhcp`, `manage_rpz_policies`,
  `manage_federation`, `manage_dtc`, and `manage_security_policy` were calling
  the real Infoblox API regardless of the `dry_run` flag. All paths now preview
  before mutation. `dry_run=False` must be explicit to execute.
- **`manage_dns_zone` silent no-ops** — `action="delete"` and `action="update"`
  for `resource_type="auth_zone"` were wired to placeholder lambdas that returned
  `None`, claiming success without calling the API. Now dispatch to real
  `delete_auth_zone` and `update_auth_zone` client methods. `forward_zone` also
  got its missing `delete` and `update` dispatch entries.
- **`manage_dns_zone(action="list", view=...)` ignored the view filter** and
  returned zones from every view. Now threads the view into a `filter` query.
- **Exception-string leakage in error responses** — 50+ sites were returning
  raw `str(e)` in tool output, risking leaks of HTML error pages, stack traces,
  and patterns that resemble credentials. A new `_clean_error()` utility strips
  HTML, censors Bearer tokens and `api_key=...` patterns, censors long hex
  strings, and truncates to 280 chars.

### Added — UX improvements

- **`view_name` on zone/delegation list responses** — each row now carries
  `view_name` alongside `view` UUID so agents can disambiguate split-horizon
  zones without a follow-up `list_dns_views` call.
- **Rich "view not found" errors** — when `resolve_view()` fails, the error
  lists every configured view name plus the closest fuzzy match. A typo like
  `view="dfault"` now gets `"Available views: default, TEST, PROD. Closest
  match: 'default'."` instead of just `"DNS view 'dfault' not found"`.
- **"Zone not in view" errors** — when a zone exists but not in the requested
  view, `resolve_zone()` now tells the caller which views DO contain the zone
  (e.g. `"Zone 'acme.corp' exists, but not in view 'default'. It IS in views:
  TEST, PROD."`).
- **Ambiguity errors use view names** — when a zone exists in multiple views,
  the error shows view names instead of raw UUIDs.
- **`manage_dns_record(action="create")` routes to `provision_dns`** — instead
  of a cryptic `literal_error`, callers now get a clear hand-off: the `action`
  Literal widened to include `"create"`, with a short-circuit that tells the
  agent to call `provision_dns()` instead.

### Added — Tests

- 27 new regression tests covering every fix above:
  - `TestDryRunSafetyContract` — 13 tests, one per affected tool/action
  - `TestAuthZoneDispatchFixes` — delete + update no-op regressions
  - `TestViewFilterAndEnrichment` — view filter and view_name enrichment
  - `TestResolveZoneViewDisambiguation` — zone-not-in-view + ambiguity
  - `TestManageDnsRecordCreateRouting` — create routing
  - `TestCleanErrorHelper` — HTML stripping, secret censoring, truncation

### Changed

- `manage_dns_zone` docstring updated: "ALL mutating actions (create, update,
  delete) default to `dry_run=True`" (previously only mentioned delete).
- Version bumped from 2.1.0 to 2.2.0.

## [2.1.0] - 2026-04-11

### Added

- **3 new MCP tools** (23 → 26 total):
  - `manage_rpz_policies` — RPZ rule CRUD (list, get, create, update, delete) via DDI client
  - `manage_dnssec` — DNSSEC lifecycle: sign/unsign zones, check status, export trust anchors, delete keys, import keysets
  - `manage_doh` — DNS-over-HTTPS and security operations: PoP regions, DoH FQDNs, threat feeds, threat indicators, app/block approvals
- **5 extended MCP tools** covering previously unreachable actions:
  - `manage_network` — ip_space full CRUD (create with dry_run guard, get, update, delete)
  - `manage_dhcp` — 7 new resource types: `option_code`, `hardware_filter`, `option_filter`, `hardware`, `option_group`, `mac_item`, `dhcp_host`; new actions `bulk_create`, `link`, `delink`
  - `manage_dns_zone` — 7 new resource types: `rpz`, `delegation`, `dns_acl`, `auth_nsg`, `forward_nsg`, `dns_server`, `dns_host`; new `copy` action; `target_view` parameter
  - `manage_ip_reservation` — IPAM host routing (`ipam/host/*` resource IDs now routed to ipam host methods)
  - `manage_security_policy` — full security policy and rule CRUD, network list management
- **3 input validation functions** added at module level: `validate_dns_value`, `sanitize_query`, `validate_insight_id`

### Fixed

- **`manage_doh` NameError** — function was referencing undefined `security_client` (9 call sites); corrected to `atcfw_client` (the initialized global)

### Changed

- Version bumped from 2.0.0 to 2.1.0 (303 API methods, 26 tools)
- All user-visible metadata updated to reflect 26 tools: README, pyproject.toml, FastMCP instructions, startup banner, `infoblox://tools` resource catalog

## [2.0.0] - 2026-03-30

### Added

- **121 new API methods** (182 → 303 total) covering previously missing endpoints:
  - DHCP: servers, global config, option groups, option spaces, MAC address items, config profiles, DHCP filters, host associations, linked HA groups
  - DNS Config: ACLs, auth/forward nameserver groups, DNS servers, DNS global config, DNS hosts, DNS services, zone copy, trust anchor export, DNSSEC key management, RPZ rules, record protection, domain name conversion
  - Security (ATCFW): full security policy CRUD, policy rules, network lists, access code CRUD, application filter CRUD, internal domain list CRUD, threat feeds, threat indicators, app/block approvals, PoP regions, DoH FQDNs
  - Federation: next available FLD, next appropriate delegation, next available overlapping/reserved blocks, pool-level block allocation
  - IPAM: IP space full CRUD (get, create, update, delete)
- **3 new MCP resource templates**: `infoblox://spaces/{name}/subnets`, `infoblox://zones/{fqdn}/records`, `infoblox://health`
- **Server instructions** — LLM clients now receive usage guidance via MCP `instructions` field
- **`openWorldHint`** annotations on `provision_host` and `provision_dns`

### Fixed

- **`list_rpz_zones`** — was querying `/dns/auth_zone` (returning all zones), now correctly uses `/dns/rpz` endpoint
- **`delete_dns_record`** — was bypassing `_resource_endpoint` normalization, failing on bare IDs
- **`diagnose_dns` cache flush** — dead code (`if False`) permanently disabled view-scoped flush
- **`manage_dns_zone` get** — was returning DNS view list instead of actual zone details
- **`manage_network` subnet/block create** — cleaned up redundant comment passing, added tags support for address blocks
- **`partial_update_named_list_items`** — was not invalidating `named_list_cache` after mutations
- **Security policy write methods** — `create/update/delete_security_policy` were not invalidating `security_policy_cache`
- **`list_security_policies`** — removed redundant `headers=self.session.headers` parameter
- **Error guidance** — `provision_host` space-not-found, multiple-subnets, and `decommission_host` failures now include `next_actions` with specific tool suggestions

### Changed

- Server version now correctly reports app version (was showing FastMCP version)
- Version bumped from 1.8.0 to 2.0.0 (303 API methods, 8 MCP resources, 23 tools, 163 tests)

## [1.8.0] - 2026-03-24

### Added

- **MCP resources**: `infoblox://spaces` and `infoblox://zones` — live resource URIs returning current IP spaces and DNS zones
- **Pagination**: `explore_network` now accepts `limit` parameter (default 500) with truncation warnings when results exceed the limit
- **Rollback suggestions**: `provision_host` partial failures now include explicit rollback `next_action` via `decommission_host`
- **Error guidance**: All client-not-initialized failures now include `next_actions` pointing to `check_api_health()` and env var setup

### Fixed

- **Resource catalog**: `infoblox://tools` now correctly reports 23 tools (was 20) and includes `check_api_health`, `manage_dhcp_lease`, `manage_dtc` in their respective domains

### Changed

- Version bumped from 1.7.1 to 1.8.0 (5 MCP resources, 23 tools, 163 tests)

## [1.7.1] - 2026-03-24

### Fixed

- **README**: Added 3 missing tools to table (`check_api_health`, `manage_dhcp_lease`, `manage_dtc`) — table now matches all 23 registered tools
- **README**: Added Claude Code CLI connection examples (stdio + HTTP)
- **README**: Added Remote Access section for HTTP transport usage
- **README**: Fixed curl examples — added required `Accept` header and `Mcp-Session-Id` session flow for MCP streamable HTTP
- **Makefile**: Switched from bare `python` to `uv run python` for compatibility with systems where only `python3` is available
- **README**: Updated Quick Start to use `uv run python` consistently

## [1.7.0] - 2026-03-04

### Added

- **`check_api_health` tool** (tool #23) — verifies API connectivity for all three service clients (DDI, Insights, ATCFW) with response latency reporting
- **`dry_run` parameter** on `provision_host`, `provision_dns`, and `manage_dhcp_lease` (clear/resend_ddns) — defaults to `True` to prevent accidental resource creation by AI agents
- **Circuit breaker** on `InsightsClient` — matching the pattern from InfobloxClient and AtcfwClient (pybreaker, 5 failures, 60s reset)
- **Metrics recording** on `InsightsClient._request()` — API call counts, latency, and status codes now tracked
- **Transient HTTP error exclusion** from all 3 circuit breakers — 429/502/503/504 errors (already retried by urllib3) no longer count toward breaker failure threshold
- **Cache invalidation** on write operations — `address_block_cache`, `dns_zone_cache`, and `named_list_cache` are cleared after create/update/delete
- **`sanitize_filter` hardened** — now truncates input to 512 chars and strips BloxOne filter operators (`==`, `!=`, `~=`, `<=`, `>=`, `!~`) to prevent filter injection
- 15 new tests (163 total): error scenarios (API failures, partial workflows), sanitize_filter injection, dry_run protection, health endpoint

### Changed

- `provision_host` and `provision_dns` now default to `dry_run=True` — agents must explicitly set `dry_run=False` to create resources
- `manage_dhcp_lease` clear/resend_ddns now default to `dry_run=True`
- `manage_dns_zone` docstring enhanced with quick routing guide for resource_type → action mapping
- Version bumped from 1.6.0 to 1.7.0 (23 MCP tools, 163 tests)

## [1.6.0] - 2026-03-04

### Added

- **`manage_dhcp_lease` tool** (tool #21) — list/search active DHCP leases, wipe leases (`clear`), resend DDNS updates
- **`manage_dtc` tool** (tool #22) — DTC/GSLB management: LBDNs, pools, servers, and policies with full CRUD
- **`manage_dns_zone` expanded** — 3 new resource types (`dns_view`, `rpz`, `delegation`) + 5 new actions (`update`, `sign`, `unsign`, `dnssec_status`, `reorder`)
- **`manage_network` expanded** — 2 new actions (`next_available_subnet`, `next_available_address_block`) for allocating from address blocks
- **`manage_security_policy` expanded** — `category_filter` resource type with full CRUD (create, update via PUT, delete, list, get)
- ~25 new client methods on `InfobloxClient`: DHCP leases (3), DNS view CRUD (4), RPZ zone CRUD + reorder (6), DNSSEC operations (3), DNS delegation CRUD (5), next-available subnet/block (2), DTC LBDN/pool/server/policy CRUD (20)
- 4 new client methods on `AtcfwClient`: category filter get/create/update (PUT)/delete
- 19 new tests (148 total): DHCP leases, DTC, expanded DNS zones, expanded network, expanded security policy

### Changed

- **`manage_dns_zone` refactored**: `zone_type` parameter renamed to `resource_type` with expanded values (`auth_zone`, `forward_zone`, `dns_view`, `rpz`, `delegation`). Action constraints enforce `sign`/`unsign`/`dnssec_status` only for `auth_zone` and `reorder` only for `rpz`.
- Version bumped from 1.5.0 to 1.6.0 (22 MCP tools, ~148 tests)

## [1.5.0] - 2026-03-04

### Fixed

- **Path-doubling bug** in `InfobloxClient`: 56 resource-specific methods (get/update/delete for all resource types) produced doubled URL paths like `/api/ddi/v1/ipam/host/ipam/host/uuid` when called with full-path IDs returned by the API — causing HTTP 501. Added `_resource_endpoint()` helper that normalizes both full-path IDs (`ipam/host/uuid`) and bare UUIDs.
- **FQDN doubling** in `provision_host`: passing `hostname="web.example.com"` with `zone="example.com"` no longer produces `web.example.com.example.com`. The `host_names[].name` field now correctly sends the short hostname relative to the zone.
- **Decommission of auto-DNS hosts**: `decommission_host` now detects `auto_generate_records` flag on IPAM hosts. For auto-managed DNS, skips separate DNS deletion (system records are auto-cleaned when the host is deleted). For manual DNS, deletes DNS records before the host. Handles 400/404 gracefully.

### Added

- `_resource_endpoint()` static helper on `InfobloxClient` — normalizes resource IDs to prevent path doubling across all 56 resource methods
- `flush_dns_cache()` method on `InfobloxClient` — triggers DNS cache flush via `POST /api/ddi/v1/dns/cache_flush`
- `list_infra_hosts()` and `list_infra_services()` methods on `InfobloxClient` — queries on-prem appliance health via `/api/infra/v1/detail_hosts` and `/api/infra/v1/detail_services`
- `partial_update_named_list_items()` method on `AtcfwClient` — add/remove items from named lists without replacing the entire list (`PATCH /api/atcfw/v1/named_lists/{id}/items`)
- `flush_cache` parameter on `diagnose_dns` tool — triggers DNS cache flush before diagnosis
- `add_items` and `remove_items` actions on `manage_security_policy` tool — partial updates to named list items
- Infrastructure host and service health checks in `check_infrastructure_health` tool — reports degraded on-prem appliances
- 4 new tests for `_resource_endpoint` helper (129 total)

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
