---
title: "fix: Partner release readiness — runtime bug, stale metadata, CI count, v2.1.0 release"
type: fix
status: active
date: 2026-04-11
---

# fix: Partner release readiness — runtime bug, stale metadata, CI count, v2.1.0 release

## Overview

Before sharing with the Cisco partnership team, three categories of defects must be resolved
in the uncommitted session work that added 3 new tools (manage_rpz_policies, manage_dnssec,
manage_doh) and extended 5 existing tools. The fix lands as v2.1.0.

## Problem Frame

The session work extended the MCP server from 23 to 26 tools. That work is correct and complete
but has three blocking issues before it can be shipped to a partner:

1. **Critical runtime bug**: `manage_doh` references an undefined name `security_client`
   throughout (9 call sites). The actual initialized global is `atcfw_client`. Every
   `manage_doh` call will raise `NameError` and return a 500 to the agent.

2. **CI hard-fail**: `.github/workflows/ci.yml` asserts `[ "$count" -eq 23 ]` on the tool
   count. With 26 tools, this fails and blocks the PR from merging.

3. **Stale metadata in 10+ places**: Documentation, startup output, the live
   `infoblox://tools` MCP resource, and the FastMCP `instructions` string still say "23 tools"
   or even "20 tools". Cisco/partners will see the wrong count in the tool picker, the resource
   catalog an agent would query, and the server's startup banner.

## Requirements Trace

- R1. `manage_doh` must route all 8 action paths through `atcfw_client` without NameError
- R2. CI `lint`, `test`, and `docker` jobs must all pass (no hardcoded count assertions)
- R3. All user-visible metadata — README, pyproject.toml, FastMCP instructions, startup
  print, `resource_tool_catalog()` — must report 26 tools
- R4. `resource_tool_catalog()` (the live `infoblox://tools` MCP resource) must list all 26
  tools, including manage_rpz_policies, manage_dnssec, manage_doh in correct domain groups
- R5. Work is released as v2.1.0 with CHANGELOG entry, git tag, and GitHub release

## Scope Boundaries

- No new tools, no new API methods, no new test scenarios beyond manage_doh coverage
- No changes to existing tool behavior
- No README prose changes beyond tool counts and the HCL AEX "20 tools" line

## Context & Research

### Relevant Code and Patterns

- `mcp_intent.py:89` — `atcfw_client = AtcfwClient()` is the correct variable name; the
  previous 25 tools all reference `atcfw_client`, not `security_client`
- `mcp_intent.py:5171–5255` — `manage_doh` function, all 9 `security_client` references
- `mcp_intent.py:5442` — `resource_tool_catalog()` function, domain group dict to extend
- `mcp_intent.py:5801` — startup print statement
- `.github/workflows/ci.yml:51–55` — tool count assertion step
- `README.md:9,17,37,39,146` — "23 tools" occurrences; `README.md:284` — stale "20 tools"
- `pyproject.toml:4` — description field
- `mcp_intent.py:5,53` — module docstring and FastMCP `instructions` string
- Existing test patterns: `tests/test_tools.py` — each tool class mocks `atcfw_client` via
  `unittest.mock.patch("mcp_intent.atcfw_client")`. New `manage_doh` tests must follow this
  exact pattern
- Git workflow: `MEMORY.md` documents the full feature-branch → PR → CI → merge → tag →
  GitHub release sequence

### Institutional Learnings

- No prior `docs/solutions/` entries in this repo

## Key Technical Decisions

- **Variable name**: Use `atcfw_client` everywhere in `manage_doh` — matches the 25 existing
  tools, the initialized global, and the mock target in tests
- **Version**: Bump to `2.1.0` (not `2.0.1`) — 3 new user-visible MCP tools and 5 extended
  tool signatures constitute a minor feature release, not a patch
- **CI count**: Change assertion value from `23` to `26`; keep the assertion itself — it is
  a useful sanity check
- **resource_tool_catalog domain grouping**: Place `manage_rpz_policies` and `manage_dnssec`
  in the existing `"dns"` group; place `manage_doh` in the existing `"security"` group

## Open Questions

### Resolved During Planning

- **Which variable name?** `atcfw_client` — confirmed by grepping all 25 existing tools and
  the initialization code at line 89
- **New version?** `2.1.0` — new tools = minor bump per Semantic Versioning
- **Add manage_doh tests?** Yes — the tool was added without test coverage and is a new
  behavioral unit. Minimum: no-client guard, list_pop_regions happy path, invalid action

### Deferred to Implementation

- Whether `resource_tool_catalog` domain descriptions need prose updates — implementer
  can judge at edit time without changing plan intent

## Implementation Units

- [ ] **Unit 1: Fix `manage_doh` critical runtime bug and add tests**

  **Goal:** Replace all 9 `security_client` references with `atcfw_client` in `manage_doh`
  and add minimum test coverage to prevent this class of regression.

  **Requirements:** R1

  **Dependencies:** None

  **Files:**
  - Modify: `mcp_intent.py` (lines 5171–5255, `manage_doh` function)
  - Test: `tests/test_tools.py`

  **Approach:**
  - Replace every occurrence of `security_client` in `manage_doh` with `atcfw_client` —
    this is the only change needed; the rest of the function logic is correct
  - Add a `TestManageDoh` test class following the same mock-and-assert pattern used by
    all other tool test classes in `tests/test_tools.py`

  **Patterns to follow:**
  - `mcp_intent.py:89` — `atcfw_client` initialization
  - Existing tool classes in `tests/test_tools.py` that `patch("mcp_intent.atcfw_client")`
    (e.g. `TestManageSecurityPolicy`, `TestInvestigateThreat`)

  **Test scenarios:**
  - Happy path: `list_pop_regions` action → mock `atcfw_client.list_pop_regions` returns
    `{"result": [{"id": "pop/1", "name": "us-east"}]}` → response status is `"success"`,
    result contains the mocked items
  - Happy path: `list_threat_feeds` action → mock returns feed list → response summarizes
    feed count correctly
  - Error path: `atcfw_client` is `None` → response status is `"failed"`, message mentions
    `INFOBLOX_API_KEY`
  - Error path: invalid action string → response status is `"failed"`, message mentions
    valid actions
  - Error path: `create_doh_fqdn` with neither `fqdn` nor `data` → response status is
    `"failed"`, message says requires `fqdn` or `data`

  **Verification:**
  - `uv run pytest tests/test_tools.py -k TestManageDoh -v` — all new tests pass
  - `grep "security_client" mcp_intent.py` — zero matches in `manage_doh` function body

---

- [ ] **Unit 2: Update stale metadata and CI assertion**

  **Goal:** Ensure every user-visible surface correctly reports 26 tools; fix the CI count
  assertion that hard-blocks the PR.

  **Requirements:** R2, R3, R4

  **Dependencies:** Unit 1 (tool count must be correct before updating CI check)

  **Files:**
  - Modify: `mcp_intent.py` (module docstring line 5, instructions string line 53,
    `resource_tool_catalog` lines 5443–5491, startup print line 5801)
  - Modify: `README.md` (lines 9, 17, 37, 39, 146, 284)
  - Modify: `pyproject.toml` (description field, line 4)
  - Modify: `.github/workflows/ci.yml` (line 55, count assertion)

  **Approach:**
  - `mcp_intent.py`: change every `"23 tool"` / `23` count reference to `26`; add
    `manage_rpz_policies` and `manage_dnssec` to the `"dns"` domain group's `"tools"` list
    and `manage_doh` to the `"security"` domain group's `"tools"` list; update
    `"tool_count": 23` → `26`
  - `README.md`: change all five "23 tools" occurrences; change "20 DDI tools" (HCL AEX
    section, line 284) to "26 tools"
  - `pyproject.toml`: update description string
  - `.github/workflows/ci.yml`: change `[ "$count" -eq 23 ]` to `[ "$count" -eq 26 ]`

  **Patterns to follow:**
  - Existing `resource_tool_catalog` domain group structure (dns: list of tool names,
    description string) — add new entries in-place, do not restructure

  **Test scenarios:**
  - Integration: `python -c "import json, mcp_intent; d = json.loads(mcp_intent.resource_tool_catalog()); assert d['tool_count'] == 26"` — passes without error
  - Integration: `grep -c '@mcp.tool(' mcp_intent.py` returns 26
  - Edge case: `resource_tool_catalog()` lists exactly the 26 tool names returned by `grep -A1 "@mcp.tool" mcp_intent.py | grep "^def "` — no tool is missing from a domain group

  **Verification:**
  - `grep "23 tool\|23 intent\|23 workflow\|20 DDI tool" README.md pyproject.toml mcp_intent.py` — zero matches
  - `grep -c '@mcp.tool(' mcp_intent.py` outputs `26`
  - CI "Verify 23 tools" step name can be updated to "Verify 26 tools" (cosmetic)

---

- [ ] **Unit 3: Version bump, CHANGELOG, PR, merge, tag, and GitHub release**

  **Goal:** Ship the work as v2.1.0 following the documented git workflow.

  **Requirements:** R5

  **Dependencies:** Units 1 and 2 (all fixes must be in before release)

  **Files:**
  - Modify: `pyproject.toml` (version field: `2.0.0` → `2.1.0`)
  - Modify: `CHANGELOG.md` (add `[2.1.0]` entry above `[2.0.0]`)
  - Modified: `mcp_intent.py` (`__version__ = "2.0.0"` → `"2.1.0"`)

  **Approach:**
  - CHANGELOG entry should document: 3 new tools (manage_rpz_policies, manage_dnssec,
    manage_doh), 5 extended tools (manage_network ip_space, manage_dhcp +7 resource types,
    manage_dns_zone +7 resource types + copy action, manage_ip_reservation IPAM host routing,
    manage_security_policy full policy/rule/network_list CRUD), 3 validation functions added,
    and the manage_doh NameError fix
  - Follow MEMORY.md git workflow exactly: feature branch → bump → changelog → commit → push
    → `gh pr create` → `gh pr checks --watch` → `gh pr merge` → main checkout → tag → push
    tag → `gh release create`
  - Branch name: `feat/full-api-coverage` is already the implied branch name from session
    context; use or create it

  **Test scenarios:**
  - Test expectation: none — version bump and release are process steps, not behavioral
    changes

  **Verification:**
  - `grep '^version' pyproject.toml` outputs `version = "2.1.0"`
  - `grep '__version__' mcp_intent.py` outputs `__version__ = "2.1.0"`
  - `gh pr checks <number> --watch` — all three CI jobs (lint, test, docker) pass
  - `gh release view v2.1.0` — release exists with correct notes

## System-Wide Impact

- **API surface parity:** `manage_doh` is the only tool affected by the runtime bug. The
  fix does not change its external parameter schema or response shape.
- **CI contract:** The tool count assertion is the only external contract surface being
  changed. It is internal to this repo's CI; no downstream consumers depend on it.
- **Unchanged invariants:** All 25 existing tools, their signatures, test coverage, and
  response envelopes are unchanged. The `resource_tool_catalog` resource gains 3 entries but
  its schema is unchanged.
- **Startup print:** The HTTP startup banner is cosmetic; no clients parse it.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Ruff linting rejects the new test class style | Follow the exact class + mock pattern from existing test classes in `tests/test_tools.py`; run `uv run ruff check` before pushing |
| `manage_doh` has additional undefined names beyond `security_client` | `grep "security_client" mcp_intent.py` confirms only 9 occurrences, all in `manage_doh`; no other undefined names present |
| CI docker job fails on import | Unit 1 fix is a pure rename; module imports correctly after the change |
| PR blocked by non-test changes to `uv.lock` | `uv.lock` is already modified (appears in `git status`) — stage it in the same commit as other changes |

## Sources & References

- Related code: `mcp_intent.py:5171–5255` (manage_doh), `mcp_intent.py:5442` (resource_tool_catalog)
- CI workflow: `.github/workflows/ci.yml:51–55`
- Git workflow: `MEMORY.md` (git-workflow.md)
