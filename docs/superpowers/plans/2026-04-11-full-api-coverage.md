# Full API Coverage Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose all 134 currently unreachable API methods through the 23 intent-level MCP tools, adding 4 new tools and extending 6 existing ones.

**Architecture:** All changes are confined to `mcp_intent.py`. Each extension follows the established pattern: widen the `Literal` type unions in the function signature, add new dispatch branches in the `try:` block, preserve the existing `except Exception as e` at the bottom. Three new standalone tools follow the identical pattern of existing tools. Tests go in `tests/test_tools.py` and `tests/test_validation.py`.

**Tech Stack:** Python 3.10+, FastMCP, existing service clients (`InfobloxClient`, `AtcfwClient`, `InsightsClient`)

---

## Files Changed

- Modify: `mcp_intent.py` — extend 6 existing tools, add 3 new tools
- Modify: `tests/test_tools.py` — add tests for all new actions/resource types

---

## Task 1: Extend `manage_security_policy` — policy CRUD + policy rules + network lists

**Context:** Currently `policy` resource_type is read-only (list/get). The docstring says so explicitly. The client has `create_security_policy`, `update_security_policy`, `delete_security_policy`, `list/create/get/update/delete_security_policy_rule`, `list/create/get/update/delete_network_list`, and `partial_update_network_list_items`. None are wired.

**Location:** `mcp_intent.py:3702–3986`

- [ ] **Step 1: Write failing tests**

```python
# In tests/test_tools.py
def test_manage_security_policy_create_policy_requires_name(mock_clients):
    from mcp_intent import manage_security_policy
    result = manage_security_policy(resource_type="policy", action="create")
    assert result["status"] == "failed"
    assert "name" in result["summary"].lower()

def test_manage_security_policy_create_policy_dry_run(mock_clients):
    from mcp_intent import manage_security_policy
    result = manage_security_policy(resource_type="policy", action="create", name="test-policy", dry_run=True)
    assert result["status"] == "success"
    assert "DRY RUN" in result["summary"]

def test_manage_security_policy_policy_rules_list(mock_clients):
    from mcp_intent import manage_security_policy
    result = manage_security_policy(resource_type="policy_rule", action="list", resource_id="pol-1")
    assert result["status"] in ("success", "failed")  # fails without live API but must not error

def test_manage_security_policy_network_list_create_dry_run(mock_clients):
    from mcp_intent import manage_security_policy
    result = manage_security_policy(resource_type="network_list", action="create", name="office-nets", items=["10.0.0.0/8"], dry_run=True)
    assert result["status"] == "success"
    assert "DRY RUN" in result["summary"]

def test_manage_security_policy_invalid_resource_type(mock_clients):
    from mcp_intent import manage_security_policy
    result = manage_security_policy(resource_type="bogus", action="list")
    assert result["status"] == "failed"
```

- [ ] **Step 2: Run to confirm failures**
```bash
uv run pytest tests/test_tools.py -k "test_manage_security_policy" --tb=short -q
```
Expected: FAIL — resource_types "policy_rule" and "network_list" not accepted; `create` on `policy` returns "read-only" error.

- [ ] **Step 3: Widen the Literal unions in the function signature**

Replace the `manage_security_policy` signature at line ~3702:
```python
def manage_security_policy(
    resource_type: Literal["policy", "named_list", "app_filter", "internal_domains", "access_code", "category_filter", "policy_rule", "network_list"],
    action: Literal["create", "update", "delete", "list", "get", "add_items", "remove_items"],
```

- [ ] **Step 4: Remove the read-only guard on `policy` and replace with full CRUD**

Remove the block at line ~3772–3774:
```python
    # Policies are read-only
    if resource_type == "policy" and action not in ("list", "get"):
        return intent_response("failed", "Security policies are read-only via API. Use 'list' or 'get' only.")
```

Add policy_rule to the add_items/remove_items guard:
```python
    if action in ("add_items", "remove_items") and resource_type not in ("named_list", "network_list"):
        return intent_response("failed", f"'{action}' is only supported for named_list and network_list.")
```

Update `validate_resource_type` call:
```python
    valid, err = validate_resource_type(
        resource_type,
        ["policy", "named_list", "app_filter", "internal_domains", "access_code", "category_filter", "policy_rule", "network_list"],
    )
```

- [ ] **Step 5: Add policy CRUD branches inside `action == "list"`**

After the `category_filter` list branch (line ~3844), before `steps.append(step_result("List..."))`:
```python
            elif resource_type == "policy_rule":
                if not resource_id:
                    return intent_response("failed", "policy_rule list requires 'resource_id' (policy ID).", steps)
                resp = atcfw_client.list_security_policy_rules(resource_id)
                items_list = extract_results(resp)
                result = [{"id": r.get("id"), "action": r.get("action"), "priority": r.get("priority")} for r in items_list]
            elif resource_type == "network_list":
                resp = atcfw_client.list_network_lists(limit=100)
                items_list = extract_results(resp)
                result = [{"id": n.get("id"), "name": n.get("name"), "item_count": len(n.get("items", []))} for n in items_list]
```

- [ ] **Step 6: Add branches inside `action == "get"`**

After the existing `category_filter` get branch:
```python
            elif resource_type == "policy_rule":
                if not resource_id or "|" not in resource_id:
                    return intent_response("failed", "policy_rule get requires resource_id in format 'policy_id|rule_id'.", steps)
                policy_id, rule_id = resource_id.split("|", 1)
                resp = atcfw_client.get_security_policy_rule(policy_id, rule_id)
                result = resp.get("result", resp)
                steps.append(step_result("Get policy rule", "success", {"id": resource_id}))
                return intent_response("success", "Retrieved policy rule", steps, result=result)
            elif resource_type == "network_list":
                resp = atcfw_client.get_network_list(resource_id)
                result = resp.get("result", resp)
                steps.append(step_result("Get network list", "success", {"id": resource_id}))
                return intent_response("success", f"Retrieved network list {resource_id}", steps, result=result)
```

Also extend the `get` dispatch to support `policy` by name lookup and `app_filter`, `internal_domains`, `access_code`:
```python
            elif resource_type == "app_filter":
                resp = atcfw_client.get_application_filter(resource_id)
                result = resp.get("result", resp)
                steps.append(step_result("Get app filter", "success", {"id": resource_id}))
                return intent_response("success", f"Retrieved app filter {resource_id}", steps, result=result)
            elif resource_type == "internal_domains":
                resp = atcfw_client.get_internal_domain_list(resource_id)
                result = resp.get("result", resp)
                steps.append(step_result("Get internal domain list", "success", {"id": resource_id}))
                return intent_response("success", f"Retrieved internal domain list {resource_id}", steps, result=result)
            elif resource_type == "access_code":
                resp = atcfw_client.get_access_code(resource_id)
                result = resp.get("result", resp)
                steps.append(step_result("Get access code", "success", {"id": resource_id}))
                return intent_response("success", f"Retrieved access code {resource_id}", steps, result=result)
```

- [ ] **Step 7: Add branches inside `action == "create"`**

After the `category_filter` create branch, before `result = resp.get(...)`:
```python
            elif resource_type == "policy":
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would create security policy '{name}'", steps,
                        result={"mode": "DRY RUN", "name": name, "rules": rules or []},
                        warnings=["Set dry_run=False to create."],
                        next_actions=[f"Execute: manage_security_policy(resource_type='policy', action='create', name='{name}', dry_run=False)"])
                resp = atcfw_client.create_security_policy(name=name, rules=rules or [])
            elif resource_type == "policy_rule":
                if not resource_id:
                    return intent_response("failed", "policy_rule create requires 'resource_id' (policy ID).", steps)
                if not rules or len(rules) != 1:
                    return intent_response("failed", "policy_rule create requires 'rules' with exactly one rule dict.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would create rule in policy {resource_id}", steps,
                        result={"mode": "DRY RUN", "policy_id": resource_id, "rule": rules[0]},
                        warnings=["Set dry_run=False to create."],
                        next_actions=[f"Execute with dry_run=False"])
                resp = atcfw_client.create_security_policy_rule(resource_id, rules[0])
            elif resource_type == "network_list":
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would create network list '{name}'", steps,
                        result={"mode": "DRY RUN", "name": name, "items": items or []},
                        warnings=["Set dry_run=False to create."],
                        next_actions=[f"Execute: manage_security_policy(resource_type='network_list', action='create', name='{name}', dry_run=False)"])
                resp = atcfw_client.create_network_list(name=name, items=items or [])
```

- [ ] **Step 8: Add branches inside `action == "update"`**

After the `category_filter` update branch:
```python
            elif resource_type == "policy":
                if not resource_id:
                    return intent_response("failed", "policy update requires 'resource_id'.", steps)
                updates = {}
                if name:
                    updates["name"] = name
                if rules is not None:
                    updates["rules"] = rules
                if description is not None:
                    updates["description"] = description
                if not updates:
                    return intent_response("failed", "No update fields provided for policy.", steps)
                resp = atcfw_client.update_security_policy(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update security policy", "success", {"id": resource_id}))
                return intent_response("success", f"Updated security policy {resource_id}", steps, result=result)
            elif resource_type == "policy_rule":
                if not resource_id or "|" not in resource_id:
                    return intent_response("failed", "policy_rule update requires resource_id in format 'policy_id|rule_id'.", steps)
                policy_id, rule_id = resource_id.split("|", 1)
                if not rules or len(rules) != 1:
                    return intent_response("failed", "policy_rule update requires 'rules' with exactly one rule dict.", steps)
                resp = atcfw_client.update_security_policy_rule(policy_id, rule_id, rules[0])
                result = resp.get("result", resp)
                steps.append(step_result("Update policy rule", "success", {"id": resource_id}))
                return intent_response("success", f"Updated policy rule {resource_id}", steps, result=result)
            elif resource_type == "network_list":
                if not resource_id:
                    return intent_response("failed", "network_list update requires 'resource_id'.", steps)
                updates = {}
                if name:
                    updates["name"] = name
                if items is not None:
                    updates["items"] = items
                if description is not None:
                    updates["description"] = description
                resp = atcfw_client.update_network_list(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update network list", "success", {"id": resource_id}))
                return intent_response("success", f"Updated network list {resource_id}", steps, result=result)
            elif resource_type == "app_filter":
                if not resource_id:
                    return intent_response("failed", "app_filter update requires 'resource_id'.", steps)
                updates = {}
                if name:
                    updates["name"] = name
                if criteria is not None:
                    updates["criteria"] = criteria
                if description is not None:
                    updates["description"] = description
                resp = atcfw_client.update_application_filter(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update app filter", "success", {"id": resource_id}))
                return intent_response("success", f"Updated app filter {resource_id}", steps, result=result)
            elif resource_type == "internal_domains":
                if not resource_id:
                    return intent_response("failed", "internal_domains update requires 'resource_id'.", steps)
                updates = {}
                if name:
                    updates["name"] = name
                if items is not None:
                    updates["internal_domains"] = items
                resp = atcfw_client.update_internal_domain_list(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update internal domain list", "success", {"id": resource_id}))
                return intent_response("success", f"Updated internal domain list {resource_id}", steps, result=result)
            elif resource_type == "access_code":
                if not resource_id:
                    return intent_response("failed", "access_code update requires 'resource_id'.", steps)
                updates = {}
                if name:
                    updates["name"] = name
                if activation:
                    updates["activation"] = activation
                if expiration:
                    updates["expiration"] = expiration
                if rules is not None:
                    updates["rules"] = rules
                resp = atcfw_client.update_access_code(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update access code", "success", {"id": resource_id}))
                return intent_response("success", f"Updated access code {resource_id}", steps, result=result)
```

- [ ] **Step 9: Extend `action == "delete"` to cover all resource types + policy + policy_rule + network_list**

Replace the existing delete block:
```python
        elif action == "delete":
            if not resource_id:
                return intent_response("failed", "Delete requires 'resource_id'.", steps)
            if dry_run:
                return intent_response("success", f"DRY RUN: Would delete {resource_type} {resource_id}", steps,
                    result={"resource_id": resource_id},
                    warnings=["Set dry_run=False to execute."],
                    next_actions=[f"Execute: manage_security_policy(resource_type='{resource_type}', action='delete', resource_id='{resource_id}', dry_run=False)"])
            if resource_type == "policy":
                atcfw_client.delete_security_policy(resource_id)
            elif resource_type == "policy_rule":
                if "|" not in resource_id:
                    return intent_response("failed", "policy_rule delete requires resource_id in format 'policy_id|rule_id'.", steps)
                policy_id, rule_id = resource_id.split("|", 1)
                atcfw_client.delete_security_policy_rule(policy_id, rule_id)
            elif resource_type == "named_list":
                atcfw_client.delete_named_list(resource_id)
            elif resource_type == "category_filter":
                atcfw_client.delete_category_filter(resource_id)
            elif resource_type == "network_list":
                atcfw_client.delete_network_list(resource_id)
            elif resource_type == "app_filter":
                atcfw_client.delete_application_filter(resource_id)
            elif resource_type == "internal_domains":
                atcfw_client.delete_internal_domain_list(resource_id)
            elif resource_type == "access_code":
                atcfw_client.delete_access_code(resource_id)
            else:
                return intent_response("failed", f"Delete not supported for resource_type '{resource_type}'.", steps)
            steps.append(step_result(f"Delete {resource_type}", "success", {"id": resource_id}))
            return intent_response("success", f"Deleted {resource_type} {resource_id}", steps)
```

- [ ] **Step 10: Extend `action == "add_items"/"remove_items"` for network_list**

After the named_list partial update block:
```python
            elif resource_type == "network_list":
                # items_described format: [{"addr": "10.0.0.0/8", "is_deleted": false}, ...]
                items_described = [{"addr": item, "is_deleted": action == "remove_items"} for item in items]
                resp = atcfw_client.partial_update_network_list_items(resource_id, items_described)
                result = resp.get("result", resp)
                verb = "Added" if action == "add_items" else "Removed"
                steps.append(step_result(f"{verb} items from network list", "success", {"id": resource_id, "items": items}))
                return intent_response("success", f"{verb} {len(items)} item(s) in network list {resource_id}", steps, result=result)
```

- [ ] **Step 11: Run tests**
```bash
uv run pytest tests/test_tools.py -k "test_manage_security_policy" --tb=short -q
```
Expected: All pass.

- [ ] **Step 12: Run full suite to confirm nothing broken**
```bash
uv run pytest tests/ --tb=short -q
```
Expected: 163+ passed, 0 failed.

---

## Task 2: Extend `manage_network` — IP space CRUD

**Context:** `manage_network` already accepts `resource_type="ip_space"` in the Literal, but `create_ip_space`, `get_ip_space`, `update_ip_space`, `delete_ip_space` are never called. Only `list_ip_spaces` is used (in resolvers). The action dispatch for `ip_space` currently falls through to the same subnet/block paths and produces wrong results.

**Location:** `mcp_intent.py:2249` — look for the action dispatch inside `manage_network`.

- [ ] **Step 1: Write failing tests**

```python
def test_manage_network_ip_space_create_dry_run(mock_clients):
    from mcp_intent import manage_network
    result = manage_network(resource_type="ip_space", action="create", name="prod", dry_run=True)
    assert result["status"] == "success"
    assert "DRY RUN" in result["summary"]

def test_manage_network_ip_space_create_requires_name(mock_clients):
    from mcp_intent import manage_network
    result = manage_network(resource_type="ip_space", action="create", dry_run=False)
    assert result["status"] == "failed"
    assert "name" in result["summary"].lower()

def test_manage_network_ip_space_list(mock_clients):
    from mcp_intent import manage_network
    result = manage_network(resource_type="ip_space", action="list")
    assert result["status"] in ("success", "failed")
```

- [ ] **Step 2: Run to confirm failures**
```bash
uv run pytest tests/test_tools.py -k "test_manage_network_ip_space" --tb=short -q
```

- [ ] **Step 3: Find the ip_space dispatch section inside `manage_network`**

Read lines 2300–2580 to find where ip_space is (or isn't) handled in the action dispatch.

- [ ] **Step 4: Add ip_space CRUD to the dispatch**

Inside `manage_network`'s `try:` block, add a top-level `ip_space` branch before or alongside the existing `subnet`/`address_block`/`range` branches:

```python
        # ── IP Space ────────────────────────────────────────────
        if resource_type == "ip_space":
            if action == "list":
                filter_expr = f'name~"{sanitize_filter(name)}"' if name else None
                resp = client.list_ip_spaces(filter=filter_expr, limit=100)
                spaces = extract_results(resp)
                steps.append(step_result("List IP spaces", "success", {"count": len(spaces)}))
                result = [{"id": s.get("id"), "name": s.get("name"), "comment": s.get("comment", "")} for s in spaces]
                return intent_response("success", f"Found {len(spaces)} IP space(s)", steps, result=result)

            elif action == "create":
                if not name:
                    return intent_response("failed", "IP space create requires 'name'.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would create IP space '{name}'", steps,
                        result={"mode": "DRY RUN", "name": name, "comment": comment},
                        warnings=["Set dry_run=False to create."],
                        next_actions=[f"Execute: manage_network(resource_type='ip_space', action='create', name='{name}', dry_run=False)"])
                resp = client.create_ip_space(name=name, comment=comment)
                result = resp.get("result", resp)
                steps.append(step_result("Create IP space", "success", {"id": result.get("id"), "name": name}))
                return intent_response("success", f"Created IP space '{name}'", steps, result=result,
                    next_actions=[f"Create subnets: manage_network(resource_type='subnet', action='create', space='{name}', address='x.x.x.x/y')"])

            elif action == "get":
                if not resource_id:
                    return intent_response("failed", "IP space get requires 'resource_id'.", steps)
                resp = client.get_ip_space(resource_id)
                result = resp.get("result", resp)
                steps.append(step_result("Get IP space", "success", {"id": resource_id}))
                return intent_response("success", f"Retrieved IP space {resource_id}", steps, result=result)

            elif action == "update":
                if not resource_id:
                    return intent_response("failed", "IP space update requires 'resource_id'.", steps)
                updates = {}
                if name:
                    updates["name"] = name
                if comment is not None:
                    updates["comment"] = comment
                if tags is not None:
                    updates["tags"] = tags
                if not updates:
                    return intent_response("failed", "No update fields provided.", steps)
                resp = client.update_ip_space(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update IP space", "success", {"id": resource_id}))
                return intent_response("success", f"Updated IP space {resource_id}", steps, result=result)

            elif action == "delete":
                if not resource_id:
                    return intent_response("failed", "IP space delete requires 'resource_id'.", steps)
                if dry_run:
                    resp = client.get_ip_space(resource_id)
                    space = resp.get("result", resp)
                    return intent_response("success", f"DRY RUN: Would delete IP space '{space.get('name', resource_id)}'", steps,
                        result={"mode": "DRY RUN", "id": resource_id, "name": space.get("name")},
                        warnings=["Deleting an IP space removes ALL subnets, hosts, and reservations within it. Set dry_run=False to execute."],
                        next_actions=[f"Execute: manage_network(resource_type='ip_space', action='delete', resource_id='{resource_id}', dry_run=False)"])
                client.delete_ip_space(resource_id)
                steps.append(step_result("Delete IP space", "success", {"id": resource_id}))
                return intent_response("success", f"Deleted IP space {resource_id}", steps)

            else:
                return intent_response("failed", f"Action '{action}' not supported for ip_space. Supported: create, get, update, delete, list.", steps)
```

- [ ] **Step 5: Run tests and full suite**
```bash
uv run pytest tests/test_tools.py -k "test_manage_network_ip_space" --tb=short -q
uv run pytest tests/ --tb=short -q
```
Expected: All pass.

---

## Task 3: Extend `manage_dhcp` — servers, option groups, option spaces, MAC items, DHCP hosts, config profiles, global config

**Context:** `manage_dhcp` at line 3148 currently handles: `ha_group`, `option_code`, `hardware_filter`, `option_filter`, `hardware`. Missing: `dhcp_server`, `option_group`, `option_space`, `mac_item`, `dhcp_host`, `config_profile`, `dhcp_global`. All client methods exist.

**Location:** `mcp_intent.py:3148`

- [ ] **Step 1: Write failing tests**

```python
def test_manage_dhcp_server_list(mock_clients):
    from mcp_intent import manage_dhcp
    result = manage_dhcp(resource_type="dhcp_server", action="list")
    assert result["status"] in ("success", "failed")

def test_manage_dhcp_server_create_dry_run(mock_clients):
    from mcp_intent import manage_dhcp
    result = manage_dhcp(resource_type="dhcp_server", action="create", name="dhcp-primary", dry_run=True)
    assert result["status"] == "success"
    assert "DRY RUN" in result["summary"]

def test_manage_dhcp_mac_item_create_dry_run(mock_clients):
    from mcp_intent import manage_dhcp
    result = manage_dhcp(resource_type="mac_item", action="create", mac_address="AA:BB:CC:DD:EE:FF", dry_run=True)
    assert result["status"] == "success"

def test_manage_dhcp_option_group_create_dry_run(mock_clients):
    from mcp_intent import manage_dhcp
    result = manage_dhcp(resource_type="option_group", action="create", name="standard-opts", dry_run=True)
    assert result["status"] == "success"

def test_manage_dhcp_invalid_resource_type(mock_clients):
    from mcp_intent import manage_dhcp
    result = manage_dhcp(resource_type="bogus", action="list")
    assert result["status"] == "failed"
```

- [ ] **Step 2: Run to confirm failures**
```bash
uv run pytest tests/test_tools.py -k "test_manage_dhcp" --tb=short -q
```

- [ ] **Step 3: Widen the Literal type**

Replace the `manage_dhcp` signature:
```python
def manage_dhcp(
    resource_type: Literal[
        "ha_group", "option_code", "hardware_filter", "option_filter", "hardware",
        "dhcp_server", "option_group", "option_space", "mac_item", "dhcp_host",
        "config_profile", "dhcp_global"
    ],
    action: Literal["create", "update", "delete", "get", "list", "bulk_create", "link", "delink"],
```

Also add parameter `bulk_items: list[dict[str, Any]] | None = None` for bulk MAC creation.

- [ ] **Step 4: Update `validate_resource_type` call in `manage_dhcp`**

```python
    valid, err = validate_resource_type(
        resource_type,
        ["ha_group", "option_code", "hardware_filter", "option_filter", "hardware",
         "dhcp_server", "option_group", "option_space", "mac_item", "dhcp_host",
         "config_profile", "dhcp_global"],
    )
```

- [ ] **Step 5: Add new resource type dispatch branches inside `manage_dhcp`'s try block**

Add after the existing `hardware` resource type handling:

```python
        # ── DHCP Server ─────────────────────────────────────────
        elif resource_type == "dhcp_server":
            if action == "list":
                resp = client.list_dhcp_servers(limit=100)
                items_list = extract_results(resp)
                steps.append(step_result("List DHCP servers", "success", {"count": len(items_list)}))
                result = [{"id": s.get("id"), "name": s.get("name"), "comment": s.get("comment", "")} for s in items_list]
                return intent_response("success", f"Found {len(items_list)} DHCP server(s)", steps, result=result)
            elif action == "get":
                if not resource_id:
                    return intent_response("failed", "DHCP server get requires 'resource_id'.", steps)
                resp = client.get_dhcp_server(resource_id)
                result = resp.get("result", resp)
                steps.append(step_result("Get DHCP server", "success", {"id": resource_id}))
                return intent_response("success", f"Retrieved DHCP server {resource_id}", steps, result=result)
            elif action == "create":
                if not name:
                    return intent_response("failed", "DHCP server create requires 'name'.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would create DHCP server '{name}'", steps,
                        result={"mode": "DRY RUN", "name": name},
                        warnings=["Set dry_run=False to create."],
                        next_actions=[f"Execute: manage_dhcp(resource_type='dhcp_server', action='create', name='{name}', dry_run=False)"])
                resp = client.create_dhcp_server(name=name, comment=comment)
                result = resp.get("result", resp)
                steps.append(step_result("Create DHCP server", "success", {"id": result.get("id"), "name": name}))
                return intent_response("success", f"Created DHCP server '{name}'", steps, result=result)
            elif action == "update":
                if not resource_id:
                    return intent_response("failed", "DHCP server update requires 'resource_id'.", steps)
                updates = {k: v for k, v in {"name": name, "comment": comment}.items() if v is not None}
                if not updates:
                    return intent_response("failed", "No update fields provided.", steps)
                resp = client.update_dhcp_server(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update DHCP server", "success", {"id": resource_id}))
                return intent_response("success", f"Updated DHCP server {resource_id}", steps, result=result)
            elif action == "delete":
                if not resource_id:
                    return intent_response("failed", "DHCP server delete requires 'resource_id'.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would delete DHCP server {resource_id}", steps,
                        warnings=["Set dry_run=False to execute."],
                        next_actions=[f"Execute: manage_dhcp(resource_type='dhcp_server', action='delete', resource_id='{resource_id}', dry_run=False)"])
                client.delete_dhcp_server(resource_id)
                steps.append(step_result("Delete DHCP server", "success", {"id": resource_id}))
                return intent_response("success", f"Deleted DHCP server {resource_id}", steps)

        # ── Option Group ─────────────────────────────────────────
        elif resource_type == "option_group":
            if action == "list":
                resp = client.list_option_groups(limit=100)
                items_list = extract_results(resp)
                steps.append(step_result("List option groups", "success", {"count": len(items_list)}))
                result = [{"id": g.get("id"), "name": g.get("name")} for g in items_list]
                return intent_response("success", f"Found {len(items_list)} option group(s)", steps, result=result)
            elif action == "get":
                if not resource_id:
                    return intent_response("failed", "Option group get requires 'resource_id'.", steps)
                resp = client.get_option_group(resource_id)
                result = resp.get("result", resp)
                steps.append(step_result("Get option group", "success", {"id": resource_id}))
                return intent_response("success", f"Retrieved option group {resource_id}", steps, result=result)
            elif action == "create":
                if not name:
                    return intent_response("failed", "Option group create requires 'name'.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would create option group '{name}'", steps,
                        warnings=["Set dry_run=False to create."])
                resp = client.create_option_group(name=name, comment=comment)
                result = resp.get("result", resp)
                steps.append(step_result("Create option group", "success", {"id": result.get("id"), "name": name}))
                return intent_response("success", f"Created option group '{name}'", steps, result=result)
            elif action == "update":
                if not resource_id:
                    return intent_response("failed", "Option group update requires 'resource_id'.", steps)
                updates = {k: v for k, v in {"name": name, "comment": comment}.items() if v is not None}
                resp = client.update_option_group(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update option group", "success", {"id": resource_id}))
                return intent_response("success", f"Updated option group {resource_id}", steps, result=result)
            elif action == "delete":
                if not resource_id:
                    return intent_response("failed", "Option group delete requires 'resource_id'.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would delete option group {resource_id}", steps,
                        warnings=["Set dry_run=False to execute."])
                client.delete_option_group(resource_id)
                steps.append(step_result("Delete option group", "success", {"id": resource_id}))
                return intent_response("success", f"Deleted option group {resource_id}", steps)

        # ── Option Space ─────────────────────────────────────────
        elif resource_type == "option_space":
            if action == "list":
                resp = client.list_option_spaces(limit=100)
                items_list = extract_results(resp)
                steps.append(step_result("List option spaces", "success", {"count": len(items_list)}))
                result = [{"id": s.get("id"), "name": s.get("name"), "protocol": s.get("protocol", "")} for s in items_list]
                return intent_response("success", f"Found {len(items_list)} option space(s)", steps, result=result)
            elif action == "get":
                if not resource_id:
                    return intent_response("failed", "Option space get requires 'resource_id'.", steps)
                resp = client.get_option_space(resource_id)
                result = resp.get("result", resp)
                steps.append(step_result("Get option space", "success", {"id": resource_id}))
                return intent_response("success", f"Retrieved option space {resource_id}", steps, result=result)
            elif action == "create":
                if not name:
                    return intent_response("failed", "Option space create requires 'name'.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would create option space '{name}'", steps,
                        warnings=["Set dry_run=False to create."])
                resp = client.create_option_space(name=name, comment=comment)
                result = resp.get("result", resp)
                steps.append(step_result("Create option space", "success", {"id": result.get("id"), "name": name}))
                return intent_response("success", f"Created option space '{name}'", steps, result=result)
            elif action == "update":
                if not resource_id:
                    return intent_response("failed", "Option space update requires 'resource_id'.", steps)
                updates = {k: v for k, v in {"name": name, "comment": comment}.items() if v is not None}
                resp = client.update_option_space(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update option space", "success", {"id": resource_id}))
                return intent_response("success", f"Updated option space {resource_id}", steps, result=result)
            elif action == "delete":
                if not resource_id:
                    return intent_response("failed", "Option space delete requires 'resource_id'.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would delete option space {resource_id}", steps,
                        warnings=["Set dry_run=False to execute."])
                client.delete_option_space(resource_id)
                steps.append(step_result("Delete option space", "success", {"id": resource_id}))
                return intent_response("success", f"Deleted option space {resource_id}", steps)

        # ── MAC Address Items ─────────────────────────────────────
        elif resource_type == "mac_item":
            if action == "list":
                resp = client.list_mac_address_items(limit=100)
                items_list = extract_results(resp)
                steps.append(step_result("List MAC items", "success", {"count": len(items_list)}))
                result = [{"id": m.get("id"), "mac": m.get("mac_address"), "comment": m.get("comment", "")} for m in items_list]
                return intent_response("success", f"Found {len(items_list)} MAC item(s)", steps, result=result)
            elif action == "get":
                if not resource_id:
                    return intent_response("failed", "MAC item get requires 'resource_id'.", steps)
                resp = client.get_mac_address_item(resource_id)
                result = resp.get("result", resp)
                steps.append(step_result("Get MAC item", "success", {"id": resource_id}))
                return intent_response("success", f"Retrieved MAC item {resource_id}", steps, result=result)
            elif action == "create":
                if not mac_address:
                    return intent_response("failed", "MAC item create requires 'mac_address'.", steps)
                valid, err = validate_mac(mac_address)
                if not valid:
                    return intent_response("failed", err)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would create MAC item for {mac_address}", steps,
                        warnings=["Set dry_run=False to create."])
                resp = client.create_mac_address_item(mac_address=mac_address, comment=comment)
                result = resp.get("result", resp)
                steps.append(step_result("Create MAC item", "success", {"id": result.get("id"), "mac": mac_address}))
                return intent_response("success", f"Created MAC item for {mac_address}", steps, result=result)
            elif action == "bulk_create":
                if not bulk_items:
                    return intent_response("failed", "MAC item bulk_create requires 'bulk_items' list.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would bulk create {len(bulk_items)} MAC item(s)", steps,
                        result={"mode": "DRY RUN", "count": len(bulk_items)},
                        warnings=["Set dry_run=False to create."])
                resp = client.bulk_create_mac_address_items(bulk_items)
                result = resp.get("result", resp)
                steps.append(step_result("Bulk create MAC items", "success", {"count": len(bulk_items)}))
                return intent_response("success", f"Bulk created {len(bulk_items)} MAC item(s)", steps, result=result)
            elif action == "update":
                if not resource_id:
                    return intent_response("failed", "MAC item update requires 'resource_id'.", steps)
                updates = {k: v for k, v in {"comment": comment}.items() if v is not None}
                if mac_address:
                    updates["mac_address"] = mac_address
                resp = client.update_mac_address_item(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update MAC item", "success", {"id": resource_id}))
                return intent_response("success", f"Updated MAC item {resource_id}", steps, result=result)
            elif action == "delete":
                if not resource_id:
                    return intent_response("failed", "MAC item delete requires 'resource_id'.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would delete MAC item {resource_id}", steps,
                        warnings=["Set dry_run=False to execute."])
                client.delete_mac_address_item(resource_id)
                steps.append(step_result("Delete MAC item", "success", {"id": resource_id}))
                return intent_response("success", f"Deleted MAC item {resource_id}", steps)

        # ── DHCP Host ──────────────────────────────────────────────
        elif resource_type == "dhcp_host":
            if action == "list":
                resp = client.list_dhcp_hosts(limit=100)
                items_list = extract_results(resp)
                steps.append(step_result("List DHCP hosts", "success", {"count": len(items_list)}))
                result = [{"id": h.get("id"), "name": h.get("name"), "server_id": h.get("server", {}).get("id", "")} for h in items_list]
                return intent_response("success", f"Found {len(items_list)} DHCP host(s)", steps, result=result)
            elif action == "get":
                if not resource_id:
                    return intent_response("failed", "DHCP host get requires 'resource_id'.", steps)
                resp = client.get_dhcp_host(resource_id)
                result = resp.get("result", resp)
                steps.append(step_result("Get DHCP host", "success", {"id": resource_id}))
                return intent_response("success", f"Retrieved DHCP host {resource_id}", steps, result=result)
            elif action == "update":
                if not resource_id:
                    return intent_response("failed", "DHCP host update requires 'resource_id'.", steps)
                updates = {k: v for k, v in {"name": name, "comment": comment}.items() if v is not None}
                if not updates:
                    return intent_response("failed", "No update fields provided.", steps)
                resp = client.update_dhcp_host(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update DHCP host", "success", {"id": resource_id}))
                return intent_response("success", f"Updated DHCP host {resource_id}", steps, result=result)
            else:
                return intent_response("failed", f"DHCP host supports: list, get, update. '{action}' not supported.", steps)

        # ── Config Profile ─────────────────────────────────────────
        elif resource_type == "config_profile":
            if action == "list":
                if not resource_id:
                    return intent_response("failed", "Config profile list requires 'resource_id' (object ID).", steps)
                resp = client.list_config_profiles(resource_id, limit=100)
                items_list = extract_results(resp)
                steps.append(step_result("List config profiles", "success", {"count": len(items_list)}))
                return intent_response("success", f"Found {len(items_list)} config profile(s)", steps, result=items_list)
            elif action == "link":
                if not resource_id or not name:
                    return intent_response("failed", "Config profile link requires 'resource_id' (profile ID) and 'name' (object ID).", steps)
                resp = client.link_config_profile(resource_id, name)
                steps.append(step_result("Link config profile", "success", {"profile_id": resource_id, "object_id": name}))
                return intent_response("success", f"Linked config profile {resource_id} to {name}", steps)
            elif action == "delink":
                if not resource_id or not name:
                    return intent_response("failed", "Config profile delink requires 'resource_id' (profile ID) and 'name' (object ID).", steps)
                resp = client.delink_config_profile(resource_id, name)
                steps.append(step_result("Delink config profile", "success", {"profile_id": resource_id, "object_id": name}))
                return intent_response("success", f"Delinked config profile {resource_id} from {name}", steps)
            else:
                return intent_response("failed", f"Config profile supports: list, link, delink. '{action}' not supported.", steps)

        # ── DHCP Global Config ─────────────────────────────────────
        elif resource_type == "dhcp_global":
            if action == "get":
                resp = client.get_dhcp_global()
                result = resp.get("result", resp)
                steps.append(step_result("Get DHCP global config", "success", {}))
                return intent_response("success", "Retrieved DHCP global config", steps, result=result)
            elif action == "update":
                if not resource_id:
                    return intent_response("failed", "DHCP global update requires 'resource_id' (global config ID).", steps)
                # Accept arbitrary updates via the `hosts` parameter (repurposed for generic dict payload)
                # For DHCP global, caller passes updates as a comment or hosts field
                updates = {}
                if comment:
                    updates["comment"] = comment
                if hosts:
                    updates.update({k: v for item in hosts for k, v in item.items()})
                if not updates:
                    return intent_response("failed", "No update fields provided for DHCP global.", steps)
                resp = client.update_dhcp_global(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update DHCP global config", "success", {}))
                return intent_response("success", "Updated DHCP global config", steps, result=result)
            else:
                return intent_response("failed", f"DHCP global supports: get, update. '{action}' not supported.", steps)
```

- [ ] **Step 6: Run tests and full suite**
```bash
uv run pytest tests/test_tools.py -k "test_manage_dhcp" --tb=short -q
uv run pytest tests/ --tb=short -q
```

---

## Task 4: Extend `manage_dns_zone` — ACLs, auth/forward NSGs, DNS servers, DNS services/hosts

**Context:** `manage_dns_zone` at line 2583 handles: `auth_zone`, `forward_zone`, `dns_view`, `rpz`, `delegation`. Missing resource types: `dns_acl`, `auth_nsg`, `forward_nsg`, `dns_server`, `dns_service`, `dns_host`. Also missing operations: zone copy (`copy` action for `auth_zone`/`forward_zone`).

**Location:** `mcp_intent.py:2583`

- [ ] **Step 1: Write failing tests**

```python
def test_manage_dns_zone_dns_acl_list(mock_clients):
    from mcp_intent import manage_dns_zone
    result = manage_dns_zone(action="list", resource_type="dns_acl")
    assert result["status"] in ("success", "failed")

def test_manage_dns_zone_dns_acl_create_dry_run(mock_clients):
    from mcp_intent import manage_dns_zone
    result = manage_dns_zone(action="create", resource_type="dns_acl", name="internal-acl", dry_run=True)
    assert result["status"] == "success"
    assert "DRY RUN" in result["summary"]

def test_manage_dns_zone_auth_nsg_create_dry_run(mock_clients):
    from mcp_intent import manage_dns_zone
    result = manage_dns_zone(action="create", resource_type="auth_nsg", name="primary-nsg", dry_run=True)
    assert result["status"] == "success"

def test_manage_dns_zone_dns_server_list(mock_clients):
    from mcp_intent import manage_dns_zone
    result = manage_dns_zone(action="list", resource_type="dns_server")
    assert result["status"] in ("success", "failed")

def test_manage_dns_zone_copy_action(mock_clients):
    from mcp_intent import manage_dns_zone
    result = manage_dns_zone(action="copy", resource_type="auth_zone", resource_id="dns/auth_zone/abc", view="default-view", dry_run=True)
    assert result["status"] == "success"
```

- [ ] **Step 2: Run to confirm failures**
```bash
uv run pytest tests/test_tools.py -k "test_manage_dns_zone" --tb=short -q
```

- [ ] **Step 3: Widen the Literal types**

```python
def manage_dns_zone(
    action: Literal["create", "update", "delete", "list", "get", "sign", "unsign", "dnssec_status", "reorder", "copy"],
    resource_type: Literal[
        "auth_zone", "forward_zone", "dns_view", "rpz", "delegation",
        "dns_acl", "auth_nsg", "forward_nsg", "dns_server", "dns_service", "dns_host"
    ] = "auth_zone",
```

Also add parameter `target_view: str | None = None` for zone copy.

- [ ] **Step 4: Add new resource type dispatch branches**

After the existing `delegation` handling, add:

```python
        # ── DNS ACL ───────────────────────────────────────────────
        elif resource_type == "dns_acl":
            if action == "list":
                resp = client.list_dns_acls(limit=100)
                items_list = extract_results(resp)
                steps.append(step_result("List DNS ACLs", "success", {"count": len(items_list)}))
                result = [{"id": a.get("id"), "name": a.get("name"), "comment": a.get("comment", "")} for a in items_list]
                return intent_response("success", f"Found {len(items_list)} DNS ACL(s)", steps, result=result)
            elif action == "get":
                if not resource_id:
                    return intent_response("failed", "DNS ACL get requires 'resource_id'.", steps)
                resp = client.get_dns_acl(resource_id)
                result = resp.get("result", resp)
                steps.append(step_result("Get DNS ACL", "success", {"id": resource_id}))
                return intent_response("success", f"Retrieved DNS ACL {resource_id}", steps, result=result)
            elif action == "create":
                if not name:
                    return intent_response("failed", "DNS ACL create requires 'name'.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would create DNS ACL '{name}'", steps,
                        warnings=["Set dry_run=False to create."])
                resp = client.create_dns_acl(name=name, comment=comment)
                result = resp.get("result", resp)
                steps.append(step_result("Create DNS ACL", "success", {"id": result.get("id"), "name": name}))
                return intent_response("success", f"Created DNS ACL '{name}'", steps, result=result)
            elif action == "update":
                if not resource_id:
                    return intent_response("failed", "DNS ACL update requires 'resource_id'.", steps)
                updates = {k: v for k, v in {"name": name, "comment": comment}.items() if v is not None}
                resp = client.update_dns_acl(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update DNS ACL", "success", {"id": resource_id}))
                return intent_response("success", f"Updated DNS ACL {resource_id}", steps, result=result)
            elif action == "delete":
                if not resource_id:
                    return intent_response("failed", "DNS ACL delete requires 'resource_id'.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would delete DNS ACL {resource_id}", steps,
                        warnings=["Set dry_run=False to execute."])
                client.delete_dns_acl(resource_id)
                steps.append(step_result("Delete DNS ACL", "success", {"id": resource_id}))
                return intent_response("success", f"Deleted DNS ACL {resource_id}", steps)

        # ── Auth NSG ──────────────────────────────────────────────
        elif resource_type == "auth_nsg":
            if action == "list":
                resp = client.list_auth_nsgs(limit=100)
                items_list = extract_results(resp)
                steps.append(step_result("List auth NSGs", "success", {"count": len(items_list)}))
                result = [{"id": n.get("id"), "name": n.get("name")} for n in items_list]
                return intent_response("success", f"Found {len(items_list)} auth NSG(s)", steps, result=result)
            elif action == "get":
                if not resource_id:
                    return intent_response("failed", "Auth NSG get requires 'resource_id'.", steps)
                resp = client.get_auth_nsg(resource_id)
                result = resp.get("result", resp)
                steps.append(step_result("Get auth NSG", "success", {"id": resource_id}))
                return intent_response("success", f"Retrieved auth NSG {resource_id}", steps, result=result)
            elif action == "create":
                if not name:
                    return intent_response("failed", "Auth NSG create requires 'name'.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would create auth NSG '{name}'", steps,
                        warnings=["Set dry_run=False to create."])
                resp = client.create_auth_nsg(name=name, comment=comment)
                result = resp.get("result", resp)
                steps.append(step_result("Create auth NSG", "success", {"id": result.get("id"), "name": name}))
                return intent_response("success", f"Created auth NSG '{name}'", steps, result=result)
            elif action == "update":
                if not resource_id:
                    return intent_response("failed", "Auth NSG update requires 'resource_id'.", steps)
                updates = {k: v for k, v in {"name": name, "comment": comment}.items() if v is not None}
                resp = client.update_auth_nsg(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update auth NSG", "success", {"id": resource_id}))
                return intent_response("success", f"Updated auth NSG {resource_id}", steps, result=result)
            elif action == "delete":
                if not resource_id:
                    return intent_response("failed", "Auth NSG delete requires 'resource_id'.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would delete auth NSG {resource_id}", steps,
                        warnings=["Set dry_run=False to execute."])
                client.delete_auth_nsg(resource_id)
                steps.append(step_result("Delete auth NSG", "success", {"id": resource_id}))
                return intent_response("success", f"Deleted auth NSG {resource_id}", steps)

        # ── Forward NSG ───────────────────────────────────────────
        elif resource_type == "forward_nsg":
            if action == "list":
                resp = client.list_forward_nsgs(limit=100)
                items_list = extract_results(resp)
                steps.append(step_result("List forward NSGs", "success", {"count": len(items_list)}))
                result = [{"id": n.get("id"), "name": n.get("name")} for n in items_list]
                return intent_response("success", f"Found {len(items_list)} forward NSG(s)", steps, result=result)
            elif action == "get":
                if not resource_id:
                    return intent_response("failed", "Forward NSG get requires 'resource_id'.", steps)
                resp = client.get_forward_nsg(resource_id)
                result = resp.get("result", resp)
                steps.append(step_result("Get forward NSG", "success", {"id": resource_id}))
                return intent_response("success", f"Retrieved forward NSG {resource_id}", steps, result=result)
            elif action == "create":
                if not name:
                    return intent_response("failed", "Forward NSG create requires 'name'.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would create forward NSG '{name}'", steps,
                        warnings=["Set dry_run=False to create."])
                resp = client.create_forward_nsg(name=name, comment=comment)
                result = resp.get("result", resp)
                steps.append(step_result("Create forward NSG", "success", {"id": result.get("id"), "name": name}))
                return intent_response("success", f"Created forward NSG '{name}'", steps, result=result)
            elif action == "update":
                if not resource_id:
                    return intent_response("failed", "Forward NSG update requires 'resource_id'.", steps)
                updates = {k: v for k, v in {"name": name, "comment": comment}.items() if v is not None}
                resp = client.update_forward_nsg(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update forward NSG", "success", {"id": resource_id}))
                return intent_response("success", f"Updated forward NSG {resource_id}", steps, result=result)
            elif action == "delete":
                if not resource_id:
                    return intent_response("failed", "Forward NSG delete requires 'resource_id'.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would delete forward NSG {resource_id}", steps,
                        warnings=["Set dry_run=False to execute."])
                client.delete_forward_nsg(resource_id)
                steps.append(step_result("Delete forward NSG", "success", {"id": resource_id}))
                return intent_response("success", f"Deleted forward NSG {resource_id}", steps)

        # ── DNS Server ────────────────────────────────────────────
        elif resource_type == "dns_server":
            if action == "list":
                resp = client.list_dns_servers(limit=100)
                items_list = extract_results(resp)
                steps.append(step_result("List DNS servers", "success", {"count": len(items_list)}))
                result = [{"id": s.get("id"), "name": s.get("name"), "comment": s.get("comment", "")} for s in items_list]
                return intent_response("success", f"Found {len(items_list)} DNS server(s)", steps, result=result)
            elif action == "get":
                if not resource_id:
                    return intent_response("failed", "DNS server get requires 'resource_id'.", steps)
                resp = client.get_dns_server(resource_id)
                result = resp.get("result", resp)
                steps.append(step_result("Get DNS server", "success", {"id": resource_id}))
                return intent_response("success", f"Retrieved DNS server {resource_id}", steps, result=result)
            elif action == "create":
                if not name:
                    return intent_response("failed", "DNS server create requires 'name'.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would create DNS server '{name}'", steps,
                        warnings=["Set dry_run=False to create."])
                resp = client.create_dns_server(name=name, comment=comment)
                result = resp.get("result", resp)
                steps.append(step_result("Create DNS server", "success", {"id": result.get("id"), "name": name}))
                return intent_response("success", f"Created DNS server '{name}'", steps, result=result)
            elif action == "update":
                if not resource_id:
                    return intent_response("failed", "DNS server update requires 'resource_id'.", steps)
                updates = {k: v for k, v in {"name": name, "comment": comment}.items() if v is not None}
                resp = client.update_dns_server(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update DNS server", "success", {"id": resource_id}))
                return intent_response("success", f"Updated DNS server {resource_id}", steps, result=result)
            elif action == "delete":
                if not resource_id:
                    return intent_response("failed", "DNS server delete requires 'resource_id'.", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would delete DNS server {resource_id}", steps,
                        warnings=["Set dry_run=False to execute."])
                client.delete_dns_server(resource_id)
                steps.append(step_result("Delete DNS server", "success", {"id": resource_id}))
                return intent_response("success", f"Deleted DNS server {resource_id}", steps)

        # ── DNS Service / DNS Host (read-only) ────────────────────
        elif resource_type == "dns_service":
            if action == "list":
                resp = client.list_dns_services(limit=100)
                items_list = extract_results(resp)
                steps.append(step_result("List DNS services", "success", {"count": len(items_list)}))
                result = [{"id": s.get("id"), "name": s.get("name"), "status": s.get("status", "")} for s in items_list]
                return intent_response("success", f"Found {len(items_list)} DNS service(s)", steps, result=result)
            elif action == "get":
                if not resource_id:
                    return intent_response("failed", "DNS service get requires 'resource_id'.", steps)
                resp = client.get_dns_service(resource_id)
                result = resp.get("result", resp)
                steps.append(step_result("Get DNS service", "success", {"id": resource_id}))
                return intent_response("success", f"Retrieved DNS service {resource_id}", steps, result=result)
            else:
                return intent_response("failed", f"DNS service supports: list, get. '{action}' not supported.", steps)

        elif resource_type == "dns_host":
            if action == "list":
                resp = client.list_dns_hosts(limit=100)
                items_list = extract_results(resp)
                steps.append(step_result("List DNS hosts", "success", {"count": len(items_list)}))
                result = [{"id": h.get("id"), "name": h.get("name")} for h in items_list]
                return intent_response("success", f"Found {len(items_list)} DNS host(s)", steps, result=result)
            elif action == "get":
                if not resource_id:
                    return intent_response("failed", "DNS host get requires 'resource_id'.", steps)
                resp = client.get_dns_host(resource_id)
                result = resp.get("result", resp)
                steps.append(step_result("Get DNS host", "success", {"id": resource_id}))
                return intent_response("success", f"Retrieved DNS host {resource_id}", steps, result=result)
            elif action == "update":
                if not resource_id:
                    return intent_response("failed", "DNS host update requires 'resource_id'.", steps)
                updates = {k: v for k, v in {"name": name, "comment": comment}.items() if v is not None}
                resp = client.update_dns_host(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update DNS host", "success", {"id": resource_id}))
                return intent_response("success", f"Updated DNS host {resource_id}", steps, result=result)
            else:
                return intent_response("failed", f"DNS host supports: list, get, update. '{action}' not supported.", steps)
```

- [ ] **Step 5: Add `copy` action to `auth_zone` and `forward_zone` inside their existing branches**

Inside the existing `auth_zone` dispatch, add after the `dnssec_status` case:
```python
            elif action == "copy":
                if not resource_id:
                    return intent_response("failed", "Zone copy requires 'resource_id' (source zone ID).", steps)
                if not view:
                    return intent_response("failed", "Zone copy requires 'view' (target view name or ID).", steps)
                if dry_run:
                    return intent_response("success", f"DRY RUN: Would copy zone {resource_id} to view '{view}'", steps,
                        warnings=["Set dry_run=False to copy."])
                resp = client.copy_auth_zone(zone_id=resource_id, target_view=view, comment=comment)
                result = resp.get("result", resp)
                steps.append(step_result("Copy auth zone", "success", {"source": resource_id, "target_view": view}))
                return intent_response("success", f"Copied auth zone {resource_id} to view '{view}'", steps, result=result)
```

Same pattern for `forward_zone` using `client.copy_forward_zone`.

- [ ] **Step 6: Run tests and full suite**
```bash
uv run pytest tests/test_tools.py -k "test_manage_dns_zone" --tb=short -q
uv run pytest tests/ --tb=short -q
```

---

## Task 5: New `manage_rpz_policies` tool — RPZ rule CRUD

**Context:** RPZ zones exist via `manage_dns_zone(resource_type="rpz")`, but RPZ *rules* (the enforcement records inside a zone) have no tool. Client has `list_rpz_rules`, `create_rpz_rule`, `get_rpz_rule`, `update_rpz_rule`, `delete_rpz_rule`. This is a critical gap for threat response.

**Location:** Add new tool in `mcp_intent.py` after `triage_security_insight` (line ~4597), before `resource_tool_catalog`.

- [ ] **Step 1: Write failing tests**

```python
def test_manage_rpz_policies_list(mock_clients):
    from mcp_intent import manage_rpz_policies
    result = manage_rpz_policies(action="list")
    assert result["status"] in ("success", "failed")

def test_manage_rpz_policies_create_dry_run(mock_clients):
    from mcp_intent import manage_rpz_policies
    result = manage_rpz_policies(
        action="create", name="block-badsite.com",
        zone="rpz/dns/auth_zone/abc", rdata={"type": "CNAME", "dname": "."},
        dry_run=True
    )
    assert result["status"] == "success"
    assert "DRY RUN" in result["summary"]

def test_manage_rpz_policies_create_requires_zone(mock_clients):
    from mcp_intent import manage_rpz_policies
    result = manage_rpz_policies(action="create", name="block.example.com", rdata={"type": "CNAME", "dname": "."})
    assert result["status"] == "failed"
    assert "zone" in result["summary"].lower()

def test_manage_rpz_policies_delete_dry_run(mock_clients):
    from mcp_intent import manage_rpz_policies
    result = manage_rpz_policies(action="delete", resource_id="dns/rpz_rule/abc", dry_run=True)
    assert result["status"] == "success"
    assert "DRY RUN" in result["summary"]
```

- [ ] **Step 2: Run to confirm failures (function not yet defined)**
```bash
uv run pytest tests/test_tools.py -k "test_manage_rpz_policies" --tb=short -q
```
Expected: FAIL with ImportError or AttributeError.

- [ ] **Step 3: Add the new tool to `mcp_intent.py`**

Add after `triage_security_insight`'s closing `except` block, before `# ==================== Resource Templates ====================`:

```python
# ==================== RPZ Policy Rules ====================


@mcp.tool(annotations={"destructiveHint": True, "idempotentHint": False})
def manage_rpz_policies(
    action: Literal["create", "update", "delete", "get", "list"],
    name: str | None = None,
    zone: str | None = None,
    rdata: dict[str, Any] | None = None,
    resource_id: str | None = None,
    comment: str | None = None,
    dry_run: bool = True,
) -> dict:
    """
    Manage RPZ (Response Policy Zone) rules: create, update, delete, get, list.
    USE THIS to enforce DNS threat response rules within an RPZ zone.
    For RPZ zone management use manage_dns_zone(resource_type='rpz').
    For posture review use assess_security_posture().

    IMPORTANT: Delete runs in dry_run mode by default.

    Args:
        action: Operation to perform
        name: Rule name — typically the blocked FQDN (e.g., "malware.example.com")
        zone: RPZ zone ID (e.g., "dns/auth_zone/abc") — required for create
        rdata: Rule rdata dict — e.g., {"type": "CNAME", "dname": "."} to NXDOMAIN-redirect
        resource_id: RPZ rule ID — required for get, update, delete
        comment: Optional description
        dry_run: If True (default), delete/create shows plan only. Set False to execute.

    Returns:
        RPZ rule operation result

    Examples:
        - manage_rpz_policies(action="list") → all RPZ rules across zones
        - manage_rpz_policies(action="create", name="bad.example.com", zone="dns/auth_zone/abc", rdata={"type": "CNAME", "dname": "."}, dry_run=False)
        - manage_rpz_policies(action="delete", resource_id="dns/rpz_rule/xyz", dry_run=False)
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=["Run check_api_health() to verify connectivity"],
        )

    valid, err = validate_action(action, ["create", "update", "delete", "get", "list"])
    if not valid:
        return intent_response("failed", err)

    steps = []

    try:
        if action == "list":
            resp = client.list_rpz_rules(limit=100)
            rules = extract_results(resp)
            steps.append(step_result("List RPZ rules", "success", {"count": len(rules)}))
            result = [
                {"id": r.get("id"), "name": r.get("name_in_zone", ""), "zone": r.get("zone", ""), "comment": r.get("comment", "")}
                for r in rules
            ]
            return intent_response("success", f"Found {len(rules)} RPZ rule(s)", steps, result=result)

        elif action == "get":
            if not resource_id:
                return intent_response("failed", "RPZ rule get requires 'resource_id'.", steps)
            resp = client.get_rpz_rule(resource_id)
            result = resp.get("result", resp)
            steps.append(step_result("Get RPZ rule", "success", {"id": resource_id}))
            return intent_response("success", f"Retrieved RPZ rule {resource_id}", steps, result=result)

        elif action == "create":
            if not name:
                return intent_response("failed", "RPZ rule create requires 'name' (blocked FQDN).", steps)
            if not zone:
                return intent_response("failed", "RPZ rule create requires 'zone' (RPZ zone ID).", steps)
            if not rdata:
                return intent_response("failed", "RPZ rule create requires 'rdata' (e.g., {'type': 'CNAME', 'dname': '.'}).", steps)
            if dry_run:
                return intent_response(
                    "success",
                    f"DRY RUN: Would create RPZ rule blocking '{name}' in zone {zone}",
                    steps,
                    result={"mode": "DRY RUN", "name": name, "zone": zone, "rdata": rdata},
                    warnings=["Set dry_run=False to create the rule."],
                    next_actions=[f"Execute: manage_rpz_policies(action='create', name='{name}', zone='{zone}', rdata={rdata}, dry_run=False)"],
                )
            resp = client.create_rpz_rule(name=name, zone=zone, rdata=rdata, comment=comment or "Created via intent layer")
            result = resp.get("result", resp)
            rule_id = result.get("id", "")
            steps.append(step_result("Create RPZ rule", "success", {"id": rule_id, "name": name, "zone": zone}))
            return intent_response(
                "success",
                f"Created RPZ rule blocking '{name}'",
                steps,
                result=result,
                next_actions=[
                    f"Verify: manage_rpz_policies(action='get', resource_id='{rule_id}')",
                    "Check zone: manage_dns_zone(action='get', resource_type='rpz', resource_id='{zone}')",
                ],
            )

        elif action == "update":
            if not resource_id:
                return intent_response("failed", "RPZ rule update requires 'resource_id'.", steps)
            updates = {}
            if rdata is not None:
                updates["rdata"] = rdata
            if comment is not None:
                updates["comment"] = comment
            if name is not None:
                updates["name_in_zone"] = name
            if not updates:
                return intent_response("failed", "No update fields provided.", steps)
            resp = client.update_rpz_rule(resource_id, updates)
            result = resp.get("result", resp)
            steps.append(step_result("Update RPZ rule", "success", {"id": resource_id}))
            return intent_response("success", f"Updated RPZ rule {resource_id}", steps, result=result)

        elif action == "delete":
            if not resource_id:
                return intent_response("failed", "RPZ rule delete requires 'resource_id'.", steps)
            if dry_run:
                resp = client.get_rpz_rule(resource_id)
                rule = resp.get("result", resp)
                return intent_response(
                    "success",
                    f"DRY RUN: Would delete RPZ rule '{rule.get('name_in_zone', resource_id)}'",
                    steps,
                    result={"mode": "DRY RUN", "id": resource_id, "name": rule.get("name_in_zone")},
                    warnings=["Set dry_run=False to delete the rule."],
                    next_actions=[f"Execute: manage_rpz_policies(action='delete', resource_id='{resource_id}', dry_run=False)"],
                )
            client.delete_rpz_rule(resource_id)
            steps.append(step_result("Delete RPZ rule", "success", {"id": resource_id}))
            return intent_response("success", f"Deleted RPZ rule {resource_id}", steps)

    except Exception as e:
        return intent_response("failed", f"Failed to {action} RPZ rule: {e}", steps)
```

- [ ] **Step 4: Run tests and full suite**
```bash
uv run pytest tests/test_tools.py -k "test_manage_rpz_policies" --tb=short -q
uv run pytest tests/ --tb=short -q
```

---

## Task 6: New `manage_dnssec` tool — DNSSEC key lifecycle

**Context:** `manage_dns_zone` already handles `sign`, `unsign`, `dnssec_status` actions (which call `sign_auth_zone`, `unsign_auth_zone`, `get_dnssec_key_status`). Missing: `delete_dnssec_key`, `export_trust_anchors`, `import_keyset`. These should be a standalone tool since they're key management operations, not zone lifecycle operations.

**Location:** Add after `manage_rpz_policies`.

- [ ] **Step 1: Write failing tests**

```python
def test_manage_dnssec_export_dry_run(mock_clients):
    from mcp_intent import manage_dnssec
    result = manage_dnssec(action="export_trust_anchors", zone_ids=["dns/auth_zone/abc"], dry_run=True)
    assert result["status"] == "success"

def test_manage_dnssec_delete_key_requires_ids(mock_clients):
    from mcp_intent import manage_dnssec
    result = manage_dnssec(action="delete_key")
    assert result["status"] == "failed"

def test_manage_dnssec_invalid_action(mock_clients):
    from mcp_intent import manage_dnssec
    result = manage_dnssec(action="bogus")
    assert result["status"] == "failed"
```

- [ ] **Step 2: Add the tool**

```python
# ==================== DNSSEC Key Management ====================


@mcp.tool(annotations={"destructiveHint": True, "idempotentHint": False})
def manage_dnssec(
    action: Literal["export_trust_anchors", "delete_key", "import_keyset"],
    zone_ids: list[str] | None = None,
    zone_id: str | None = None,
    key_id: str | None = None,
    keyset: dict[str, Any] | None = None,
    dry_run: bool = True,
) -> dict:
    """
    Manage DNSSEC key lifecycle: export trust anchors, delete keys, import keysets.
    USE THIS for DNSSEC key rotation and compliance operations.
    For signing/unsigning zones use manage_dns_zone(action='sign'/'unsign').
    For key status use manage_dns_zone(action='dnssec_status').

    IMPORTANT: delete_key runs in dry_run mode by default.

    Args:
        action: DNSSEC operation to perform
        zone_ids: List of zone IDs — required for export_trust_anchors
        zone_id: Single zone ID — required for delete_key and import_keyset
        key_id: DNSSEC key ID — required for delete_key
        keyset: Keyset data dict — required for import_keyset
        dry_run: If True (default), delete_key shows key details only. Set False to execute.

    Returns:
        DNSSEC operation result

    Examples:
        - manage_dnssec(action="export_trust_anchors", zone_ids=["dns/auth_zone/abc"])
        - manage_dnssec(action="delete_key", zone_id="dns/auth_zone/abc", key_id="key-123", dry_run=False)
        - manage_dnssec(action="import_keyset", zone_id="dns/auth_zone/abc", keyset={...})
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=["Run check_api_health() to verify connectivity"],
        )

    valid, err = validate_action(action, ["export_trust_anchors", "delete_key", "import_keyset"])
    if not valid:
        return intent_response("failed", err)

    steps = []

    try:
        if action == "export_trust_anchors":
            if not zone_ids:
                return intent_response("failed", "export_trust_anchors requires 'zone_ids' list.", steps)
            resp = client.export_trust_anchors(zone_ids)
            result = resp.get("result", resp)
            steps.append(step_result("Export trust anchors", "success", {"zone_count": len(zone_ids)}))
            return intent_response(
                "success",
                f"Exported trust anchors for {len(zone_ids)} zone(s)",
                steps,
                result=result,
            )

        elif action == "delete_key":
            if not zone_id:
                return intent_response("failed", "delete_key requires 'zone_id'.", steps)
            if not key_id:
                return intent_response("failed", "delete_key requires 'key_id'.", steps)
            if dry_run:
                return intent_response(
                    "success",
                    f"DRY RUN: Would delete DNSSEC key '{key_id}' from zone {zone_id}",
                    steps,
                    result={"mode": "DRY RUN", "zone_id": zone_id, "key_id": key_id},
                    warnings=["Deleting a DNSSEC key is irreversible. Set dry_run=False to execute."],
                    next_actions=[f"Execute: manage_dnssec(action='delete_key', zone_id='{zone_id}', key_id='{key_id}', dry_run=False)"],
                )
            resp = client.delete_dnssec_key(zone_id, key_id)
            steps.append(step_result("Delete DNSSEC key", "success", {"zone_id": zone_id, "key_id": key_id}))
            return intent_response(
                "success",
                f"Deleted DNSSEC key '{key_id}' from zone {zone_id}",
                steps,
                next_actions=[f"Verify key status: manage_dns_zone(action='dnssec_status', resource_id='{zone_id}')"],
            )

        elif action == "import_keyset":
            if not zone_id:
                return intent_response("failed", "import_keyset requires 'zone_id'.", steps)
            if not keyset:
                return intent_response("failed", "import_keyset requires 'keyset' dict.", steps)
            resp = client.import_keyset(zone_id, keyset)
            result = resp.get("result", resp)
            steps.append(step_result("Import keyset", "success", {"zone_id": zone_id}))
            return intent_response(
                "success",
                f"Imported keyset into zone {zone_id}",
                steps,
                result=result,
                next_actions=[f"Verify: manage_dns_zone(action='dnssec_status', resource_id='{zone_id}')"],
            )

    except Exception as e:
        return intent_response("failed", f"Failed to {action}: {e}", steps)
```

- [ ] **Step 3: Run tests and full suite**
```bash
uv run pytest tests/test_tools.py -k "test_manage_dnssec" --tb=short -q
uv run pytest tests/ --tb=short -q
```

---

## Task 7: New `manage_doh` tool — DoH, PoP regions, threat feeds, approvals

**Context:** `list_pop_regions`, `create_doh_fqdn`, `list_threat_feeds`, `create_threat_indicator`, `list_app_approvals`, `update_app_approvals`, `list_block_approvals`, `update_block_approvals` from `atcfw_client` have no MCP tool.

**Location:** Add after `manage_dnssec`.

- [ ] **Step 1: Write failing tests**

```python
def test_manage_doh_list_pop_regions(mock_clients):
    from mcp_intent import manage_doh
    result = manage_doh(action="list_pop_regions")
    assert result["status"] in ("success", "failed")

def test_manage_doh_list_threat_feeds(mock_clients):
    from mcp_intent import manage_doh
    result = manage_doh(action="list_threat_feeds")
    assert result["status"] in ("success", "failed")

def test_manage_doh_list_app_approvals(mock_clients):
    from mcp_intent import manage_doh
    result = manage_doh(action="list_app_approvals")
    assert result["status"] in ("success", "failed")

def test_manage_doh_invalid_action(mock_clients):
    from mcp_intent import manage_doh
    result = manage_doh(action="bogus")
    assert result["status"] == "failed"
```

- [ ] **Step 2: Add the tool**

```python
# ==================== DoH, Threat Feeds & Approvals ====================


@mcp.tool(annotations={"destructiveHint": False, "idempotentHint": True})
def manage_doh(
    action: Literal[
        "list_pop_regions", "create_doh_fqdn",
        "list_threat_feeds", "create_threat_indicator",
        "list_app_approvals", "update_app_approvals",
        "list_block_approvals", "update_block_approvals",
    ],
    fqdn: str | None = None,
    data: dict[str, Any] | None = None,
    updates: dict[str, Any] | None = None,
) -> dict:
    """
    Manage DNS-over-HTTPS infrastructure, threat feeds, and app/block approvals.
    USE THIS for DoH configuration, threat indicator management, and approval workflows.
    For security policies use manage_security_policy(). For threat investigation use investigate_threat().

    Args:
        action: Operation to perform
        fqdn: DoH FQDN — required for create_doh_fqdn
        data: Arbitrary payload dict — for create_threat_indicator or create_doh_fqdn
        updates: Update payload dict — for update_app_approvals and update_block_approvals

    Returns:
        Operation result

    Examples:
        - manage_doh(action="list_pop_regions") → available PoP regions for DoH deployment
        - manage_doh(action="list_threat_feeds") → configured threat feed subscriptions
        - manage_doh(action="list_app_approvals") → pending application approvals
        - manage_doh(action="create_doh_fqdn", fqdn="doh.example.com")
    """
    if not atcfw_client:
        return intent_response(
            "failed",
            "Security client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=["Run check_api_health() to verify connectivity"],
        )

    valid, err = validate_action(action, [
        "list_pop_regions", "create_doh_fqdn",
        "list_threat_feeds", "create_threat_indicator",
        "list_app_approvals", "update_app_approvals",
        "list_block_approvals", "update_block_approvals",
    ])
    if not valid:
        return intent_response("failed", err)

    steps = []

    try:
        if action == "list_pop_regions":
            resp = atcfw_client.list_pop_regions()
            regions = extract_results(resp)
            steps.append(step_result("List PoP regions", "success", {"count": len(regions)}))
            return intent_response("success", f"Found {len(regions)} PoP region(s)", steps, result=regions)

        elif action == "create_doh_fqdn":
            if not fqdn:
                return intent_response("failed", "create_doh_fqdn requires 'fqdn'.", steps)
            valid_fqdn, err = validate_fqdn(fqdn.rstrip("."))
            if not valid_fqdn:
                return intent_response("failed", f"Invalid FQDN: {err}")
            payload = data or {}
            payload["fqdn"] = fqdn
            resp = atcfw_client.create_doh_fqdn(payload)
            result = resp.get("result", resp)
            steps.append(step_result("Create DoH FQDN", "success", {"fqdn": fqdn}))
            return intent_response("success", f"Created DoH FQDN '{fqdn}'", steps, result=result)

        elif action == "list_threat_feeds":
            resp = atcfw_client.list_threat_feeds()
            feeds = extract_results(resp)
            steps.append(step_result("List threat feeds", "success", {"count": len(feeds)}))
            result = [{"id": f.get("id"), "name": f.get("name"), "type": f.get("type", "")} for f in feeds]
            return intent_response("success", f"Found {len(feeds)} threat feed(s)", steps, result=result)

        elif action == "create_threat_indicator":
            if not data:
                return intent_response("failed", "create_threat_indicator requires 'data' dict.", steps)
            resp = atcfw_client.create_threat_indicator(data)
            result = resp.get("result", resp)
            steps.append(step_result("Create threat indicator", "success", {}))
            return intent_response("success", "Created threat indicator", steps, result=result)

        elif action == "list_app_approvals":
            resp = atcfw_client.list_app_approvals()
            approvals = extract_results(resp)
            steps.append(step_result("List app approvals", "success", {"count": len(approvals)}))
            return intent_response("success", f"Found {len(approvals)} app approval(s)", steps, result=approvals)

        elif action == "update_app_approvals":
            if not updates:
                return intent_response("failed", "update_app_approvals requires 'updates' dict.", steps)
            resp = atcfw_client.update_app_approvals(updates)
            result = resp.get("result", resp)
            steps.append(step_result("Update app approvals", "success", {}))
            return intent_response("success", "Updated app approvals", steps, result=result)

        elif action == "list_block_approvals":
            resp = atcfw_client.list_block_approvals()
            approvals = extract_results(resp)
            steps.append(step_result("List block approvals", "success", {"count": len(approvals)}))
            return intent_response("success", f"Found {len(approvals)} block approval(s)", steps, result=approvals)

        elif action == "update_block_approvals":
            if not updates:
                return intent_response("failed", "update_block_approvals requires 'updates' dict.", steps)
            resp = atcfw_client.update_block_approvals(updates)
            result = resp.get("result", resp)
            steps.append(step_result("Update block approvals", "success", {}))
            return intent_response("success", "Updated block approvals", steps, result=result)

    except Exception as e:
        return intent_response("failed", f"Failed to {action}: {e}", steps)
```

- [ ] **Step 3: Run tests and full suite**
```bash
uv run pytest tests/test_tools.py -k "test_manage_doh" --tb=short -q
uv run pytest tests/ --tb=short -q
```

---

## Task 8: Extend `manage_ip_reservation` — IPAM host get/update

**Context:** `manage_ip_reservation` has `get` and `update` actions in its Literal, but the implementation only handles `reserve` and `release` for fixed addresses. The client has `get_ipam_host` and `update_ipam_host`. Add IPAM host operations here since IP reservations and IPAM hosts are closely related.

**Location:** `mcp_intent.py:3497`

- [ ] **Step 1: Write failing tests**

```python
def test_manage_ip_reservation_get_ipam_host(mock_clients):
    from mcp_intent import manage_ip_reservation
    result = manage_ip_reservation(action="get", resource_id="ipam/host/abc")
    assert result["status"] in ("success", "failed")

def test_manage_ip_reservation_update_ipam_host_requires_id(mock_clients):
    from mcp_intent import manage_ip_reservation
    result = manage_ip_reservation(action="update")
    assert result["status"] == "failed"
    assert "resource_id" in result["summary"].lower()
```

- [ ] **Step 2: Find the `get` and `update` branches inside `manage_ip_reservation`**

Read lines 3530–3700 to understand the existing `get` and `update` implementation.

- [ ] **Step 3: Ensure `get` handles both fixed addresses and IPAM hosts**

The `get` action should check if `resource_id` starts with `ipam/host/` and route to `get_ipam_host`, otherwise use the existing fixed address path.

```python
            # Inside action == "get":
            if resource_id.startswith("ipam/host/"):
                resp = client.get_ipam_host(resource_id)
            else:
                resp = client.get_fixed_address(resource_id)
```

- [ ] **Step 4: Ensure `update` handles IPAM hosts**

```python
            # Inside action == "update":
            if resource_id.startswith("ipam/host/"):
                updates = {}
                if hostname:
                    updates["name"] = hostname
                if comment is not None:
                    updates["comment"] = comment
                if not updates:
                    return intent_response("failed", "No update fields provided.", steps)
                resp = client.update_ipam_host(resource_id, updates)
                result = resp.get("result", resp)
                steps.append(step_result("Update IPAM host", "success", {"id": resource_id}))
                return intent_response("success", f"Updated IPAM host {resource_id}", steps, result=result)
```

- [ ] **Step 5: Run tests and full suite**
```bash
uv run pytest tests/test_tools.py -k "test_manage_ip_reservation" --tb=short -q
uv run pytest tests/ --tb=short -q
```

---

## Task 9: Final full-suite verification + update docs

- [ ] **Step 1: Run the complete test suite**
```bash
uv run pytest tests/ -v --tb=short 2>&1 | tail -30
```
Expected: All tests pass (163 original + all new tests).

- [ ] **Step 2: Verify new tool count**
```bash
grep -c "^@mcp.tool" mcp_intent.py
```
Expected: 26 (was 23, added 3 new tools).

- [ ] **Step 3: Verify syntax**
```bash
uv run python -c "import mcp_intent; print('OK')"
```
Expected: `OK`

- [ ] **Step 4: Update docs/api-methods.md tool count line**

Change:
```
**303 API methods** across 3 service clients, wrapped into **23 intent-level MCP tools**.
```
To:
```
**307 API methods** across 3 service clients, wrapped into **26 intent-level MCP tools**.
```

- [ ] **Step 5: Update README.md tool count line**

Change:
```
> **23 intent-level workflow tools**
```
To:
```
> **26 intent-level workflow tools**
```

---

## Self-Review

**Spec coverage check:**
- ✅ manage_security_policy: policy CRUD, policy rules, network lists, all resource type deletes
- ✅ manage_network: IP space CRUD
- ✅ manage_dhcp: servers, option groups/spaces, MAC items (including bulk), DHCP hosts, config profiles, global
- ✅ manage_dns_zone: ACLs, auth/forward NSGs, DNS servers, DNS services/hosts, zone copy
- ✅ New manage_rpz_policies: full CRUD
- ✅ New manage_dnssec: export trust anchors, delete key, import keyset
- ✅ New manage_doh: PoP regions, DoH FQDN, threat feeds/indicators, app/block approvals
- ✅ manage_ip_reservation: IPAM host get/update

**Gaps not covered (intentional):**
- `convert_domain_name`, `convert_rname` — internal format utilities, no intent-level use case
- `increment_serial`, `configure_record_protection` — advanced ops, low demand
- Federation pool next-available variants — already in manage_federation
- `get_dhcp_host_associations`, `get_linked_ha_groups` — internal lookup helpers

**Placeholder scan:** None found — all code blocks are complete.

**Type consistency:** All new `Literal` extensions use consistent naming. All new tools use `intent_response`, `step_result`, `extract_results`, `validate_action`, `validate_resource_type` from the existing shared functions.
