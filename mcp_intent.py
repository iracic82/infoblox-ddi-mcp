"""
Infoblox DDI Intent-Layer MCP Server

High-level workflow tools for agentic AI integration.
Instead of 98 atomic CRUD operations, this server exposes 23 intent-level tools
that orchestrate multi-step DDI workflows automatically — covering 100% of the
Infoblox BloxOne DDI API surface.

Any MCP-compatible AI agent (Claude, OpenAI, HCL AEX, Cursor, etc.) can reason
about these tools without being an Infoblox expert.

Usage:
    INFOBLOX_API_KEY=your_key python mcp_intent.py          # stdio transport
    INFOBLOX_API_KEY=your_key python mcp_intent.py --http   # HTTP on port 4005
"""

import json
import logging
import os
import sys

import structlog

__version__ = "1.8.0"

# CRITICAL: Configure structlog to use stderr BEFORE importing service clients.
# In stdio transport mode, stdout is reserved exclusively for JSON-RPC protocol messages.
# Any non-JSON output on stdout corrupts the protocol stream and causes:
#   "Unexpected non-whitespace character after JSON at position 4"
structlog.configure(
    logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
)

# Configure standard logging to stderr too
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", stream=sys.stderr
)
logger = logging.getLogger(__name__)

from typing import Any, Literal

from fastmcp import FastMCP

from services.atcfw_client import AtcfwClient
from services.infoblox_client import InfobloxClient
from services.insights_client import InsightsClient

# Initialize FastMCP server
mcp = FastMCP("Infoblox DDI Intent Layer")


# ==================== Service Client Initialization ====================

try:
    client = InfobloxClient()
    logger.info("InfobloxClient initialized successfully")
except ValueError as e:
    logger.warning(f"InfobloxClient initialization failed: {e}")
    client = None

try:
    insights_client = InsightsClient()
    logger.info("InsightsClient initialized successfully")
except ValueError as e:
    logger.warning(f"InsightsClient initialization failed: {e}")
    insights_client = None

try:
    atcfw_client = AtcfwClient()
    logger.info("AtcfwClient initialized successfully")
except ValueError as e:
    logger.warning(f"AtcfwClient initialization failed: {e}")
    atcfw_client = None


# ==================== Response Helpers ====================


def intent_response(
    status: str,
    summary: str,
    steps: list[dict] = None,
    result: Any = None,
    warnings: list[str] = None,
    next_actions: list[str] = None,
) -> dict:
    """Standard intent response envelope"""
    return {
        "status": status,
        "summary": summary,
        "steps": steps or [],
        "result": result,
        "warnings": warnings or [],
        "next_actions": next_actions or [],
    }


def step_result(step_name: str, status: str, result: Any = None, error: str = None) -> dict:
    """Individual step result"""
    s = {"step": step_name, "status": status}
    if result is not None:
        s["result"] = result
    if error:
        s["error"] = error
    return s


def extract_results(response: dict) -> list:
    """Extract results list from API response"""
    return response.get("results", response.get("result", []))


# ==================== Validation Helpers ====================

import ipaddress
import re


def sanitize_filter(value: str, max_length: int = 512) -> str:
    """Escape user input for safe use in BloxOne API filter expressions.

    Prevents filter injection by:
    1. Truncating to max_length to prevent abuse
    2. Escaping backslashes and double quotes
    3. Removing BloxOne filter operators that could break out of a quoted value
    """
    value = value[:max_length]
    # Escape backslashes first, then quotes
    value = value.replace("\\", "\\\\").replace('"', '\\"')
    # Remove filter operators that could break out of the value context
    for op in ["==", "!=", "~=", "<=", ">=", "!~"]:
        value = value.replace(op, "")
    return value


def validate_action(action: str, allowed: list[str]) -> tuple:
    """Validate action against allowed list. Returns (is_valid, error_msg)."""
    if action not in allowed:
        return False, f"Invalid action '{action}'. Allowed: {', '.join(allowed)}"
    return True, ""


def validate_resource_type(resource_type: str, allowed: list[str]) -> tuple:
    """Validate resource_type against allowed list. Returns (is_valid, error_msg)."""
    if resource_type not in allowed:
        return False, f"Invalid resource_type '{resource_type}'. Allowed: {', '.join(allowed)}"
    return True, ""


def validate_cidr(cidr: str) -> tuple:
    """Validate CIDR notation. Returns (is_valid, error_msg)."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True, ""
    except ValueError as e:
        return False, f"Invalid CIDR '{cidr}': {e}"


def validate_ip(ip: str) -> tuple:
    """Validate IP address. Returns (is_valid, error_msg)."""
    try:
        ipaddress.ip_address(ip)
        return True, ""
    except ValueError as e:
        return False, f"Invalid IP address '{ip}': {e}"


def validate_mac(mac: str) -> tuple:
    """Validate MAC address. Returns (is_valid, error_msg)."""
    pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    if re.match(pattern, mac):
        return True, ""
    return False, f"Invalid MAC address '{mac}'. Expected format: AA:BB:CC:DD:EE:FF"


def validate_fqdn(fqdn: str) -> tuple:
    """Validate fully qualified domain name. Returns (is_valid, error_msg)."""
    pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.?$"
    if re.match(pattern, fqdn) and len(fqdn) <= 253:
        return True, ""
    return False, f"Invalid FQDN '{fqdn}'. Must be a valid domain name."


# ==================== Resolver Functions ====================


def resolve_space(space_name: str) -> tuple:
    """Resolve IP space name to ID. Returns (space_id, step, error_msg)."""
    if not client:
        return None, None, "Infoblox client not initialized"
    if space_name.startswith("ipam/ip_space/"):
        return space_name, step_result("Resolve IP space", "success", {"space_id": space_name}), ""
    try:
        spaces = extract_results(client.list_ip_spaces(filter=f'name=="{sanitize_filter(space_name)}"'))
        if not spaces:
            spaces = extract_results(client.list_ip_spaces(filter=f'name~"{sanitize_filter(space_name)}"'))
        if spaces:
            space_id = spaces[0].get("id", "")
            return (
                space_id,
                step_result("Resolve IP space", "success", {"space_id": space_id, "name": spaces[0].get("name")}),
                "",
            )
        return (
            None,
            step_result("Resolve IP space", "failed", error=f"IP space '{space_name}' not found"),
            f"IP space '{space_name}' not found",
        )
    except Exception as e:
        return None, step_result("Resolve IP space", "failed", error=str(e)), str(e)


def resolve_zone(zone_fqdn: str, view: str | None = None) -> tuple:
    """Resolve DNS zone FQDN to ID. Returns (zone_id, step, error_msg).

    If view is provided, filters zones to the matching view.
    If multiple zones match and no view is specified, returns an error listing available views.
    """
    if not client:
        return None, None, "Infoblox client not initialized"
    if zone_fqdn.startswith("dns/auth_zone/"):
        return zone_fqdn, step_result("Resolve DNS zone", "success", {"zone_id": zone_fqdn}), ""

    # Resolve view name to ID if provided
    view_id = None
    if view:
        view_id, v_step, v_err = resolve_view(view)
        if v_err:
            return None, v_step, v_err

    try:
        zones = extract_results(client.list_auth_zones(filter=f'fqdn=="{sanitize_filter(zone_fqdn)}"'))
        if not zones:
            zones = extract_results(client.list_auth_zones(filter=f'fqdn=="{sanitize_filter(zone_fqdn)}."'))
        if not zones:
            return (
                None,
                step_result("Resolve DNS zone", "failed", error=f"DNS zone '{zone_fqdn}' not found"),
                f"DNS zone '{zone_fqdn}' not found",
            )

        # Filter by view if specified
        if view_id:
            zones = [z for z in zones if z.get("view") == view_id]
            if not zones:
                return (
                    None,
                    step_result(
                        "Resolve DNS zone",
                        "failed",
                        error=f"DNS zone '{zone_fqdn}' not found in view '{view}'",
                    ),
                    f"DNS zone '{zone_fqdn}' not found in view '{view}'",
                )

        # Ambiguity check: multiple zones, no view specified
        if len(zones) > 1 and not view_id:
            view_names = [z.get("view", "unknown") for z in zones]
            return (
                None,
                step_result(
                    "Resolve DNS zone",
                    "failed",
                    error=f"Zone '{zone_fqdn}' exists in {len(zones)} views: {view_names}. Specify a view to disambiguate.",
                ),
                f"Zone '{zone_fqdn}' exists in {len(zones)} views: {view_names}. Specify a view to disambiguate.",
            )

        zone_id = zones[0].get("id", "")
        return (
            zone_id,
            step_result("Resolve DNS zone", "success", {"zone_id": zone_id, "fqdn": zones[0].get("fqdn")}),
            "",
        )
    except Exception as e:
        return None, step_result("Resolve DNS zone", "failed", error=str(e)), str(e)


def resolve_view(view_name: str) -> tuple:
    """Resolve DNS view name to ID. Returns (view_id, step, error_msg)."""
    if not client:
        return None, None, "Infoblox client not initialized"
    if view_name.startswith("dns/view/"):
        return view_name, step_result("Resolve DNS view", "success", {"view_id": view_name}), ""
    try:
        views = extract_results(client.list_dns_views(filter=f'name=="{sanitize_filter(view_name)}"'))
        if not views:
            views = extract_results(client.list_dns_views(filter=f'name~"{sanitize_filter(view_name)}"'))
        if views:
            view_id = views[0].get("id", "")
            return (
                view_id,
                step_result("Resolve DNS view", "success", {"view_id": view_id, "name": views[0].get("name")}),
                "",
            )
        return (
            None,
            step_result("Resolve DNS view", "failed", error=f"DNS view '{view_name}' not found"),
            f"DNS view '{view_name}' not found",
        )
    except Exception as e:
        return None, step_result("Resolve DNS view", "failed", error=str(e)), str(e)


def resolve_realm(realm_name: str) -> tuple:
    """Resolve federated realm name to ID. Returns (realm_id, step, error_msg)."""
    if not client:
        return None, None, "Infoblox client not initialized"
    if realm_name.startswith("federation/"):
        return realm_name, step_result("Resolve federated realm", "success", {"realm_id": realm_name}), ""
    try:
        realms = extract_results(client.list_federated_realms(filter=f'name=="{sanitize_filter(realm_name)}"'))
        if not realms:
            realms = extract_results(client.list_federated_realms(filter=f'name~"{sanitize_filter(realm_name)}"'))
        if realms:
            realm_id = realms[0].get("id", "")
            return (
                realm_id,
                step_result(
                    "Resolve federated realm", "success", {"realm_id": realm_id, "name": realms[0].get("name")}
                ),
                "",
            )
        return (
            None,
            step_result("Resolve federated realm", "failed", error=f"Federated realm '{realm_name}' not found"),
            f"Federated realm '{realm_name}' not found",
        )
    except Exception as e:
        return None, step_result("Resolve federated realm", "failed", error=str(e)), str(e)


# ==================== Discovery & Exploration Tools ====================


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": True})
def explore_network(
    scope: str | None = None, depth: Literal["summary", "blocks", "full"] = "summary", limit: int = 500
) -> dict:
    """
    Browse the IP hierarchy tree (Spaces → Blocks → Subnets) with utilization data.
    USE THIS to navigate and drill into network structure.
    For executive dashboards use get_network_summary(). For keyword search use search_infrastructure().

    Args:
        scope: Optional IP space name to focus on (e.g., "prod", "corp"). If not set, shows all spaces.
        depth: Level of detail — "summary" (counts only), "blocks" (include address blocks), or "full" (include subnets)
        limit: Max items per category (address blocks, subnets) per space. Default 500.

    Returns:
        Hierarchical network view with utilization percentages

    Examples:
        - explore_network() → overview of all IP spaces with counts
        - explore_network(scope="prod") → detailed view of the prod IP space
        - explore_network(depth="full") → complete hierarchy with all subnets
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    steps = []
    warnings = []

    # Step 1: Get IP spaces
    try:
        space_filter = f'name~"{sanitize_filter(scope)}"' if scope else None
        spaces_resp = client.list_ip_spaces(filter=space_filter)
        spaces = extract_results(spaces_resp)
        steps.append(step_result("List IP spaces", "success", {"count": len(spaces)}))
    except Exception as e:
        return intent_response("failed", f"Failed to list IP spaces: {e}", steps)

    # Build hierarchy
    hierarchy = []
    for space in spaces:
        space_info = {
            "id": space.get("id", ""),
            "name": space.get("name", "Unknown"),
            "comment": space.get("comment", ""),
            "utilization": space.get("utilization", {}),
            "address_blocks": [],
            "subnets": [],
        }

        if depth in ("blocks", "full"):
            # Step 2: Get address blocks for this space
            try:
                space_id = space.get("id", "")
                blocks_resp = client.list_address_blocks(filter=f'space=="{space_id}"' if space_id else None)
                blocks = extract_results(blocks_resp)
                if len(blocks) > limit:
                    warnings.append(
                        f"Showing {limit} of {len(blocks)} address blocks for {space_info['name']}. Use scope= to narrow."
                    )
                    blocks = blocks[:limit]
                space_info["address_blocks"] = [
                    {
                        "id": b.get("id", ""),
                        "address": b.get("address", ""),
                        "cidr": b.get("cidr", 0),
                        "name": b.get("name", b.get("comment", "")),
                        "utilization": b.get("utilization", {}),
                    }
                    for b in blocks
                ]
                steps.append(
                    step_result(f"List address blocks for {space_info['name']}", "success", {"count": len(blocks)})
                )
            except Exception as e:
                warnings.append(f"Failed to get blocks for {space_info['name']}: {e}")

        if depth == "full":
            # Step 3: Get subnets for this space
            try:
                space_id = space.get("id", "")
                subnets_resp = client.list_subnets(filter=f'space=="{space_id}"' if space_id else None)
                subnets = extract_results(subnets_resp)
                if len(subnets) > limit:
                    warnings.append(
                        f"Showing {limit} of {len(subnets)} subnets for {space_info['name']}. Use scope= to narrow."
                    )
                    subnets = subnets[:limit]
                space_info["subnets"] = [
                    {
                        "id": s.get("id", ""),
                        "address": s.get("address", ""),
                        "cidr": s.get("cidr", 0),
                        "name": s.get("name", s.get("comment", "")),
                        "utilization": s.get("utilization", {}),
                    }
                    for s in subnets
                ]
                steps.append(step_result(f"List subnets for {space_info['name']}", "success", {"count": len(subnets)}))
            except Exception as e:
                warnings.append(f"Failed to get subnets for {space_info['name']}: {e}")

        hierarchy.append(space_info)

    total_blocks = sum(len(s["address_blocks"]) for s in hierarchy)
    total_subnets = sum(len(s["subnets"]) for s in hierarchy)

    summary = f"Found {len(hierarchy)} IP space(s)"
    if depth in ("blocks", "full"):
        summary += f", {total_blocks} address block(s)"
    if depth == "full":
        summary += f", {total_subnets} subnet(s)"

    return intent_response(
        status="success",
        summary=summary,
        steps=steps,
        result={"ip_spaces": hierarchy},
        warnings=warnings,
        next_actions=[
            "Use get_network_summary() for utilization stats",
            "Use search_infrastructure(query='...') to find specific resources",
            "Use provision_host() to add a new host to any subnet",
        ],
    )


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": True})
def search_infrastructure(
    query: str,
    types: list[Literal["subnets", "dns_zones", "dns_records", "hosts", "addresses"]] | None = None,
    limit: int = 20,
) -> dict:
    """
    Find resources by keyword across all DDI domains (IP, hostname, domain, comment).
    USE THIS when looking for something specific by name or address.
    For hierarchy browsing use explore_network(). For dashboards use get_network_summary().

    Args:
        query: Search term (IP address, hostname, domain name, comment text, etc.)
        types: Optional list of resource types to search. If not set, searches all types.
        limit: Maximum results per type (default: 20, max: 100)

    Returns:
        Matching resources grouped by type

    Examples:
        - search_infrastructure(query="10.20.3") → finds subnets, hosts, addresses matching
        - search_infrastructure(query="web-prod", types=["hosts", "dns_records"])
        - search_infrastructure(query="example.com", types=["dns_records"])
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    search_types = types or ["subnets", "dns_zones", "dns_records", "hosts", "addresses"]
    limit = min(limit, 100)
    steps = []
    results = {}
    total_found = 0

    # Search DNS zones
    if "dns_zones" in search_types:
        try:
            zone_filter = f'fqdn~"{sanitize_filter(query)}"' if query and query != "*" else None
            resp = client.list_auth_zones(filter=zone_filter, limit=limit)
            items = extract_results(resp)
            results["dns_zones"] = [
                {
                    "id": z.get("id"),
                    "fqdn": z.get("fqdn"),
                    "view": z.get("view"),
                    "primary_type": z.get("primary_type", ""),
                    "comment": z.get("comment", ""),
                }
                for z in items
            ]
            total_found += len(items)
            steps.append(step_result("Search DNS zones", "success", {"count": len(items)}))
        except Exception as e:
            steps.append(step_result("Search DNS zones", "failed", error=str(e)))

    # Search subnets
    if "subnets" in search_types:
        try:
            resp = client.list_subnets(
                filter=f'address~"{sanitize_filter(query)}" or comment~"{sanitize_filter(query)}"', limit=limit
            )
            items = extract_results(resp)
            results["subnets"] = [
                {
                    "id": s.get("id"),
                    "address": s.get("address"),
                    "cidr": s.get("cidr"),
                    "name": s.get("name", s.get("comment", "")),
                    "space": s.get("space"),
                }
                for s in items
            ]
            total_found += len(items)
            steps.append(step_result("Search subnets", "success", {"count": len(items)}))
        except Exception as e:
            steps.append(step_result("Search subnets", "failed", error=str(e)))

    # Search DNS records
    if "dns_records" in search_types:
        try:
            resp = client.list_dns_records(
                filter=f'name_in_zone~"{sanitize_filter(query)}" or absolute_name_spec~"{sanitize_filter(query)}"',
                limit=limit,
            )
            items = extract_results(resp)
            results["dns_records"] = [
                {
                    "id": r.get("id"),
                    "name": r.get("absolute_name_spec", r.get("name_in_zone")),
                    "type": r.get("type"),
                    "rdata": r.get("rdata"),
                    "zone": r.get("zone"),
                }
                for r in items
            ]
            total_found += len(items)
            steps.append(step_result("Search DNS records", "success", {"count": len(items)}))
        except Exception as e:
            steps.append(step_result("Search DNS records", "failed", error=str(e)))

    # Search IPAM hosts
    if "hosts" in search_types:
        try:
            resp = client.list_ipam_hosts(filter=f'name~"{sanitize_filter(query)}"', limit=limit)
            items = extract_results(resp)
            results["hosts"] = [
                {
                    "id": h.get("id"),
                    "name": h.get("name"),
                    "addresses": h.get("addresses", []),
                    "comment": h.get("comment", ""),
                }
                for h in items
            ]
            total_found += len(items)
            steps.append(step_result("Search IPAM hosts", "success", {"count": len(items)}))
        except Exception as e:
            steps.append(step_result("Search IPAM hosts", "failed", error=str(e)))

    # Search IP addresses
    if "addresses" in search_types:
        try:
            resp = client.list_addresses(filter=f'address~"{sanitize_filter(query)}"', limit=limit)
            items = extract_results(resp)
            results["addresses"] = [
                {
                    "id": a.get("id"),
                    "address": a.get("address"),
                    "names": a.get("names", []),
                    "space": a.get("space"),
                    "usage": a.get("usage", []),
                }
                for a in items
            ]
            total_found += len(items)
            steps.append(step_result("Search IP addresses", "success", {"count": len(items)}))
        except Exception as e:
            steps.append(step_result("Search IP addresses", "failed", error=str(e)))

    status = "success" if total_found > 0 else "success"
    summary = f"Found {total_found} result(s) matching '{query}'"

    return intent_response(
        status=status,
        summary=summary,
        steps=steps,
        result=results,
        next_actions=[
            "Use explore_network(scope='...') to see the network context",
            "Use diagnose_dns(domain='...') to troubleshoot DNS issues",
            "Use provision_host() to create a new host",
        ],
    )


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": True})
def get_network_summary(scope: str | None = None) -> dict:
    """
    Get an executive dashboard with counts and health across all DDI infrastructure.
    USE THIS for high-level overviews and reporting.
    For hierarchy browsing use explore_network(). For keyword search use search_infrastructure().

    Args:
        scope: Optional IP space name to focus on. If not set, summarizes everything.

    Returns:
        Summary with counts, utilization percentages, and health status

    Examples:
        - get_network_summary() → full infrastructure overview
        - get_network_summary(scope="production") → production space only
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    steps = []
    summary_data = {}

    # IP Spaces
    try:
        space_filter = f'name~"{sanitize_filter(scope)}"' if scope else None
        spaces = extract_results(client.list_ip_spaces(filter=space_filter))
        summary_data["ip_spaces"] = {"count": len(spaces), "names": [s.get("name", "") for s in spaces]}
        steps.append(step_result("Count IP spaces", "success", {"count": len(spaces)}))
    except Exception as e:
        steps.append(step_result("Count IP spaces", "failed", error=str(e)))

    # Subnets
    try:
        subnets = extract_results(client.list_subnets(limit=1000))
        summary_data["subnets"] = {"count": len(subnets)}
        steps.append(step_result("Count subnets", "success", {"count": len(subnets)}))
    except Exception as e:
        steps.append(step_result("Count subnets", "failed", error=str(e)))

    # Address blocks
    try:
        blocks = extract_results(client.list_address_blocks(limit=1000))
        summary_data["address_blocks"] = {"count": len(blocks)}
        steps.append(step_result("Count address blocks", "success", {"count": len(blocks)}))
    except Exception as e:
        steps.append(step_result("Count address blocks", "failed", error=str(e)))

    # DNS zones
    try:
        auth_zones = extract_results(client.list_auth_zones(limit=1000))
        summary_data["dns_zones"] = {"count": len(auth_zones)}
        steps.append(step_result("Count DNS zones", "success", {"count": len(auth_zones)}))
    except Exception as e:
        steps.append(step_result("Count DNS zones", "failed", error=str(e)))

    # DHCP hosts
    try:
        dhcp_hosts = extract_results(client.list_dhcp_hosts(limit=100))
        summary_data["dhcp_hosts"] = {"count": len(dhcp_hosts)}
        steps.append(step_result("Count DHCP hosts", "success", {"count": len(dhcp_hosts)}))
    except Exception as e:
        steps.append(step_result("Count DHCP hosts", "failed", error=str(e)))

    # HA groups
    try:
        ha_groups = extract_results(client.list_ha_groups(limit=100))
        summary_data["ha_groups"] = {"count": len(ha_groups)}
        steps.append(step_result("Count HA groups", "success", {"count": len(ha_groups)}))
    except Exception as e:
        steps.append(step_result("Count HA groups", "failed", error=str(e)))

    scope_label = f"'{scope}'" if scope else "all"
    total_items = sum(v.get("count", 0) for v in summary_data.values() if isinstance(v, dict))

    return intent_response(
        status="success",
        summary=f"Infrastructure summary ({scope_label}): {total_items} total resources across {len(summary_data)} categories",
        steps=steps,
        result=summary_data,
        next_actions=[
            "Use explore_network(depth='full') for detailed hierarchy",
            "Use get_ip_utilization() for capacity planning",
            "Use check_infrastructure_health() for service health",
        ],
    )


# ==================== Provisioning Tools ====================


@mcp.tool(annotations={"destructiveHint": False, "idempotentHint": False})
def provision_host(
    hostname: str,
    space: str,
    ip: str | None = None,
    zone: str | None = None,
    view: str | None = None,
    subnet: str | None = None,
    auto_dns: bool = True,
    dry_run: bool = True,
    comment: str | None = None,
) -> dict:
    """
    Provision a complete host in one step: creates IPAM host + IP + optional DNS A/PTR records.
    USE THIS when adding a new host to the network. For DNS-only changes use provision_dns().
    To remove a host use decommission_host().

    IMPORTANT: Runs in dry_run mode by default — shows what WOULD be created without actually creating.
    Set dry_run=False to execute the actual provisioning.

    IMPORTANT: When a zone is provided, ASK the user whether they want auto_dns=True (recommended,
    lets the API create DNS records atomically with the host) or auto_dns=False (creates DNS A/PTR
    records as separate steps after host creation, giving more control but less atomicity).

    Args:
        hostname: Host name (e.g., "web-prod-01"). If zone is provided, will be used as FQDN: hostname.zone
        space: IP space name or ID where the host should be created (e.g., "prod", "corp", or full resource ID)
        ip: Optional specific IP address. If not provided, auto-assigns the next available IP from the subnet.
        zone: Optional DNS zone name for creating A/PTR records (e.g., "prod.example.com")
        view: Optional DNS view name or ID. Required when a zone exists in multiple views (e.g., "default", "Azure.private-2")
        subnet: Optional subnet address (CIDR) or ID for auto-IP assignment (e.g., "10.10.20.0/24").
                Required when multiple subnets exist in the space and no IP is specified.
        auto_dns: If True (default), DNS records (A + PTR) are auto-generated atomically by the API
                  during host creation — this matches the "Auto-generate DNS records" option in the UI.
                  If False, DNS A and PTR records are created as separate API calls after host creation.
        dry_run: If True (default), only shows what would be created. Set to False to actually provision.
        comment: Optional description for the host

    Returns:
        Complete provisioning result with host, IP, and DNS record details

    Examples:
        - provision_host(hostname="web-01", space="prod", ip="10.20.3.50", zone="prod.example.com") → DRY RUN
        - provision_host(hostname="web-01", space="prod", ip="10.20.3.50", zone="prod.example.com", dry_run=False)
        - provision_host(hostname="db-replica-02", space="corp", subnet="10.10.20.0/24", dry_run=False)
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    steps = []
    warnings = []
    created_resources = []

    # Step 1: Resolve IP space name to ID if needed
    space_id = space
    if not space.startswith("ipam/ip_space/"):
        try:
            spaces = extract_results(client.list_ip_spaces(filter=f'name=="{sanitize_filter(space)}"'))
            if not spaces:
                spaces = extract_results(client.list_ip_spaces(filter=f'name~"{sanitize_filter(space)}"'))
            if spaces:
                space_id = spaces[0].get("id", space)
                steps.append(
                    step_result("Resolve IP space", "success", {"space_id": space_id, "name": spaces[0].get("name")})
                )
            else:
                return intent_response("failed", f"IP space '{space}' not found", steps)
        except Exception as e:
            return intent_response("failed", f"Failed to resolve IP space: {e}", steps)

    # Step 2: Resolve IP (auto-assign if not provided)
    if not ip:
        try:
            subnets = extract_results(client.list_subnets(filter=f'space=="{space_id}"'))
            if not subnets:
                return intent_response("failed", f"No subnets found in space '{space}' for IP auto-assignment", steps)

            if subnet:
                # Match by ID or CIDR address
                target = [
                    s for s in subnets if s.get("id") == subnet or f"{s.get('address')}/{s.get('cidr')}" == subnet
                ]
                if not target:
                    return intent_response("failed", f"Subnet '{subnet}' not found in space '{space}'", steps)
                target_subnet_id = target[0]["id"]
            elif len(subnets) == 1:
                target_subnet_id = subnets[0]["id"]
            else:
                subnet_list = [f"{s.get('address')}/{s.get('cidr')} (id={s.get('id')})" for s in subnets]
                return intent_response(
                    "failed",
                    f"Multiple subnets in space '{space}': {subnet_list}. Specify 'subnet' or 'ip' to disambiguate.",
                    steps,
                )

            available_ips = client.get_next_available_ip(target_subnet_id)
            if not available_ips:
                return intent_response("failed", "No available IPs in subnet", steps)
            ip = available_ips[0]
            steps.append(step_result("Auto-assign IP", "success", {"ip": ip, "subnet": target_subnet_id}))
        except Exception as e:
            return intent_response("failed", f"Failed to auto-assign IP: {e}", steps)

    # Step 3: Resolve DNS zone (if zone provided)
    zone_id = None
    if zone:
        try:
            zone_id, z_step, z_err = resolve_zone(zone, view)
            if z_step:
                steps.append(z_step)
            if z_err:
                warnings.append(f"{z_err} — DNS records skipped. Create zone first or use provision_dns().")
                steps.append(step_result("Resolve DNS zone", "skipped", error=z_err))
        except Exception as e:
            warnings.append(f"Failed to resolve zone: {e} — DNS records skipped.")
            steps.append(step_result("Resolve DNS zone", "failed", error=str(e)))

    # Dry run: show what would be created without executing
    if dry_run:
        plan = {
            "hostname": hostname,
            "fqdn": f"{hostname}.{zone}"
            if zone and not hostname.rstrip(".").endswith(f".{zone.rstrip('.')}")
            else hostname,
            "ip": ip or "(auto-assigned)",
            "space": space,
            "space_id": space_id,
            "zone": zone,
            "zone_id": zone_id,
            "auto_dns": auto_dns,
        }
        steps.append(step_result("Dry run analysis", "success", {"plan": plan}))
        return intent_response(
            status="success",
            summary=f"DRY RUN: Would provision host '{hostname}' with IP {ip or '(auto)'} in space '{space}'",
            steps=steps,
            result={"mode": "DRY RUN", "plan": plan},
            warnings=warnings + ["This is a DRY RUN. Set dry_run=False to actually provision."],
            next_actions=[
                f"Execute: provision_host(hostname='{hostname}', space='{space}'"
                + (f", ip='{ip}'" if ip else "")
                + (f", zone='{zone}'" if zone else "")
                + ", dry_run=False)"
            ],
        )

    # Step 4: Create IPAM host
    try:
        # Build FQDN and short name: avoid doubling if hostname already includes the zone
        zone_suffix = zone.rstrip(".") if zone else ""
        if zone and not hostname.rstrip(".").endswith(f".{zone_suffix}"):
            fqdn = f"{hostname}.{zone}"
            name_in_zone = hostname  # e.g. "web-prod" for zone "infolab.com"
        else:
            fqdn = hostname
            # Strip zone suffix to get the short name for DNS
            name_in_zone = hostname.rstrip(".").removesuffix(f".{zone_suffix}") if zone_suffix else hostname
        address_config = {"space": space_id, "address": ip}

        # auto_dns=True: let the API create DNS records atomically with the host
        # host_names[].name must be the short name (relative to zone), not the FQDN
        host_kwargs = {}
        if auto_dns and zone_id:
            host_kwargs["auto_generate_records"] = True
            host_kwargs["host_names"] = [{"name": name_in_zone, "zone": zone_id, "primary_name": True}]

        host_resp = client.create_ipam_host(
            name=fqdn, addresses=[address_config], comment=comment or "Provisioned via intent layer", **host_kwargs
        )

        host_result = host_resp.get("result", host_resp)
        host_id = host_result.get("id", "")
        assigned_addresses = host_result.get("addresses", [])
        assigned_ip = ip
        if assigned_addresses:
            assigned_ip = assigned_addresses[0].get("address", ip)

        host_step_data = {"host_id": host_id, "fqdn": fqdn, "ip": assigned_ip}
        if auto_dns and zone_id:
            host_step_data["dns_auto_generated"] = True
            host_step_data["zone_id"] = zone_id
        steps.append(step_result("Create IPAM host", "success", host_step_data))
        created_resources.append({"type": "ipam_host", "id": host_id})

    except Exception as e:
        return intent_response("failed", f"Failed to create IPAM host: {e}", steps)

    # Steps 5-6: Manual DNS record creation (only when auto_dns=False and zone resolved)
    if not auto_dns and zone_id:
        # Step 5: Create DNS A record
        dns_a_id = None
        try:
            a_resp = client.create_dns_record(
                name_in_zone=name_in_zone,
                zone=zone_id,
                record_type="A",
                rdata={"address": assigned_ip or ip},
                comment=f"Auto-created for host {fqdn}",
            )
            dns_a_id = a_resp.get("result", {}).get("id", "")
            steps.append(
                step_result(
                    "Create DNS A record",
                    "success",
                    {"record_id": dns_a_id, "name": fqdn, "address": assigned_ip or ip},
                )
            )
            created_resources.append({"type": "dns_a_record", "id": dns_a_id})
        except Exception as e:
            warnings.append(f"Failed to create A record: {e}")
            steps.append(step_result("Create DNS A record", "failed", error=str(e)))

        # Step 6: Create DNS PTR record
        if assigned_ip and dns_a_id:
            try:
                ip_parts = assigned_ip.split(".")
                reverse_name = ip_parts[3]
                reverse_zone_fqdn = f"{ip_parts[2]}.{ip_parts[1]}.{ip_parts[0]}.in-addr.arpa."

                rev_zones = extract_results(
                    client.list_auth_zones(filter=f'fqdn=="{sanitize_filter(reverse_zone_fqdn)}"')
                )
                if rev_zones:
                    rev_zone_id = rev_zones[0].get("id", "")
                    ptr_resp = client.create_dns_record(
                        name_in_zone=reverse_name,
                        zone=rev_zone_id,
                        record_type="PTR",
                        rdata={"dname": fqdn},
                        comment=f"Auto-created for host {fqdn}",
                    )
                    ptr_id = ptr_resp.get("result", {}).get("id", "")
                    steps.append(
                        step_result(
                            "Create DNS PTR record",
                            "success",
                            {"record_id": ptr_id, "reverse": f"{reverse_name}.{reverse_zone_fqdn}", "points_to": fqdn},
                        )
                    )
                    created_resources.append({"type": "dns_ptr_record", "id": ptr_id})
                else:
                    warnings.append(f"Reverse DNS zone not found for {assigned_ip} — skipped PTR record")
                    steps.append(step_result("Create DNS PTR record", "skipped", error="Reverse zone not found"))
            except Exception as e:
                warnings.append(f"Failed to create PTR record: {e}")
                steps.append(step_result("Create DNS PTR record", "failed", error=str(e)))

    # Build summary
    success_count = sum(1 for s in steps if s["status"] == "success")
    total_count = len(steps)
    status = "success" if success_count == total_count else "partial" if success_count > 0 else "failed"

    next = [
        f"Verify: search_infrastructure(query='{hostname}')",
        f"Diagnose: diagnose_dns(domain='{hostname}.{zone}')" if zone else "Add DNS: provision_dns()",
        "Decommission: decommission_host(identifier='...')",
    ]
    if status == "partial":
        next.insert(0, f"Rollback partial provisioning: decommission_host(identifier='{hostname}', dry_run=True)")

    return intent_response(
        status=status,
        summary=f"Host '{hostname}' provisioned: {success_count}/{total_count} steps completed",
        steps=steps,
        result={
            "hostname": hostname,
            "fqdn": f"{hostname}.{zone}" if zone else hostname,
            "ip": assigned_ip or ip,
            "space": space,
            "created_resources": created_resources,
        },
        warnings=warnings,
        next_actions=next,
    )


@mcp.tool(annotations={"destructiveHint": False, "idempotentHint": False})
def provision_dns(
    name: str,
    record_type: Literal["A", "AAAA", "CNAME", "MX", "TXT", "PTR", "SRV", "NS"],
    value: str,
    zone: str | None = None,
    view: str | None = None,
    ttl: int | None = None,
    dry_run: bool = True,
    comment: str | None = None,
) -> dict:
    """
    Create a new DNS record with automatic zone discovery and validation.
    USE THIS to create records. For update/delete/list use manage_dns_record().

    IMPORTANT: Runs in dry_run mode by default — shows what WOULD be created without actually creating.
    Set dry_run=False to execute the actual DNS record creation.

    Args:
        name: Record name (e.g., "www" for www.example.com, or full FQDN "www.example.com")
        record_type: DNS record type
        value: Record value — IP for A/AAAA, domain for CNAME/MX/PTR/NS, text for TXT
        zone: DNS zone name (e.g., "example.com"). If not provided, extracted from the name.
        view: Optional DNS view name or ID. Required when a zone exists in multiple views (e.g., "default", "Azure.private-2")
        ttl: Time to live in seconds (optional)
        dry_run: If True (default), only shows what would be created. Set to False to actually create.
        comment: Optional description

    Returns:
        Created DNS record details

    Examples:
        - provision_dns(name="www", record_type="A", value="10.20.3.50", zone="example.com") → DRY RUN
        - provision_dns(name="www", record_type="A", value="10.20.3.50", zone="example.com", dry_run=False)
        - provision_dns(name="app.example.com", record_type="CNAME", value="lb.example.com", dry_run=False)
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    steps = []

    # Parse zone from FQDN if not provided
    name_in_zone = name
    if not zone and "." in name:
        parts = name.split(".", 1)
        name_in_zone = parts[0]
        zone = parts[1]

    if not zone:
        return intent_response("failed", "Could not determine DNS zone. Provide zone parameter or use FQDN as name.")

    # Step 1: Find the zone
    zone_id, z_step, z_err = resolve_zone(zone, view)
    if z_step:
        steps.append(z_step)
    if z_err:
        return intent_response(
            "failed",
            z_err,
            steps,
            next_actions=[f"Create zone '{zone}' in Infoblox Portal, then retry"],
        )

    # Step 2: Build rdata based on record type
    rdata = {}
    rt = record_type.upper()
    if rt in ("A", "AAAA"):
        rdata = {"address": value}
    elif rt in ("CNAME", "PTR", "NS"):
        rdata = {"dname": value}
    elif rt == "MX":
        # Parse "10 mail.example.com" or just "mail.example.com"
        parts = value.split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            rdata = {"preference": int(parts[0]), "exchange": parts[1]}
        else:
            rdata = {"preference": 10, "exchange": value}
    elif rt == "TXT":
        rdata = {"text": value}
    else:
        rdata = {"text": value}

    # Dry run: show what would be created without executing
    if dry_run:
        plan = {
            "name": name_in_zone,
            "fqdn": f"{name_in_zone}.{zone}",
            "type": rt,
            "value": value,
            "zone": zone,
            "zone_id": zone_id,
            "rdata": rdata,
        }
        if ttl:
            plan["ttl"] = ttl
        steps.append(step_result("Dry run analysis", "success", {"plan": plan}))
        return intent_response(
            status="success",
            summary=f"DRY RUN: Would create {rt} record: {name_in_zone}.{zone} → {value}",
            steps=steps,
            result={"mode": "DRY RUN", "plan": plan},
            warnings=["This is a DRY RUN. Set dry_run=False to actually create the record."],
            next_actions=[
                f"Execute: provision_dns(name='{name}', record_type='{record_type}', value='{value}'"
                + (f", zone='{zone}'" if zone else "")
                + ", dry_run=False)"
            ],
        )

    # Step 3: Create the record
    # The zone_id from resolve_zone(zone, view) is already view-specific
    try:
        resp = client.create_dns_record(
            name_in_zone=name_in_zone,
            zone=zone_id,
            record_type=rt,
            rdata=rdata,
            ttl=ttl,
            comment=comment or "Created via intent layer",
        )
        record_result = resp.get("result", resp)
        record_id = record_result.get("id", "")
        steps.append(
            step_result(
                f"Create {rt} record",
                "success",
                {"record_id": record_id, "fqdn": f"{name_in_zone}.{zone}", "type": rt, "value": value},
            )
        )
    except Exception as e:
        err = str(e)
        if "409" in err and "already exists" in err.lower():
            steps.append(step_result(f"Create {rt} record", "skipped", {"reason": "already_exists"}))
            return intent_response(
                status="success",
                summary=f"{rt} record already exists: {name_in_zone}.{zone} → {value} (no changes made)",
                steps=steps,
                result={"fqdn": f"{name_in_zone}.{zone}", "type": rt, "value": value, "already_existed": True},
                next_actions=[
                    f"Verify: diagnose_dns(domain='{name_in_zone}.{zone}')",
                    f"Update: manage_dns_record(action='update', name='{name_in_zone}.{zone}', zone='{zone}', record_type='{rt}', ...)",
                ],
            )
        return intent_response("failed", f"Failed to create {rt} record: {e}", steps)

    return intent_response(
        status="success",
        summary=f"{rt} record created: {name_in_zone}.{zone} → {value}",
        steps=steps,
        result={"record_id": record_id, "fqdn": f"{name_in_zone}.{zone}", "type": rt, "value": value},
        next_actions=[
            f"Verify: diagnose_dns(domain='{name_in_zone}.{zone}')",
            f"Search: search_infrastructure(query='{name_in_zone}')",
        ],
    )


@mcp.tool(annotations={"destructiveHint": True, "idempotentHint": False})
def decommission_host(identifier: str, dry_run: bool = True) -> dict:
    """
    Decommission a host: removes IPAM host, DNS records, and releases IP addresses.
    USE THIS to fully remove a host. For partial cleanup use manage_dns_record() or manage_ip_reservation().

    IMPORTANT: Runs in dry_run mode by default — shows what WOULD be deleted without actually deleting.
    Set dry_run=False to execute the actual decommission.

    Args:
        identifier: Hostname, FQDN, or IP address to decommission
        dry_run: If True (default), only shows what would be deleted. Set to False to actually delete.

    Returns:
        List of resources that were (or would be) deleted

    Examples:
        - decommission_host(identifier="web-prod-01") → shows what would be deleted
        - decommission_host(identifier="web-prod-01", dry_run=False) → actually deletes everything
        - decommission_host(identifier="10.20.3.50") → finds and decommissions host at this IP
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    steps = []
    warnings = []
    resources_to_delete = []
    mode = "DRY RUN" if dry_run else "EXECUTING"

    # Step 1: Find IPAM hosts matching the identifier
    try:
        hosts = extract_results(client.list_ipam_hosts(filter=f'name~"{sanitize_filter(identifier)}"'))
        if not hosts:
            # Try searching by IP in addresses
            addresses = extract_results(client.list_addresses(filter=f'address=="{sanitize_filter(identifier)}"'))
            if addresses:
                # Find host associated with this IP
                for addr in addresses:
                    names = addr.get("names", [])
                    for name_info in names:
                        host_name = name_info.get("name", "")
                        if host_name:
                            hosts = extract_results(
                                client.list_ipam_hosts(filter=f'name=="{sanitize_filter(host_name)}"')
                            )
                            break

        if not hosts:
            return intent_response("failed", f"No host found matching '{identifier}'", steps)

        steps.append(
            step_result("Find hosts", "success", {"count": len(hosts), "hosts": [h.get("name") for h in hosts]})
        )

        for host in hosts:
            host_id = host.get("id", "")
            host_name = host.get("name", "")
            host_addresses = host.get("addresses", [])
            auto_dns = host.get("auto_generate_records", False)

            resources_to_delete.append(
                {"type": "ipam_host", "id": host_id, "name": host_name, "auto_generate_records": auto_dns}
            )

            # Find associated IP addresses (released automatically when host is deleted)
            for addr_info in host_addresses:
                addr = addr_info.get("address", "")
                if addr:
                    resources_to_delete.append({"type": "ip_release", "address": addr, "auto_released": True})

            # Search for DNS records matching this host
            # If auto_generate_records=True, DNS records are system-managed and auto-deleted with the host
            if auto_dns:
                resources_to_delete.append(
                    {"type": "dns_auto_managed", "note": "DNS records auto-generated; will be deleted with host"}
                )
            else:
                try:
                    dns_records = extract_results(
                        client.list_dns_records(filter=f'absolute_name_spec~"{sanitize_filter(host_name)}"')
                    )
                    for record in dns_records:
                        resources_to_delete.append(
                            {
                                "type": f"dns_{record.get('type', 'unknown')}_record",
                                "id": record.get("id", ""),
                                "name": record.get("absolute_name_spec", ""),
                            }
                        )
                except Exception as e:
                    warnings.append(f"DNS record lookup failed: {e}")

    except Exception as e:
        return intent_response("failed", f"Failed to find host: {e}", steps)

    # Step 2: Execute deletion if not dry_run
    if not dry_run:
        deleted = []

        # Phase 1: Delete manual DNS records FIRST (before host deletion)
        # Skip dns_auto_managed — those are cleaned up automatically when the host is deleted
        for resource in resources_to_delete:
            res_type = resource.get("type", "")
            res_id = resource.get("id", "")
            if res_type.startswith("dns_") and res_type != "dns_auto_managed" and res_id:
                try:
                    client.delete_dns_record(res_id)
                    deleted.append(resource)
                    steps.append(step_result(f"Delete {res_type} {resource.get('name')}", "success"))
                except Exception as e:
                    err_str = str(e)
                    if "404" in err_str or "not found" in err_str.lower():
                        steps.append(step_result(f"Delete {res_type}", "skipped", error="Already deleted"))
                    elif "forbidden" in err_str.lower() or "system" in err_str.lower():
                        steps.append(
                            step_result(f"Delete {res_type}", "skipped", error="System-managed record (auto-cleaned)")
                        )
                    else:
                        warnings.append(f"Failed to delete {res_type}: {e}")
                        steps.append(step_result(f"Delete {res_type}", "failed", error=err_str))

        # Phase 2: Delete IPAM hosts (cascades auto-generated DNS + releases IPs)
        for resource in resources_to_delete:
            if resource.get("type") == "ipam_host" and resource.get("id"):
                try:
                    client.delete_ipam_host(resource["id"])
                    deleted.append(resource)
                    detail = f"Delete host {resource.get('name')}"
                    if resource.get("auto_generate_records"):
                        detail += " (DNS auto-cleaned)"
                    steps.append(step_result(detail, "success"))
                except Exception as e:
                    steps.append(step_result(f"Delete host {resource.get('name')}", "failed", error=str(e)))

        summary = f"Decommissioned: {len(deleted)}/{len([r for r in resources_to_delete if r['type'] not in ('ip_release', 'dns_auto_managed')])} resources deleted"
    else:
        summary = f"DRY RUN: Would delete {len(resources_to_delete)} resource(s)"
        steps.append(step_result("Dry run analysis", "success", {"resources": resources_to_delete}))

    return intent_response(
        status="success",
        summary=summary,
        steps=steps,
        result={"mode": mode, "resources": resources_to_delete, "identifier": identifier},
        warnings=warnings + (["This is a DRY RUN. Set dry_run=False to actually delete."] if dry_run else []),
        next_actions=[
            f"Execute: decommission_host(identifier='{identifier}', dry_run=False)"
            if dry_run
            else f"Verify: search_infrastructure(query='{identifier}')"
        ],
    )


# ==================== Troubleshooting Tools ====================


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": True})
def diagnose_dns(domain: str, view: str | None = None, flush_cache: bool = False) -> dict:
    """
    Diagnose DNS resolution problems for a domain: checks zone, records, and security policies.
    USE THIS when a domain isn't resolving or has DNS issues.
    For IP-level issues use diagnose_ip_conflict(). For infrastructure-wide health use check_infrastructure_health().

    Args:
        domain: Domain name to diagnose (e.g., "web-prod-01.example.com" or "example.com")
        view: Optional DNS view name or ID. Required when a zone exists in multiple views (e.g., "default", "Azure.private-2")
        flush_cache: If True, flushes the DNS cache for the domain before diagnosing.
                     Useful when DNS changes aren't propagating. ASK the user before flushing.

    Returns:
        Diagnostic report with zone status, records found, and recommendations

    Examples:
        - diagnose_dns(domain="app.example.com") → checks zone, A/AAAA/CNAME records, security
        - diagnose_dns(domain="app.example.com", view="default") → checks in specific view
        - diagnose_dns(domain="app.example.com", flush_cache=True) → flushes cache then diagnoses
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    steps = []
    diagnostics = {"domain": domain, "issues": [], "records": []}

    # Parse domain parts
    parts = domain.split(".", 1)
    name_part = parts[0] if len(parts) > 1 else ""
    zone_part = parts[1] if len(parts) > 1 else domain

    # Step 1: Check if zone exists
    zone_found = False
    zone_id = None
    zone_id, z_step, z_err = resolve_zone(zone_part, view)
    if z_err and "." in zone_part:
        # Try parent zone
        parent = zone_part.split(".", 1)[1]
        zone_id, z_step, z_err = resolve_zone(parent, view)
        if not z_err:
            name_part = domain.replace(f".{parent}", "")
            zone_part = parent

    if z_step:
        steps.append(z_step)
    if not z_err and zone_id:
        zone_found = True
        diagnostics["zone"] = {"status": "found", "fqdn": zone_part, "id": zone_id}
    else:
        diagnostics["zone"] = {"status": "not_found"}
        diagnostics["issues"].append(z_err or f"DNS zone '{zone_part}' not found")
        steps.append(step_result("Check DNS zone", "failed", error=z_err or f"Zone '{zone_part}' not found"))

    # Step 1b: Flush DNS cache if requested
    if flush_cache:
        try:
            view_id = None
            if view and zone_found:
                # Use the view from zone resolution
                view_id = diagnostics["zone"].get("id", "").split("/")[-1] if False else None
            client.flush_dns_cache(domain, view_id=view_id)
            steps.append(step_result("Flush DNS cache", "success", {"domain": domain}))
        except Exception as e:
            warnings_msg = f"Cache flush failed: {e}"
            diagnostics.setdefault("warnings", []).append(warnings_msg)
            steps.append(step_result("Flush DNS cache", "failed", error=str(e)))

    # Step 2: Check DNS records for this domain
    try:
        records = extract_results(
            client.list_dns_records(
                filter=f'absolute_name_spec=="{sanitize_filter(domain)}" or absolute_name_spec=="{sanitize_filter(domain)}."'
            )
        )
        if not records and name_part:
            records = extract_results(client.list_dns_records(filter=f'name_in_zone=="{sanitize_filter(name_part)}"'))

        diagnostics["records"] = [
            {"type": r.get("type"), "name": r.get("absolute_name_spec"), "rdata": r.get("rdata"), "ttl": r.get("ttl")}
            for r in records
        ]

        record_types = [r.get("type") for r in records]
        steps.append(step_result("Check DNS records", "success", {"count": len(records), "types": record_types}))

        if not records:
            diagnostics["issues"].append(f"No DNS records found for '{domain}'")
        else:
            if "A" not in record_types and "AAAA" not in record_types and "CNAME" not in record_types:
                diagnostics["issues"].append("No A, AAAA, or CNAME record found — domain won't resolve to an IP")

    except Exception as e:
        steps.append(step_result("Check DNS records", "failed", error=str(e)))

    # Step 3: Check security policies (if atcfw client available)
    if atcfw_client:
        try:
            policies = extract_results(atcfw_client.list_security_policies())
            diagnostics["security"] = {"policies_count": len(policies), "status": "checked"}
            steps.append(step_result("Check security policies", "success", {"policies": len(policies)}))
        except Exception as e:
            steps.append(step_result("Check security policies", "failed", error=str(e)))
    else:
        diagnostics["security"] = {"status": "client_not_available"}

    # Build recommendations
    recommendations = []
    if not zone_found:
        recommendations.append(f"Create DNS zone '{zone_part}' first")
    if not diagnostics.get("records"):
        recommendations.append(
            f"Create A record: provision_dns(name='{name_part}', record_type='A', value='<IP>', zone='{zone_part}')"
        )
    if diagnostics.get("records") and "PTR" not in [r["type"] for r in diagnostics["records"]]:
        recommendations.append("Consider adding a PTR record for reverse DNS")

    issue_count = len(diagnostics["issues"])
    status = "success" if issue_count == 0 else "partial"
    summary = (
        f"DNS diagnosis for '{domain}': {issue_count} issue(s) found, {len(diagnostics.get('records', []))} record(s)"
    )

    return intent_response(
        status=status,
        summary=summary,
        steps=steps,
        result=diagnostics,
        next_actions=recommendations or ["No issues found — DNS appears healthy"],
    )


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": True})
def diagnose_ip_conflict(address: str) -> dict:
    """
    Check an IP address for conflicts: overlapping subnets, duplicate reservations, DHCP usage, and host associations.
    USE THIS when troubleshooting IP conflicts or verifying an IP is safe to use.
    For DNS-level issues use diagnose_dns(). For infrastructure-wide health use check_infrastructure_health().

    Args:
        address: IP address to check (e.g., "10.20.3.50")

    Returns:
        Conflict report with overlapping resources, DHCP lease status, host associations, and recommendations

    Examples:
        - diagnose_ip_conflict(address="10.20.3.50") → checks for conflicts on this IP
        - diagnose_ip_conflict(address="192.168.1.1") → checks subnet membership and reservations
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    steps = []
    diagnostics = {"address": address, "conflicts": [], "found_in": []}

    # Step 1: Check subnets containing this IP
    try:
        subnets = extract_results(
            client.list_subnets(filter=f'address~"{sanitize_filter(".".join(address.split(".")[:3]))}"')
        )
        matching_subnets = []
        for s in subnets:
            subnet_addr = s.get("address", "")
            if subnet_addr:
                matching_subnets.append(
                    {"id": s.get("id"), "address": subnet_addr, "cidr": s.get("cidr"), "name": s.get("comment", "")}
                )
        diagnostics["subnets"] = matching_subnets
        steps.append(step_result("Check subnets", "success", {"count": len(matching_subnets)}))

        if len(matching_subnets) > 1:
            diagnostics["conflicts"].append(f"IP belongs to {len(matching_subnets)} subnets — possible overlap")
    except Exception as e:
        steps.append(step_result("Check subnets", "failed", error=str(e)))

    # Step 2: Check IP address records
    try:
        addresses = extract_results(client.list_addresses(filter=f'address=="{sanitize_filter(address)}"'))
        diagnostics["address_records"] = [
            {"id": a.get("id"), "address": a.get("address"), "usage": a.get("usage", []), "names": a.get("names", [])}
            for a in addresses
        ]
        steps.append(step_result("Check address records", "success", {"count": len(addresses)}))

        if len(addresses) > 1:
            diagnostics["conflicts"].append(f"Multiple address records found for {address}")
    except Exception as e:
        steps.append(step_result("Check address records", "failed", error=str(e)))

    # Step 3: Check IP ranges
    try:
        ranges = extract_results(
            client.list_ranges(filter=f'start<="{sanitize_filter(address)}" and end>="{sanitize_filter(address)}"')
        )
        diagnostics["ranges"] = [
            {"id": r.get("id"), "start": r.get("start"), "end": r.get("end"), "comment": r.get("comment", "")}
            for r in ranges
        ]
        steps.append(step_result("Check IP ranges", "success", {"count": len(ranges)}))
    except Exception as e:
        steps.append(step_result("Check IP ranges", "failed", error=str(e)))

    # Step 4: Check IPAM host associations
    try:
        hosts = extract_results(client.list_ipam_hosts(filter=f'address=="{sanitize_filter(address)}"'))
        diagnostics["host_associations"] = [
            {"id": h.get("id"), "name": h.get("name"), "comment": h.get("comment", "")} for h in hosts
        ]
        steps.append(step_result("Check host associations", "success", {"count": len(hosts)}))
        if len(hosts) > 1:
            diagnostics["conflicts"].append(f"Multiple IPAM hosts associated with {address}")
    except Exception as e:
        steps.append(step_result("Check host associations", "failed", error=str(e)))

    conflict_count = len(diagnostics["conflicts"])
    status = "success" if conflict_count == 0 else "partial"

    return intent_response(
        status=status,
        summary=f"IP conflict check for {address}: {conflict_count} conflict(s) found",
        steps=steps,
        result=diagnostics,
        next_actions=[
            "No conflicts — IP is safe to use" if conflict_count == 0 else f"Resolve conflicts before using {address}"
        ],
    )


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": False})
def check_api_health() -> dict:
    """
    Verify Infoblox API connectivity for all three service clients (DDI, Insights, ATCFW).
    USE THIS to diagnose connection issues, check if API keys are valid, or verify the MCP server can reach Infoblox.
    For infrastructure health (HA groups, DNS zones, etc.) use check_infrastructure_health().

    Returns:
        Health status for each API client with response times

    Examples:
        - check_api_health() → shows which APIs are reachable and response latency
    """
    import time as _time

    steps = []
    results = {}
    healthy_count = 0
    total = 0

    # Check DDI API (InfobloxClient)
    if client:
        total += 1
        try:
            start = _time.time()
            client.list_ip_spaces(limit=1)
            latency_ms = round((_time.time() - start) * 1000)
            results["ddi_api"] = {"status": "healthy", "latency_ms": latency_ms}
            steps.append(step_result("DDI API", "success", {"latency_ms": latency_ms}))
            healthy_count += 1
        except Exception as e:
            results["ddi_api"] = {"status": "unreachable", "error": str(e)}
            steps.append(step_result("DDI API", "failed", error=str(e)))
    else:
        results["ddi_api"] = {"status": "not_initialized"}
        steps.append(step_result("DDI API", "skipped", error="Client not initialized"))

    # Check Insights API
    if insights_client:
        total += 1
        try:
            start = _time.time()
            insights_client.list_insights(limit=1)
            latency_ms = round((_time.time() - start) * 1000)
            results["insights_api"] = {"status": "healthy", "latency_ms": latency_ms}
            steps.append(step_result("Insights API", "success", {"latency_ms": latency_ms}))
            healthy_count += 1
        except Exception as e:
            results["insights_api"] = {"status": "unreachable", "error": str(e)}
            steps.append(step_result("Insights API", "failed", error=str(e)))
    else:
        results["insights_api"] = {"status": "not_initialized"}
        steps.append(step_result("Insights API", "skipped", error="Client not initialized"))

    # Check ATCFW API
    if atcfw_client:
        total += 1
        try:
            start = _time.time()
            atcfw_client.list_security_policies(limit=1)
            latency_ms = round((_time.time() - start) * 1000)
            results["atcfw_api"] = {"status": "healthy", "latency_ms": latency_ms}
            steps.append(step_result("ATCFW API", "success", {"latency_ms": latency_ms}))
            healthy_count += 1
        except Exception as e:
            results["atcfw_api"] = {"status": "unreachable", "error": str(e)}
            steps.append(step_result("ATCFW API", "failed", error=str(e)))
    else:
        results["atcfw_api"] = {"status": "not_initialized"}
        steps.append(step_result("ATCFW API", "skipped", error="Client not initialized"))

    if total == 0:
        return intent_response("failed", "No API clients initialized. Check INFOBLOX_API_KEY.", steps, result=results)

    status = "success" if healthy_count == total else "partial" if healthy_count > 0 else "failed"
    return intent_response(
        status=status,
        summary=f"API health: {healthy_count}/{total} services reachable",
        steps=steps,
        result=results,
        next_actions=["Use check_infrastructure_health() for DDI component health"],
    )


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": True})
def check_infrastructure_health() -> dict:
    """
    Check the health of all DDI infrastructure components: HA groups, DHCP hosts, DNS zones, DNS views, and IP spaces.
    USE THIS for operational health monitoring and alerting.
    For capacity planning use get_ip_utilization(). For security health use assess_security_posture().

    Returns:
        Health report with HA status, DHCP status, DNS status, DNS views, and recommendations

    Examples:
        - check_infrastructure_health() → full health check of all DDI components
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    steps = []
    health = {"components": {}, "issues": []}

    # Check HA groups
    try:
        ha_groups = extract_results(client.list_ha_groups())
        health["components"]["ha_groups"] = {
            "count": len(ha_groups),
            "status": "healthy" if ha_groups else "no_ha_configured",
            "groups": [{"name": g.get("name"), "mode": g.get("mode")} for g in ha_groups],
        }
        if not ha_groups:
            health["issues"].append("No HA groups configured — single point of failure risk")
        steps.append(step_result("Check HA groups", "success", {"count": len(ha_groups)}))
    except Exception as e:
        steps.append(step_result("Check HA groups", "failed", error=str(e)))

    # Check DHCP hosts
    try:
        dhcp_hosts = extract_results(client.list_dhcp_hosts())
        health["components"]["dhcp_hosts"] = {
            "count": len(dhcp_hosts),
            "status": "healthy" if dhcp_hosts else "no_dhcp_hosts",
        }
        steps.append(step_result("Check DHCP hosts", "success", {"count": len(dhcp_hosts)}))
    except Exception as e:
        steps.append(step_result("Check DHCP hosts", "failed", error=str(e)))

    # Check DNS zones
    try:
        zones = extract_results(client.list_auth_zones())
        health["components"]["dns_zones"] = {"count": len(zones), "status": "healthy" if zones else "no_zones"}
        steps.append(step_result("Check DNS zones", "success", {"count": len(zones)}))
    except Exception as e:
        steps.append(step_result("Check DNS zones", "failed", error=str(e)))

    # Check IP spaces
    try:
        spaces = extract_results(client.list_ip_spaces())
        health["components"]["ip_spaces"] = {"count": len(spaces), "status": "healthy" if spaces else "no_spaces"}
        steps.append(step_result("Check IP spaces", "success", {"count": len(spaces)}))
    except Exception as e:
        steps.append(step_result("Check IP spaces", "failed", error=str(e)))

    # Check DNS views
    try:
        views = extract_results(client.list_dns_views())
        health["components"]["dns_views"] = {
            "count": len(views),
            "status": "healthy" if views else "no_views",
            "views": [{"id": v.get("id"), "name": v.get("name")} for v in views],
        }
        steps.append(step_result("Check DNS views", "success", {"count": len(views)}))
    except Exception as e:
        steps.append(step_result("Check DNS views", "failed", error=str(e)))

    # Check on-prem infrastructure hosts
    try:
        infra_hosts = extract_results(client.list_infra_hosts())
        health["components"]["infra_hosts"] = {
            "count": len(infra_hosts),
            "status": "healthy" if infra_hosts else "no_infra_hosts",
            "hosts": [
                {
                    "display_name": h.get("display_name", h.get("host_name", "")),
                    "ip_address": h.get("ip_address", ""),
                    "host_type": h.get("host_type", ""),
                    "status": h.get("composite_status", ""),
                }
                for h in infra_hosts[:20]
            ],
        }
        degraded = [h for h in infra_hosts if h.get("composite_status", "").lower() not in ("online", "success", "")]
        if degraded:
            health["issues"].append(
                f"{len(degraded)} infrastructure host(s) not healthy: "
                + ", ".join(h.get("display_name", "unknown") for h in degraded[:5])
            )
        steps.append(step_result("Check infra hosts", "success", {"count": len(infra_hosts)}))
    except Exception as e:
        steps.append(step_result("Check infra hosts", "failed", error=str(e)))

    # Check infrastructure services
    try:
        infra_services = extract_results(client.list_infra_services())
        health["components"]["infra_services"] = {
            "count": len(infra_services),
            "status": "healthy" if infra_services else "no_services",
            "services": [
                {
                    "name": s.get("name", s.get("service_name", "")),
                    "service_type": s.get("service_type", ""),
                    "status": s.get("composite_status", ""),
                    "host": s.get("host_display_name", ""),
                }
                for s in infra_services[:20]
            ],
        }
        degraded_svc = [
            s for s in infra_services if s.get("composite_status", "").lower() not in ("online", "success", "")
        ]
        if degraded_svc:
            health["issues"].append(
                f"{len(degraded_svc)} infrastructure service(s) not healthy: "
                + ", ".join(s.get("name", "unknown") for s in degraded_svc[:5])
            )
        steps.append(step_result("Check infra services", "success", {"count": len(infra_services)}))
    except Exception as e:
        steps.append(step_result("Check infra services", "failed", error=str(e)))

    # Overall health
    failed_steps = sum(1 for s in steps if s["status"] == "failed")
    issue_count = len(health["issues"])
    if failed_steps > 0:
        health["overall"] = "degraded"
    elif issue_count > 0:
        health["overall"] = "warning"
    else:
        health["overall"] = "healthy"

    return intent_response(
        status="success",
        summary=f"Infrastructure health: {health['overall']} — {issue_count} issue(s), {len(steps)} components checked",
        steps=steps,
        result=health,
        next_actions=[
            "All systems healthy" if health["overall"] == "healthy" else "Review issues and take corrective action"
        ],
    )


# ==================== Security & Threat Intelligence Tools ====================


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": True})
def investigate_threat(
    query: str | None = None,
    priority: Literal["critical", "high", "medium", "low"] | None = None,
    limit: int = 20,
) -> dict:
    """
    Investigate active security threats: aggregates SOC insights, indicators, affected assets, and timeline events.
    USE THIS for threat investigation and incident response.
    For policy compliance use assess_security_posture(). For triage actions use triage_security_insight().

    Args:
        query: Optional search term or threat type (e.g., "malware", "phishing", "data_exfiltration")
        priority: Filter by priority level
        limit: Maximum insights to return (default: 20)

    Returns:
        Aggregated threat intelligence with indicators, affected assets, events timeline, and recommendations

    Examples:
        - investigate_threat() → all open security insights
        - investigate_threat(priority="critical") → critical threats only
        - investigate_threat(query="malware") → malware-related insights
    """
    if not insights_client:
        return intent_response(
            "failed",
            "Insights client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    steps = []
    warnings = []
    limit = min(limit, 100)

    # Step 1: Get security insights
    try:
        insights_resp = insights_client.list_insights(status="OPEN", threat_type=query, priority=priority, limit=limit)
        insights = extract_results(insights_resp)
        steps.append(step_result("Fetch security insights", "success", {"count": len(insights)}))
    except Exception as e:
        return intent_response("failed", f"Failed to fetch security insights: {e}", steps)

    # Step 2: For top insights, get indicators and assets
    enriched_insights = []
    for insight in insights[:5]:  # Enrich top 5
        insight_id = insight.get("id", "")
        enriched = {
            "id": insight_id,
            "title": insight.get("title", ""),
            "status": insight.get("status", ""),
            "priority": insight.get("priority", ""),
            "threat_type": insight.get("threat_type", ""),
            "indicators": [],
            "affected_assets": [],
        }

        # Get indicators
        try:
            indicators_resp = insights_client.get_insight_indicators(insight_id, limit=10)
            indicators = extract_results(indicators_resp)
            enriched["indicators"] = [
                {"type": i.get("type"), "value": i.get("value"), "confidence": i.get("confidence")}
                for i in indicators[:10]
            ]
            enriched["indicator_count"] = len(indicators)
        except Exception as e:
            warnings.append(f"Indicator enrichment failed for insight {insight_id}: {e}")

        # Get affected assets
        try:
            assets_resp = insights_client.get_insight_assets(insight_id, limit=10)
            assets = extract_results(assets_resp)
            enriched["affected_assets"] = [
                {"ip": a.get("ip"), "mac": a.get("mac"), "os": a.get("os_version")} for a in assets[:10]
            ]
            enriched["asset_count"] = len(assets)
        except Exception as e:
            warnings.append(f"Asset enrichment failed for insight {insight_id}: {e}")

        # Get security events (timeline context)
        try:
            events_resp = insights_client.get_insight_events(insight_id, limit=10)
            events = extract_results(events_resp)
            enriched["events"] = [
                {
                    "type": e.get("type", ""),
                    "detected_at": e.get("detected_at", ""),
                    "device_ip": e.get("device_ip", ""),
                    "threat_level": e.get("threat_level", ""),
                }
                for e in events[:10]
            ]
            enriched["event_count"] = len(events)
        except Exception as e:
            warnings.append(f"Event enrichment failed for insight {insight_id}: {e}")

        enriched_insights.append(enriched)

    steps.append(step_result("Enrich top insights", "success", {"enriched": len(enriched_insights)}))

    # Summary stats
    critical = sum(1 for i in insights if i.get("priority") == "critical")
    high = sum(1 for i in insights if i.get("priority") == "high")

    return intent_response(
        status="success",
        summary=f"Found {len(insights)} open insight(s): {critical} critical, {high} high priority",
        steps=steps,
        result={
            "total_insights": len(insights),
            "by_priority": {"critical": critical, "high": high},
            "insights": enriched_insights,
        },
        warnings=warnings,
        next_actions=[
            "Review critical insights and update status",
            "Use assess_security_posture() for policy compliance",
        ],
    )


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": True})
def assess_security_posture() -> dict:
    """
    Assess overall DNS security posture: policies, named lists, category filters, compliance, and analytics.
    USE THIS for security audits and compliance reporting.
    For active threat investigation use investigate_threat(). For triage actions use triage_security_insight().

    Returns:
        Security posture assessment with policy status, category filter coverage, compliance findings, and recommendations

    Examples:
        - assess_security_posture() → full security assessment
    """
    if not atcfw_client and not insights_client:
        return intent_response("failed", "No security clients initialized. Check INFOBLOX_API_KEY.")

    steps = []
    posture = {"policies": {}, "compliance": {}, "analytics": {}}

    # Check security policies
    if atcfw_client:
        try:
            policies = extract_results(atcfw_client.list_security_policies())
            posture["policies"] = {
                "count": len(policies),
                "policies": [{"id": p.get("id"), "name": p.get("name")} for p in policies],
            }
            steps.append(step_result("Check security policies", "success", {"count": len(policies)}))
        except Exception as e:
            steps.append(step_result("Check security policies", "failed", error=str(e)))
    else:
        steps.append(step_result("Check security policies", "skipped", error="Atcfw client not available"))

    # Check threat named lists
    if atcfw_client:
        try:
            named_lists = extract_results(atcfw_client.list_named_lists())
            posture["threat_lists"] = {
                "count": len(named_lists),
                "lists": [{"name": n.get("name"), "type": n.get("type")} for n in named_lists[:10]],
            }
            steps.append(step_result("Check threat named lists", "success", {"count": len(named_lists)}))
        except Exception as e:
            steps.append(step_result("Check threat named lists", "failed", error=str(e)))

    # Check category filters (content filtering coverage)
    if atcfw_client:
        try:
            cat_filters = extract_results(atcfw_client.list_category_filters())
            posture["category_filters"] = {
                "count": len(cat_filters),
                "filters": [{"id": f.get("id"), "name": f.get("name")} for f in cat_filters[:10]],
            }
            steps.append(step_result("Check category filters", "success", {"count": len(cat_filters)}))
        except Exception as e:
            steps.append(step_result("Check category filters", "failed", error=str(e)))

        try:
            content_cats = extract_results(atcfw_client.list_content_categories())
            posture["content_categories"] = {"count": len(content_cats)}
            steps.append(step_result("Check content categories", "success", {"count": len(content_cats)}))
        except Exception as e:
            steps.append(step_result("Check content categories", "failed", error=str(e)))

    # Check policy compliance insights
    if insights_client:
        try:
            compliance = extract_results(insights_client.list_policy_check_insights())
            posture["compliance"] = {
                "count": len(compliance),
                "findings": [{"check_type": c.get("check_type"), "status": c.get("status")} for c in compliance[:10]],
            }
            steps.append(step_result("Check policy compliance", "success", {"count": len(compliance)}))
        except Exception as e:
            steps.append(step_result("Check policy compliance", "failed", error=str(e)))

    # Check analytics insights
    if insights_client:
        try:
            analytics = extract_results(insights_client.list_analytics_insights())
            posture["analytics"] = {
                "count": len(analytics),
                "insights": [{"id": a.get("id"), "status": a.get("status")} for a in analytics[:10]],
            }
            steps.append(step_result("Check policy analytics", "success", {"count": len(analytics)}))
        except Exception as e:
            steps.append(step_result("Check policy analytics", "failed", error=str(e)))

    return intent_response(
        status="success",
        summary=f"Security posture assessed: {posture.get('policies', {}).get('count', 0)} policies, "
        f"{posture.get('compliance', {}).get('count', 0)} compliance findings",
        steps=steps,
        result=posture,
        next_actions=["Use investigate_threat() for active threat details", "Review compliance findings and remediate"],
    )


# ==================== Reporting Tools ====================


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": True})
def get_ip_utilization(scope: str | None = None) -> dict:
    """
    Get IP address utilization percentages for capacity planning.
    USE THIS to find overutilized subnets and plan expansions.
    For hierarchy browsing use explore_network(). For infrastructure health use check_infrastructure_health().

    Args:
        scope: Optional IP space name to focus on. If not set, shows all.

    Returns:
        Utilization report with percentages per space/block/subnet

    Examples:
        - get_ip_utilization() → all spaces
        - get_ip_utilization(scope="production") → production space only
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    steps = []
    warnings = []
    utilization = {"spaces": [], "high_utilization": []}

    try:
        space_filter = f'name~"{sanitize_filter(scope)}"' if scope else None
        spaces = extract_results(client.list_ip_spaces(filter=space_filter))

        for space in spaces:
            space_id = space.get("id", "")
            space_name = space.get("name", "")
            space_util = space.get("utilization", {})

            space_data = {"name": space_name, "utilization": space_util, "subnets": []}

            # Get subnets for this space
            try:
                subnets = extract_results(
                    client.list_subnets(filter=f'space=="{space_id}"' if space_id else None, limit=100)
                )
                for s in subnets:
                    subnet_util = s.get("utilization", {})
                    subnet_data = {
                        "address": s.get("address", ""),
                        "cidr": s.get("cidr", 0),
                        "name": s.get("comment", ""),
                        "utilization": subnet_util,
                    }
                    space_data["subnets"].append(subnet_data)

                    # Flag high utilization
                    util_pct = subnet_util.get("utilization", 0) if isinstance(subnet_util, dict) else 0
                    if isinstance(util_pct, (int, float)) and util_pct > 80:
                        utilization["high_utilization"].append(
                            {"space": space_name, "subnet": s.get("address"), "utilization_pct": util_pct}
                        )
            except Exception as e:
                warnings.append(f"Subnet utilization lookup failed for space '{space_name}': {e}")

            utilization["spaces"].append(space_data)

        steps.append(
            step_result(
                "Gather utilization data",
                "success",
                {"spaces": len(utilization["spaces"]), "high_utilization_count": len(utilization["high_utilization"])},
            )
        )

    except Exception as e:
        return intent_response("failed", f"Failed to get utilization: {e}", steps)

    high_count = len(utilization["high_utilization"])
    if high_count > 0:
        warnings.append(f"{high_count} subnet(s) above 80% utilization — consider expanding")

    return intent_response(
        status="success",
        summary=f"Utilization report: {len(utilization['spaces'])} space(s), {high_count} high-utilization subnet(s)",
        steps=steps,
        result=utilization,
        warnings=warnings,
        next_actions=[
            "Use provision_network() to allocate new subnets"
            if high_count > 0
            else "Utilization healthy — no action needed",
            "Use explore_network(depth='full') for detailed hierarchy",
        ],
    )


# ==================== IPAM Management Tools ====================


@mcp.tool(annotations={"destructiveHint": True, "idempotentHint": False})
def manage_network(
    resource_type: Literal["ip_space", "address_block", "subnet", "range"],
    action: Literal[
        "create", "update", "delete", "get", "list", "next_available_subnet", "next_available_address_block"
    ],
    name: str | None = None,
    address: str | None = None,
    space: str | None = None,
    start: str | None = None,
    end: str | None = None,
    resource_id: str | None = None,
    cidr: int | None = None,
    count: int | None = None,
    comment: str | None = None,
    tags: dict[str, Any] | None = None,
    dry_run: bool = True,
) -> dict:
    """
    Manage IPAM network resources: create, update, delete, get, list, and allocate next-available subnets/blocks.
    USE THIS for IPAM CRUD operations. For IP reservations use manage_ip_reservation(). For utilization use get_ip_utilization().

    IMPORTANT: Delete runs in dry_run mode by default — shows impact without deleting.
    next_available_subnet and next_available_address_block require resource_type="address_block" + resource_id + cidr.

    Args:
        resource_type: Type of IPAM network resource to manage
        action: Operation to perform
        name: Resource name (for create or lookup)
        address: CIDR notation for subnets/blocks (e.g., "10.20.0.0/16"), or IP for ranges
        space: IP space name or ID (required for create)
        start: Start IP for ranges
        end: End IP for ranges
        resource_id: Resource ID for get/update/delete/next_available_*
        cidr: CIDR prefix length for next_available_subnet/next_available_address_block (e.g., 24)
        count: Number of resources to allocate (default 1) for next_available_* actions
        comment: Description
        tags: Optional tags dict
        dry_run: If True (default), delete shows impact only. Set False to execute.

    Returns:
        Operation result with resource details

    Examples:
        - manage_network(resource_type="subnet", action="create", address="10.20.3.0/24", space="prod", comment="Web servers")
        - manage_network(resource_type="subnet", action="get", resource_id="ipam/subnet/abc123")
        - manage_network(resource_type="range", action="create", start="10.20.3.100", end="10.20.3.200", space="prod")
        - manage_network(resource_type="address_block", action="delete", resource_id="ipam/address_block/xyz", dry_run=False)
        - manage_network(resource_type="address_block", action="next_available_subnet", resource_id="ipam/address_block/xyz", cidr=24)
        - manage_network(resource_type="address_block", action="next_available_address_block", resource_id="ipam/address_block/xyz", cidr=20)
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    valid, err = validate_resource_type(resource_type, ["ip_space", "address_block", "subnet", "range"])
    if not valid:
        return intent_response("failed", err)

    valid, err = validate_action(
        action, ["create", "update", "delete", "get", "list", "next_available_subnet", "next_available_address_block"]
    )
    if not valid:
        return intent_response("failed", err)

    # next_available_* only for address_block
    if action in ("next_available_subnet", "next_available_address_block") and resource_type != "address_block":
        return intent_response("failed", f"'{action}' is only supported for address_block, not {resource_type}.")

    steps = []

    # Resolve space if needed for create or list
    space_id = None
    if space and action in ("create", "list"):
        space_id, s, err = resolve_space(space)
        if s:
            steps.append(s)
        if err:
            return intent_response("failed", f"Cannot resolve IP space: {err}", steps)

    # Validate address for create
    if action == "create" and address and resource_type in ("subnet", "address_block"):
        valid, err = validate_cidr(address)
        if not valid:
            return intent_response("failed", err)

    try:
        if action == "list":
            filters = []
            if space_id:
                filters.append(f'space=="{space_id}"')
            if name:
                filters.append(f'name~"{sanitize_filter(name)}"')
            if address:
                filters.append(f'address~"{sanitize_filter(address)}"')
            filter_str = " and ".join(filters) if filters else None

            if resource_type == "subnet":
                resp = client.list_subnets(filter=filter_str, limit=100)
                items = extract_results(resp)
                result = [
                    {
                        "id": s.get("id"),
                        "address": s.get("address"),
                        "cidr": s.get("cidr"),
                        "name": s.get("name", s.get("comment", "")),
                        "space": s.get("space"),
                        "utilization": s.get("utilization", {}),
                    }
                    for s in items
                ]
            elif resource_type == "address_block":
                resp = client.list_address_blocks(filter=filter_str, limit=100)
                items = extract_results(resp)
                result = [
                    {
                        "id": b.get("id"),
                        "address": b.get("address"),
                        "cidr": b.get("cidr"),
                        "name": b.get("name", b.get("comment", "")),
                        "space": b.get("space"),
                    }
                    for b in items
                ]
            elif resource_type == "range":
                resp = client.list_ranges(filter=filter_str, limit=100)
                items = extract_results(resp)
                result = [
                    {
                        "id": r.get("id"),
                        "start": r.get("start"),
                        "end": r.get("end"),
                        "space": r.get("space"),
                        "comment": r.get("comment", ""),
                    }
                    for r in items
                ]
            elif resource_type == "ip_space":
                resp = client.list_ip_spaces(filter=filter_str, limit=100)
                items = extract_results(resp)
                result = [
                    {
                        "id": s.get("id"),
                        "name": s.get("name"),
                        "comment": s.get("comment", ""),
                        "utilization": s.get("utilization", {}),
                    }
                    for s in items
                ]
            else:
                items = []
                result = []

            steps.append(step_result(f"List {resource_type}s", "success", {"count": len(items)}))
            return intent_response("success", f"Found {len(items)} {resource_type}(s)", steps, result=result)

        elif action == "create":
            if resource_type == "subnet":
                if not address or not space_id:
                    return intent_response("failed", "Subnet create requires 'address' (CIDR) and 'space'.", steps)
                # Parse CIDR
                network = ipaddress.ip_network(address, strict=False)
                kwargs = {}
                if comment:
                    kwargs["comment"] = comment
                if tags:
                    kwargs["tags"] = tags
                resp = client.create_subnet(
                    address=str(network.network_address),
                    space=space_id,
                    comment=comment,
                    cidr=network.prefixlen,
                    **{k: v for k, v in kwargs.items() if k not in ("comment",)},
                )
                result = resp.get("result", resp)
                steps.append(step_result("Create subnet", "success", {"id": result.get("id"), "address": address}))
                return intent_response("success", f"Subnet {address} created in space '{space}'", steps, result=result)

            elif resource_type == "address_block":
                if not address or not space_id:
                    return intent_response(
                        "failed", "Address block create requires 'address' (CIDR) and 'space'.", steps
                    )
                network = ipaddress.ip_network(address, strict=False)
                resp = client.create_address_block(
                    address=str(network.network_address), space=space_id, comment=comment, cidr=network.prefixlen
                )
                result = resp.get("result", resp)
                steps.append(
                    step_result("Create address block", "success", {"id": result.get("id"), "address": address})
                )
                return intent_response("success", f"Address block {address} created", steps, result=result)

            elif resource_type == "range":
                if not start or not end or not space_id:
                    return intent_response("failed", "Range create requires 'start', 'end', and 'space'.", steps)
                resp = client.create_range(start=start, end=end, space=space_id, comment=comment)
                result = resp.get("result", resp)
                steps.append(
                    step_result("Create range", "success", {"id": result.get("id"), "start": start, "end": end})
                )
                return intent_response("success", f"IP range {start}-{end} created", steps, result=result)

            elif resource_type == "ip_space":
                return intent_response("failed", "IP space creation is not supported via API. Use the Infoblox Portal.")

        elif action == "get":
            if not resource_id:
                return intent_response("failed", "Get requires 'resource_id'.", steps)
            if resource_type == "subnet":
                resp = client.get_subnet(resource_id)
            elif resource_type == "address_block":
                resp = client.get_address_block(resource_id)
            elif resource_type == "range":
                resp = client.get_range(resource_id)
            else:
                return intent_response("failed", f"Get not supported for '{resource_type}'.")
            result = resp.get("result", resp)
            steps.append(step_result(f"Get {resource_type}", "success", {"id": resource_id}))
            return intent_response("success", f"Retrieved {resource_type}", steps, result=result)

        elif action == "update":
            if not resource_id:
                return intent_response("failed", "Update requires 'resource_id'.", steps)
            updates = {}
            if comment is not None:
                updates["comment"] = comment
            if tags is not None:
                updates["tags"] = tags
            if name is not None:
                updates["name"] = name
            if not updates:
                return intent_response("failed", "No update fields provided. Set comment, name, or tags.", steps)

            if resource_type == "subnet":
                resp = client.update_subnet(resource_id, updates)
            elif resource_type == "address_block":
                resp = client.update_address_block(resource_id, updates)
            elif resource_type == "range":
                resp = client.update_range(resource_id, updates)
            else:
                return intent_response("failed", f"Update not supported for '{resource_type}'.")
            result = resp.get("result", resp)
            steps.append(step_result(f"Update {resource_type}", "success", {"id": resource_id, "updates": updates}))
            return intent_response("success", f"Updated {resource_type} {resource_id}", steps, result=result)

        elif action == "delete":
            if not resource_id:
                return intent_response("failed", "Delete requires 'resource_id'.", steps)

            if dry_run:
                # Show what would be affected
                try:
                    if resource_type == "subnet":
                        resp = client.get_subnet(resource_id)
                    elif resource_type == "address_block":
                        resp = client.get_address_block(resource_id)
                    elif resource_type == "range":
                        resp = client.get_range(resource_id)
                    else:
                        resp = {}
                    result = resp.get("result", resp)
                    steps.append(step_result(f"Dry run: inspect {resource_type}", "success", result))
                except Exception as e:
                    steps.append(step_result(f"Dry run: inspect {resource_type}", "failed", error=str(e)))
                return intent_response(
                    "success",
                    f"DRY RUN: Would delete {resource_type} {resource_id}",
                    steps,
                    result={"resource_id": resource_id, "resource_type": resource_type},
                    warnings=["This is a DRY RUN. Set dry_run=False to actually delete."],
                    next_actions=[
                        f"Execute: manage_network(resource_type='{resource_type}', action='delete', resource_id='{resource_id}', dry_run=False)"
                    ],
                )

            if resource_type == "subnet":
                client.delete_subnet(resource_id)
            elif resource_type == "address_block":
                client.delete_address_block(resource_id)
            elif resource_type == "range":
                client.delete_range(resource_id)
            else:
                return intent_response("failed", f"Delete not supported for '{resource_type}'.")
            steps.append(step_result(f"Delete {resource_type}", "success", {"id": resource_id}))
            return intent_response("success", f"Deleted {resource_type} {resource_id}", steps)

        elif action == "next_available_subnet":
            if not resource_id or cidr is None:
                return intent_response(
                    "failed",
                    "next_available_subnet requires 'resource_id' (parent address block) and 'cidr' (prefix length).",
                    steps,
                )
            resp = client.allocate_next_available_subnet(
                block_id=resource_id, cidr=cidr, count=count or 1, comment=comment
            )
            result = resp.get("result", resp)
            steps.append(step_result("Allocate next subnet", "success", {"cidr": cidr, "count": count or 1}))
            return intent_response("success", f"Allocated /{cidr} subnet from {resource_id}", steps, result=result)

        elif action == "next_available_address_block":
            if not resource_id or cidr is None:
                return intent_response(
                    "failed",
                    "next_available_address_block requires 'resource_id' (parent address block) and 'cidr' (prefix length).",
                    steps,
                )
            resp = client.allocate_next_available_address_block(
                block_id=resource_id, cidr=cidr, count=count or 1, comment=comment
            )
            result = resp.get("result", resp)
            steps.append(step_result("Allocate next address block", "success", {"cidr": cidr, "count": count or 1}))
            return intent_response(
                "success", f"Allocated /{cidr} address block from {resource_id}", steps, result=result
            )

    except Exception as e:
        return intent_response("failed", f"Failed to {action} {resource_type}: {e}", steps)


# ==================== DNS Configuration Tools ====================


@mcp.tool(annotations={"destructiveHint": True, "idempotentHint": False})
def manage_dns_zone(
    action: Literal["create", "update", "delete", "list", "get", "sign", "unsign", "dnssec_status", "reorder"],
    resource_type: Literal["auth_zone", "forward_zone", "dns_view", "rpz", "delegation"] = "auth_zone",
    fqdn: str | None = None,
    name: str | None = None,
    primary_type: str | None = None,
    view: str | None = None,
    forward_to: list[str] | None = None,
    delegation_servers: list[dict[str, Any]] | None = None,
    zone_ids: list[str] | None = None,
    disabled: bool | None = None,
    comment: str | None = None,
    resource_id: str | None = None,
    dry_run: bool = True,
) -> dict:
    """
    Manage DNS zones, views, RPZ, and delegations: create, update, delete, list, get, sign, unsign, check DNSSEC status, reorder.
    USE THIS for zone lifecycle operations. For DNS record CRUD use manage_dns_record(). For record creation use provision_dns().

    Quick routing guide:
    - Authoritative zones: resource_type="auth_zone" (default) → create, list, get, delete, sign, unsign, dnssec_status
    - Forward zones: resource_type="forward_zone" → create, list
    - DNS views: resource_type="dns_view" → create, list, get, update, delete
    - RPZ (Response Policy Zones): resource_type="rpz" → create, list, get, update, delete, reorder
    - Delegations: resource_type="delegation" → create, list, get, update, delete

    IMPORTANT: Delete runs in dry_run mode by default. sign/unsign/dnssec_status only work with auth_zone. reorder only works with rpz.

    Args:
        action: Operation to perform
        resource_type: DNS resource type to manage
        fqdn: Zone FQDN for create/delete (e.g., "example.com")
        name: Name for dns_view create, or RPZ zone name
        primary_type: For auth/rpz zones — "cloud" or "external"
        view: DNS view name (optional)
        forward_to: List of forwarder IPs for forward zones
        delegation_servers: List of delegation server objects for delegation create
        zone_ids: List of zone IDs for sign/unsign/reorder operations
        disabled: Set zone disabled state (for update)
        comment: Description
        resource_id: Resource ID for get/update/delete/dnssec_status
        dry_run: If True (default), delete shows record count only. Set False to execute.

    Returns:
        Zone operation result

    Examples:
        - manage_dns_zone(action="list") → all authoritative zones
        - manage_dns_zone(action="list", resource_type="forward_zone") → all forward zones
        - manage_dns_zone(action="list", resource_type="dns_view") → all DNS views
        - manage_dns_zone(action="list", resource_type="rpz") → all RPZ zones
        - manage_dns_zone(action="list", resource_type="delegation") → all delegations
        - manage_dns_zone(action="create", fqdn="new.example.com", primary_type="cloud")
        - manage_dns_zone(action="create", resource_type="dns_view", name="my-view")
        - manage_dns_zone(action="sign", resource_type="auth_zone", zone_ids=["dns/auth_zone/abc"])
        - manage_dns_zone(action="dnssec_status", resource_type="auth_zone", resource_id="dns/auth_zone/abc")
        - manage_dns_zone(action="reorder", resource_type="rpz", zone_ids=["id1", "id2"])
        - manage_dns_zone(action="delete", fqdn="old.example.com", dry_run=False)
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    valid, err = validate_resource_type(resource_type, ["auth_zone", "forward_zone", "dns_view", "rpz", "delegation"])
    if not valid:
        return intent_response("failed", err)

    # Action constraints per resource type
    if action in ("sign", "unsign", "dnssec_status") and resource_type != "auth_zone":
        return intent_response("failed", f"'{action}' is only supported for auth_zone, not {resource_type}.")
    if action == "reorder" and resource_type != "rpz":
        return intent_response("failed", "'reorder' is only supported for rpz.")

    all_actions = ["create", "update", "delete", "list", "get", "sign", "unsign", "dnssec_status", "reorder"]
    valid, err = validate_action(action, all_actions)
    if not valid:
        return intent_response("failed", err)

    steps = []

    # Dispatch table for list/get/delete/update
    dispatch = {
        "auth_zone": {
            "list": lambda: client.list_auth_zones(limit=200),
            "get": lambda rid: client.list_auth_zones(limit=200),  # placeholder, handled below
            "delete": lambda rid: None,  # handled in delete logic
            "update": lambda rid, u: None,  # auth zones don't have generic update in original
        },
        "forward_zone": {
            "list": lambda: client.list_forward_zones(limit=200),
        },
        "dns_view": {
            "list": lambda: client.list_dns_views(limit=200),
            "get": lambda rid: client.get_dns_view(rid),
            "delete": lambda rid: client.delete_dns_view(rid),
            "update": lambda rid, u: client.update_dns_view(rid, u),
        },
        "rpz": {
            "list": lambda: client.list_rpz_zones(limit=200),
            "get": lambda rid: client.get_rpz_zone(rid),
            "delete": lambda rid: client.delete_rpz_zone(rid),
            "update": lambda rid, u: client.update_rpz_zone(rid, u),
        },
        "delegation": {
            "list": lambda: client.list_dns_delegations(limit=200),
            "get": lambda rid: client.get_dns_delegation(rid),
            "delete": lambda rid: client.delete_dns_delegation(rid),
            "update": lambda rid, u: client.update_dns_delegation(rid, u),
        },
    }

    try:
        if action == "list":
            resp = dispatch[resource_type]["list"]()
            items = extract_results(resp)

            if resource_type == "auth_zone":
                result = [
                    {
                        "id": z.get("id"),
                        "fqdn": z.get("fqdn"),
                        "primary_type": z.get("primary_type", ""),
                        "view": z.get("view"),
                        "comment": z.get("comment", ""),
                    }
                    for z in items
                ]
            elif resource_type == "forward_zone":
                result = [
                    {
                        "id": z.get("id"),
                        "fqdn": z.get("fqdn"),
                        "forward_only": z.get("forward_only"),
                        "comment": z.get("comment", ""),
                    }
                    for z in items
                ]
            elif resource_type == "dns_view":
                result = [
                    {
                        "id": v.get("id"),
                        "name": v.get("name"),
                        "comment": v.get("comment", ""),
                    }
                    for v in items
                ]
            elif resource_type == "rpz":
                result = [
                    {
                        "id": z.get("id"),
                        "fqdn": z.get("fqdn"),
                        "primary_type": z.get("primary_type", ""),
                        "view": z.get("view"),
                        "comment": z.get("comment", ""),
                    }
                    for z in items
                ]
            elif resource_type == "delegation":
                result = [
                    {
                        "id": d.get("id"),
                        "fqdn": d.get("fqdn"),
                        "view": d.get("view"),
                        "comment": d.get("comment", ""),
                    }
                    for d in items
                ]
            else:
                result = []

            steps.append(step_result(f"List {resource_type}s", "success", {"count": len(items)}))
            return intent_response("success", f"Found {len(items)} {resource_type}(s)", steps, result=result)

        elif action == "get":
            if not resource_id and not fqdn:
                return intent_response("failed", "Get requires 'resource_id' or 'fqdn'.", steps)

            if resource_type in ("auth_zone", "forward_zone"):
                # Auth/forward zone get: resolve by fqdn or return zone info
                if fqdn and not resource_id:
                    zone_id, s, err = resolve_zone(fqdn, view)
                    if s:
                        steps.append(s)
                    if err:
                        return intent_response("failed", err, steps)
                    resource_id = zone_id
                # List DNS views as bonus info
                views_resp = client.list_dns_views(limit=50)
                views = extract_results(views_resp)
                steps.append(step_result("List DNS views", "success", {"count": len(views)}))
                return intent_response(
                    "success",
                    f"Zone resolved: {resource_id}",
                    steps,
                    result={
                        "zone_id": resource_id,
                        "dns_views": [{"id": v.get("id"), "name": v.get("name")} for v in views],
                    },
                )
            else:
                if not resource_id:
                    return intent_response("failed", "Get requires 'resource_id'.", steps)
                resp = dispatch[resource_type]["get"](resource_id)
                result = resp.get("result", resp)
                steps.append(step_result(f"Get {resource_type}", "success", {"id": resource_id}))
                return intent_response("success", f"Retrieved {resource_type}", steps, result=result)

        elif action == "create":
            if resource_type == "dns_view":
                if not name:
                    return intent_response("failed", "DNS view create requires 'name'.", steps)
                resp = client.create_dns_view(name=name, comment=comment)
                result = resp.get("result", resp)
                steps.append(step_result("Create DNS view", "success", {"id": result.get("id"), "name": name}))
                return intent_response("success", f"DNS view '{name}' created", steps, result=result)

            elif resource_type == "delegation":
                if not fqdn:
                    return intent_response("failed", "Delegation create requires 'fqdn'.", steps)
                resp = client.create_dns_delegation(
                    fqdn=fqdn, delegation_servers=delegation_servers, view=view, comment=comment
                )
                result = resp.get("result", resp)
                steps.append(step_result("Create delegation", "success", {"id": result.get("id"), "fqdn": fqdn}))
                return intent_response("success", f"Delegation for '{fqdn}' created", steps, result=result)

            elif resource_type == "rpz":
                if not fqdn and not name:
                    return intent_response("failed", "RPZ create requires 'fqdn' or 'name'.", steps)
                zone_fqdn = fqdn or name
                resp = client.create_rpz_zone(
                    name=zone_fqdn, primary_type=primary_type or "cloud", view=view, comment=comment
                )
                result = resp.get("result", resp)
                steps.append(step_result("Create RPZ zone", "success", {"id": result.get("id"), "fqdn": zone_fqdn}))
                return intent_response("success", f"RPZ zone '{zone_fqdn}' created", steps, result=result)

            else:
                # auth_zone / forward_zone — original create logic
                if not fqdn:
                    return intent_response("failed", "Create requires 'fqdn'.", steps)
                valid, err = validate_fqdn(fqdn)
                if not valid:
                    return intent_response("failed", err)

                # Check if zone already exists
                existing = extract_results(client.list_auth_zones(filter=f'fqdn=="{sanitize_filter(fqdn)}"'))
                if not existing:
                    existing = extract_results(client.list_auth_zones(filter=f'fqdn=="{sanitize_filter(fqdn)}."'))
                if existing:
                    return intent_response(
                        "failed", f"Zone '{fqdn}' already exists (ID: {existing[0].get('id')})", steps
                    )

                if resource_type == "auth_zone":
                    kwargs = {}
                    if view:
                        kwargs["view"] = view
                    resp = client.create_auth_zone(
                        fqdn=fqdn, primary_type=primary_type or "cloud", comment=comment, **kwargs
                    )
                    result = resp.get("result", resp)
                    steps.append(step_result("Create auth zone", "success", {"id": result.get("id"), "fqdn": fqdn}))
                    return intent_response("success", f"Authoritative zone '{fqdn}' created", steps, result=result)
                else:
                    resp = client.create_forward_zone(
                        fqdn=fqdn, forward_only=True, hosts=forward_to, view=view, comment=comment
                    )
                    result = resp.get("result", resp)
                    steps.append(step_result("Create forward zone", "success", {"id": result.get("id"), "fqdn": fqdn}))
                    return intent_response("success", f"Forward zone '{fqdn}' created", steps, result=result)

        elif action == "update":
            if not resource_id:
                return intent_response("failed", "Update requires 'resource_id'.", steps)
            if resource_type not in dispatch or "update" not in dispatch[resource_type]:
                return intent_response("failed", f"Update not supported for '{resource_type}'.", steps)
            updates = {}
            if comment is not None:
                updates["comment"] = comment
            if name is not None:
                updates["name"] = name
            if disabled is not None:
                updates["disabled"] = disabled
            if not updates:
                return intent_response("failed", "No update fields provided. Set comment, name, or disabled.", steps)
            resp = dispatch[resource_type]["update"](resource_id, updates)
            result = resp.get("result", resp) if resp else {}
            steps.append(step_result(f"Update {resource_type}", "success", {"id": resource_id, "updates": updates}))
            return intent_response("success", f"Updated {resource_type} {resource_id}", steps, result=result)

        elif action == "delete":
            if not resource_id and not fqdn:
                return intent_response("failed", "Delete requires 'resource_id' or 'fqdn'.", steps)
            if fqdn and not resource_id and resource_type in ("auth_zone", "forward_zone"):
                zone_id, s, err = resolve_zone(fqdn, view)
                if s:
                    steps.append(s)
                if err:
                    return intent_response("failed", err, steps)
                resource_id = zone_id

            if not resource_id:
                return intent_response("failed", "Could not resolve resource_id for deletion.", steps)

            # Safety: count records in zone (for auth_zone/forward_zone)
            warnings = []
            if resource_type in ("auth_zone", "forward_zone", "rpz"):
                try:
                    records = extract_results(client.list_dns_records(filter=f'zone=="{resource_id}"', limit=1))
                    record_count = len(records)
                    steps.append(step_result("Count zone records", "success", {"record_count": record_count}))
                    if record_count > 0:
                        warnings = [f"Zone contains {record_count}+ DNS record(s) that will be orphaned"]
                except Exception:
                    warnings = ["Could not verify record count"]

            if dry_run:
                return intent_response(
                    "success",
                    f"DRY RUN: Would delete {resource_type} {fqdn or resource_id}",
                    steps,
                    result={"resource_id": resource_id, "fqdn": fqdn, "resource_type": resource_type},
                    warnings=warnings + ["This is a DRY RUN. Set dry_run=False to actually delete."],
                    next_actions=[
                        f"Execute: manage_dns_zone(action='delete', resource_type='{resource_type}', resource_id='{resource_id}', dry_run=False)"
                    ],
                )

            if resource_type in ("dns_view", "rpz", "delegation") and "delete" in dispatch.get(resource_type, {}):
                dispatch[resource_type]["delete"](resource_id)
                steps.append(step_result(f"Delete {resource_type}", "success", {"id": resource_id}))
                return intent_response("success", f"Deleted {resource_type} {resource_id}", steps)

            # Auth/forward zone deletion
            return intent_response(
                "partial",
                f"Zone deletion for '{fqdn or resource_id}' — use Infoblox Portal for zone removal",
                steps,
                warnings=warnings + ["Zone deletion via API requires specific permissions. Verify in Infoblox Portal."],
            )

        elif action == "sign":
            if not zone_ids:
                return intent_response("failed", "Sign requires 'zone_ids' (list of auth zone IDs).", steps)
            resp = client.sign_auth_zone(zone_ids)
            steps.append(step_result("Sign auth zones", "success", {"zone_ids": zone_ids}))
            return intent_response("success", f"Signed {len(zone_ids)} auth zone(s)", steps, result=resp)

        elif action == "unsign":
            if not zone_ids:
                return intent_response("failed", "Unsign requires 'zone_ids' (list of auth zone IDs).", steps)
            resp = client.unsign_auth_zone(zone_ids)
            steps.append(step_result("Unsign auth zones", "success", {"zone_ids": zone_ids}))
            return intent_response("success", f"Unsigned {len(zone_ids)} auth zone(s)", steps, result=resp)

        elif action == "dnssec_status":
            if not resource_id:
                return intent_response("failed", "dnssec_status requires 'resource_id' (auth zone ID).", steps)
            resp = client.get_dnssec_key_status(resource_id)
            result = resp.get("result", resp)
            steps.append(step_result("Get DNSSEC status", "success", {"zone_id": resource_id}))
            return intent_response("success", f"DNSSEC status for {resource_id}", steps, result=result)

        elif action == "reorder":
            if not zone_ids:
                return intent_response("failed", "Reorder requires 'zone_ids' (ordered list of RPZ zone IDs).", steps)
            resp = client.reorder_rpz_zones(zone_ids)
            steps.append(step_result("Reorder RPZ zones", "success", {"zone_ids": zone_ids}))
            return intent_response("success", f"Reordered {len(zone_ids)} RPZ zone(s)", steps, result=resp)

    except Exception as e:
        return intent_response("failed", f"Failed to {action} {resource_type}: {e}", steps)


@mcp.tool(annotations={"destructiveHint": True, "idempotentHint": False})
def manage_dns_record(
    action: Literal["update", "delete", "list", "get"],
    record_id: str | None = None,
    zone: str | None = None,
    view: str | None = None,
    record_type: Literal["A", "AAAA", "CNAME", "MX", "TXT", "PTR", "SRV", "NS"] | None = None,
    name: str | None = None,
    rdata: dict[str, Any] | None = None,
    ttl: int | None = None,
    comment: str | None = None,
    dry_run: bool = True,
    limit: int = 50,
) -> dict:
    """
    Update, delete, list, or get existing DNS records. Supports smart lookup by name+zone+type.
    USE THIS for record lifecycle after creation. For creating new records use provision_dns().
    For zone management use manage_dns_zone().

    Args:
        action: Operation to perform on the record
        record_id: DNS record ID (optional — can look up by name+zone+type)
        zone: DNS zone FQDN for filtering/lookup
        view: Optional DNS view name or ID. Required when a zone exists in multiple views (e.g., "default", "Azure.private-2")
        record_type: Record type filter — "A", "AAAA", "CNAME", "MX", "TXT", "PTR", "SRV", "NS"
        name: Record name for lookup (e.g., "www" or "www.example.com")
        rdata: New rdata for update (e.g., {"address": "10.0.0.1"} for A record)
        ttl: New TTL for update
        comment: New comment for update
        dry_run: If True (default), delete shows record details only. Set False to execute.
        limit: Max records for list (default: 50)

    Returns:
        Record operation result

    Examples:
        - manage_dns_record(action="list", zone="example.com") → all records in zone
        - manage_dns_record(action="list", zone="example.com", record_type="A") → A records only
        - manage_dns_record(action="get", record_id="dns/record/abc123")
        - manage_dns_record(action="update", record_id="dns/record/abc123", rdata={"address": "10.0.0.2"})
        - manage_dns_record(action="delete", name="old-host", zone="example.com", record_type="A", dry_run=False)
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    valid, err = validate_action(action, ["update", "delete", "list", "get"])
    if not valid:
        return intent_response("failed", err)

    limit = min(limit, 500)
    steps = []

    # Smart record lookup: find record_id from name+zone+type
    def find_record_id():
        nonlocal record_id, steps
        if record_id:
            return record_id
        if not name:
            return None

        filters = []
        if "." in name and not zone:
            filters.append(f'absolute_name_spec=="{sanitize_filter(name)}"')
        elif zone:
            filters.append(f'name_in_zone=="{sanitize_filter(name)}"')
            zone_id, s, err = resolve_zone(zone, view)
            if s:
                steps.append(s)
            if zone_id:
                filters.append(f'zone=="{zone_id}"')

        if record_type:
            filters.append(f'type=="{record_type.upper()}"')

        filter_str = " and ".join(filters) if filters else f'name_in_zone~"{sanitize_filter(name)}"'
        records = extract_results(client.list_dns_records(filter=filter_str, limit=5))
        if records:
            rid = records[0].get("id", "")
            steps.append(step_result("Lookup record", "success", {"id": rid, "matches": len(records)}))
            return rid
        steps.append(step_result("Lookup record", "failed", error=f"No record found for name='{name}'"))
        return None

    try:
        if action == "list":
            filters = []
            zone_id = None
            if zone:
                zone_id, s, err = resolve_zone(zone, view)
                if s:
                    steps.append(s)
                if zone_id:
                    filters.append(f'zone=="{zone_id}"')
            if record_type:
                filters.append(f'type=="{record_type.upper()}"')
            if name:
                filters.append(f'name_in_zone~"{sanitize_filter(name)}"')

            filter_str = " and ".join(filters) if filters else None
            resp = client.list_dns_records(filter=filter_str, limit=limit)
            records = extract_results(resp)
            result = [
                {
                    "id": r.get("id"),
                    "name": r.get("absolute_name_spec", r.get("name_in_zone")),
                    "type": r.get("type"),
                    "rdata": r.get("rdata"),
                    "ttl": r.get("ttl"),
                    "zone": r.get("zone"),
                    "comment": r.get("comment", ""),
                }
                for r in records
            ]
            steps.append(step_result("List DNS records", "success", {"count": len(records)}))
            return intent_response("success", f"Found {len(records)} DNS record(s)", steps, result=result)

        elif action == "get":
            rid = find_record_id()
            if not rid:
                return intent_response("failed", "Record not found. Provide record_id or name+zone+type.", steps)
            resp = client.get_dns_record(rid)
            result = resp.get("result", resp)
            steps.append(step_result("Get DNS record", "success", {"id": rid}))
            return intent_response("success", f"Retrieved DNS record {rid}", steps, result=result)

        elif action == "update":
            rid = find_record_id()
            if not rid:
                return intent_response("failed", "Record not found. Provide record_id or name+zone+type.", steps)
            updates = {}
            if rdata is not None:
                updates["rdata"] = rdata
            if ttl is not None:
                updates["ttl"] = ttl
            if comment is not None:
                updates["comment"] = comment
            if not updates:
                return intent_response("failed", "No update fields provided. Set rdata, ttl, or comment.", steps)

            resp = client.update_dns_record(rid, updates)
            result = resp.get("result", resp)
            steps.append(step_result("Update DNS record", "success", {"id": rid, "updates": list(updates.keys())}))
            return intent_response("success", f"Updated DNS record {rid}", steps, result=result)

        elif action == "delete":
            rid = find_record_id()
            if not rid:
                return intent_response("failed", "Record not found. Provide record_id or name+zone+type.", steps)

            if dry_run:
                try:
                    resp = client.get_dns_record(rid)
                    result = resp.get("result", resp)
                    steps.append(step_result("Dry run: inspect record", "success", result))
                except Exception as e:
                    steps.append(step_result("Dry run: inspect record", "failed", error=str(e)))
                return intent_response(
                    "success",
                    f"DRY RUN: Would delete DNS record {rid}",
                    steps,
                    result={"record_id": rid},
                    warnings=["This is a DRY RUN. Set dry_run=False to actually delete."],
                    next_actions=[f"Execute: manage_dns_record(action='delete', record_id='{rid}', dry_run=False)"],
                )

            client.delete_dns_record(rid)
            steps.append(step_result("Delete DNS record", "success", {"id": rid}))
            return intent_response("success", f"Deleted DNS record {rid}", steps)

    except Exception as e:
        return intent_response("failed", f"Failed to {action} DNS record: {e}", steps)


# ==================== DHCP Management Tools ====================


@mcp.tool(annotations={"destructiveHint": True, "idempotentHint": False})
def manage_dhcp(
    resource_type: Literal["ha_group", "option_code", "hardware_filter", "option_filter", "hardware"],
    action: Literal["create", "update", "delete", "get", "list"],
    name: str | None = None,
    resource_id: str | None = None,
    mode: str | None = None,
    hosts: list[dict[str, Any]] | None = None,
    code: int | None = None,
    option_type: str | None = None,
    protocol: str | None = None,
    mac_address: str | None = None,
    comment: str | None = None,
    dry_run: bool = True,
) -> dict:
    """
    Manage DHCP configuration: HA groups, option codes, hardware filters, option filters, and hardware entries.
    USE THIS for DHCP-specific CRUD. For IP reservations use manage_ip_reservation(). For network topology use manage_network().

    Args:
        resource_type: Type of DHCP resource to manage
        action: Operation to perform
        name: Resource name
        resource_id: Resource ID for get/update/delete
        mode: HA group mode (e.g., "active-active", "active-passive") — for ha_group create
        hosts: HA group hosts list — for ha_group create
        code: DHCP option code number — for option_code create
        option_type: Option code type (e.g., "string", "uint8") — for option_code create
        protocol: Protocol for hardware filters (e.g., "dhcpv4") — for hardware_filter create
        mac_address: MAC address — for hardware create
        comment: Description
        dry_run: If True (default), delete shows resource only. Set False to execute.

    Returns:
        DHCP operation result

    Examples:
        - manage_dhcp(resource_type="ha_group", action="list")
        - manage_dhcp(resource_type="option_code", action="list")
        - manage_dhcp(resource_type="ha_group", action="create", name="dc1-ha", mode="active-active", hosts=[...])
        - manage_dhcp(resource_type="hardware", action="create", mac_address="AA:BB:CC:DD:EE:FF", name="server-01")
        - manage_dhcp(resource_type="option_code", action="delete", resource_id="dhcp/option_code/123", dry_run=False)
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    valid, err = validate_resource_type(
        resource_type, ["ha_group", "option_code", "hardware_filter", "option_filter", "hardware"]
    )
    if not valid:
        return intent_response("failed", err)

    valid, err = validate_action(action, ["create", "update", "delete", "get", "list"])
    if not valid:
        return intent_response("failed", err)

    steps = []

    # Dispatch table for list/get/delete/update/create
    dispatch = {
        "ha_group": {
            "list": lambda: client.list_ha_groups(limit=100),
            "get": lambda rid: client.get_ha_group(rid),
            "delete": lambda rid: client.delete_ha_group(rid),
            "update": lambda rid, u: client.update_ha_group(rid, u),
        },
        "option_code": {
            "list": lambda: client.list_option_codes(limit=200),
            "get": lambda rid: client.get_option_code(rid),
            "delete": lambda rid: client.delete_option_code(rid),
            "update": lambda rid, u: client.update_option_code(rid, u),
        },
        "hardware_filter": {
            "list": lambda: client.list_hardware_filters(limit=100),
            "get": lambda rid: client.get_hardware_filter(rid),
            "delete": lambda rid: client.delete_hardware_filter(rid),
            "update": lambda rid, u: client.update_hardware_filter(rid, u),
        },
        "option_filter": {
            "list": lambda: client.list_option_filters(limit=100),
            "get": lambda rid: client.get_option_filter(rid),
            "delete": lambda rid: client.delete_option_filter(rid),
            "update": lambda rid, u: client.update_option_filter(rid, u),
        },
        "hardware": {
            "list": lambda: client.list_hardware(limit=100),
            "get": lambda rid: client.get_hardware(rid),
            "delete": lambda rid: client.delete_hardware(rid),
            "update": lambda rid, u: client.update_hardware(rid, u),
        },
    }

    try:
        if action == "list":
            resp = dispatch[resource_type]["list"]()
            items = extract_results(resp)
            result = []
            for item in items:
                entry = {"id": item.get("id"), "name": item.get("name", "")}
                if resource_type == "ha_group":
                    entry["mode"] = item.get("mode", "")
                elif resource_type == "option_code":
                    entry["code"] = item.get("code")
                    entry["type"] = item.get("type", "")
                elif resource_type == "hardware":
                    entry["address"] = item.get("address", "")
                entry["comment"] = item.get("comment", "")
                result.append(entry)
            steps.append(step_result(f"List {resource_type}s", "success", {"count": len(items)}))
            return intent_response("success", f"Found {len(items)} {resource_type}(s)", steps, result=result)

        elif action == "get":
            if not resource_id:
                # Try name lookup
                if name:
                    resp = dispatch[resource_type]["list"]()
                    items = extract_results(resp)
                    matches = [i for i in items if i.get("name", "").lower() == name.lower()]
                    if not matches:
                        matches = [i for i in items if name.lower() in i.get("name", "").lower()]
                    if matches:
                        resource_id = matches[0].get("id")
                        steps.append(step_result(f"Resolve {resource_type} name", "success", {"id": resource_id}))
                    else:
                        return intent_response("failed", f"No {resource_type} found with name '{name}'", steps)
                else:
                    return intent_response("failed", "Get requires 'resource_id' or 'name'.", steps)
            resp = dispatch[resource_type]["get"](resource_id)
            result = resp.get("result", resp)
            steps.append(step_result(f"Get {resource_type}", "success", {"id": resource_id}))
            return intent_response("success", f"Retrieved {resource_type}", steps, result=result)

        elif action == "create":
            if resource_type == "ha_group":
                if not name or not mode:
                    return intent_response("failed", "HA group create requires 'name' and 'mode'.", steps)
                resp = client.create_ha_group(name=name, mode=mode, hosts=hosts or [], comment=comment)
            elif resource_type == "option_code":
                if not name or code is None or not option_type:
                    return intent_response(
                        "failed", "Option code create requires 'name', 'code', and 'option_type'.", steps
                    )
                resp = client.create_option_code(code=code, name=name, type=option_type, comment=comment)
            elif resource_type == "hardware_filter":
                if not name:
                    return intent_response("failed", "Hardware filter create requires 'name'.", steps)
                resp = client.create_hardware_filter(name=name, protocol=protocol or "dhcpv4", comment=comment)
            elif resource_type == "option_filter":
                if not name:
                    return intent_response("failed", "Option filter create requires 'name'.", steps)
                resp = client.create_option_filter(name=name, comment=comment)
            elif resource_type == "hardware":
                if not mac_address:
                    return intent_response("failed", "Hardware create requires 'mac_address'.", steps)
                valid_mac, mac_err = validate_mac(mac_address)
                if not valid_mac:
                    return intent_response("failed", mac_err)
                resp = client.create_hardware(address=mac_address, name=name, comment=comment)

            result = resp.get("result", resp)
            steps.append(step_result(f"Create {resource_type}", "success", {"id": result.get("id")}))
            return intent_response("success", f"Created {resource_type} '{name or mac_address}'", steps, result=result)

        elif action == "update":
            if not resource_id:
                return intent_response("failed", "Update requires 'resource_id'.", steps)
            updates = {}
            if comment is not None:
                updates["comment"] = comment
            if name is not None:
                updates["name"] = name
            if mode is not None:
                updates["mode"] = mode
            if not updates:
                return intent_response("failed", "No update fields provided.", steps)
            resp = dispatch[resource_type]["update"](resource_id, updates)
            result = resp.get("result", resp)
            steps.append(step_result(f"Update {resource_type}", "success", {"id": resource_id}))
            return intent_response("success", f"Updated {resource_type} {resource_id}", steps, result=result)

        elif action == "delete":
            if not resource_id:
                return intent_response("failed", "Delete requires 'resource_id'.", steps)
            if dry_run:
                try:
                    resp = dispatch[resource_type]["get"](resource_id)
                    result = resp.get("result", resp)
                    steps.append(step_result(f"Dry run: inspect {resource_type}", "success", result))
                except Exception as e:
                    steps.append(step_result(f"Dry run: inspect {resource_type}", "failed", error=str(e)))
                return intent_response(
                    "success",
                    f"DRY RUN: Would delete {resource_type} {resource_id}",
                    steps,
                    result={"resource_id": resource_id, "resource_type": resource_type},
                    warnings=["This is a DRY RUN. Set dry_run=False to actually delete."],
                    next_actions=[
                        f"Execute: manage_dhcp(resource_type='{resource_type}', action='delete', resource_id='{resource_id}', dry_run=False)"
                    ],
                )
            dispatch[resource_type]["delete"](resource_id)
            steps.append(step_result(f"Delete {resource_type}", "success", {"id": resource_id}))
            return intent_response("success", f"Deleted {resource_type} {resource_id}", steps)

    except Exception as e:
        return intent_response("failed", f"Failed to {action} {resource_type}: {e}", steps)


@mcp.tool(annotations={"destructiveHint": True, "idempotentHint": False})
def manage_dhcp_lease(
    action: Literal["list", "get", "clear", "resend_ddns"],
    address: str | None = None,
    mac_address: str | None = None,
    hostname: str | None = None,
    state: str | None = None,
    space: str | None = None,
    resource_id: str | None = None,
    dry_run: bool = True,
    limit: int = 100,
) -> dict:
    """
    Manage DHCP leases: list/search active leases, wipe leases, or resend DDNS updates.
    USE THIS for DHCP lease visibility and maintenance. For DHCP configuration use manage_dhcp().

    IMPORTANT: "clear" permanently removes leases. Runs in dry_run mode by default for clear/resend_ddns.
    Set dry_run=False to actually execute destructive actions.

    Args:
        action: Operation — list, get, clear (wipe lease), or resend_ddns
        address: IP address to filter/target
        mac_address: MAC address to filter (for list)
        hostname: Hostname to filter (for list)
        state: Lease state filter (e.g., "issued", "used")
        space: IP space name or ID (required for clear/resend_ddns to resolve address)
        resource_id: Lease resource ID for get
        dry_run: If True (default), clear/resend_ddns show what would happen. Set to False to execute.
        limit: Max results for list (default 100)

    Returns:
        Lease operation result

    Examples:
        - manage_dhcp_lease(action="list") → all active leases
        - manage_dhcp_lease(action="list", mac_address="AA:BB:CC:DD:EE:FF")
        - manage_dhcp_lease(action="get", resource_id="dhcp/lease/abc123")
        - manage_dhcp_lease(action="clear", address="10.0.0.50", space="prod")
        - manage_dhcp_lease(action="resend_ddns", address="10.0.0.50", space="prod")
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    valid, err = validate_action(action, ["list", "get", "clear", "resend_ddns"])
    if not valid:
        return intent_response("failed", err)

    steps = []

    try:
        if action == "list":
            filters = []
            if address:
                filters.append(f'address=="{sanitize_filter(address)}"')
            if mac_address:
                filters.append(f'hardware=="{sanitize_filter(mac_address)}"')
            if hostname:
                filters.append(f'hostname~"{sanitize_filter(hostname)}"')
            if state:
                filters.append(f'state=="{sanitize_filter(state)}"')
            filter_str = " and ".join(filters) if filters else None
            resp = client.list_dhcp_leases(filter=filter_str, limit=limit)
            leases = extract_results(resp)
            result = [
                {
                    "id": le.get("id"),
                    "address": le.get("address"),
                    "hardware": le.get("hardware", ""),
                    "hostname": le.get("hostname", ""),
                    "state": le.get("state", ""),
                    "starts": le.get("starts", ""),
                    "ends": le.get("ends", ""),
                    "space": le.get("space", ""),
                }
                for le in leases
            ]
            steps.append(step_result("List DHCP leases", "success", {"count": len(leases)}))
            return intent_response("success", f"Found {len(leases)} lease(s)", steps, result=result)

        elif action == "get":
            if not resource_id:
                return intent_response("failed", "Get requires 'resource_id'.", steps)
            resp = client.get_dhcp_lease(resource_id)
            result = resp.get("result", resp)
            steps.append(step_result("Get DHCP lease", "success", {"id": resource_id}))
            return intent_response("success", "Retrieved DHCP lease", steps, result=result)

        elif action in ("clear", "resend_ddns"):
            if not address:
                return intent_response("failed", f"'{action}' requires 'address'.", steps)
            if not space:
                return intent_response("failed", f"'{action}' requires 'space' (IP space name or ID).", steps)

            # Resolve space
            space_id, s, err = resolve_space(space)
            if s:
                steps.append(s)
            if err:
                return intent_response("failed", f"Cannot resolve IP space: {err}", steps)

            command = "clear" if action == "clear" else "resend-ddns"

            if dry_run:
                plan = {"command": command, "address": address, "space": space, "space_id": space_id}
                steps.append(step_result("Dry run analysis", "success", {"plan": plan}))
                verb = "clear" if action == "clear" else "resend DDNS for"
                return intent_response(
                    "success",
                    f"DRY RUN: Would {verb} lease at {address}",
                    steps,
                    result={"mode": "DRY RUN", "plan": plan},
                    warnings=[f"This is a DRY RUN. Set dry_run=False to actually {verb} the lease."],
                )

            addr_payload = [{"address": address, "space": space_id}]
            resp = client.send_lease_command(command=command, address=addr_payload)
            verb = "Cleared" if action == "clear" else "Resent DDNS for"
            steps.append(step_result(f"{verb} lease", "success", {"address": address, "command": command}))
            return intent_response("success", f"{verb} lease at {address}", steps, result=resp)

    except Exception as e:
        return intent_response("failed", f"Failed to {action} DHCP lease: {e}", steps)


# ==================== IP Reservation Tools ====================


@mcp.tool(annotations={"destructiveHint": True, "idempotentHint": False})
def manage_ip_reservation(
    action: Literal["reserve", "release", "list", "get", "update"],
    address: str | None = None,
    space: str | None = None,
    mac: str | None = None,
    hostname: str | None = None,
    comment: str | None = None,
    resource_id: str | None = None,
    dry_run: bool = True,
) -> dict:
    """
    Reserve, release, list, get, or update fixed IP addresses and DHCP static leases.
    USE THIS for IP reservation CRUD. For network topology use manage_network(). For IP conflicts use diagnose_ip_conflict().

    IMPORTANT: Release runs in dry_run mode by default — shows host associations before releasing.

    Args:
        action: Operation to perform on IP reservations
        address: IP address to reserve/release (e.g., "10.20.3.50")
        space: IP space name or ID (required for reserve)
        mac: MAC address to bind to reservation
        hostname: Hostname for the reservation
        comment: Description
        resource_id: Fixed address resource ID for get/update/release
        dry_run: If True (default), release shows associations only. Set False to execute.

    Returns:
        Reservation operation result

    Examples:
        - manage_ip_reservation(action="reserve", address="10.20.3.50", space="prod", mac="AA:BB:CC:DD:EE:FF")
        - manage_ip_reservation(action="list", space="prod") → all reservations in space
        - manage_ip_reservation(action="release", address="10.20.3.50", dry_run=False)
        - manage_ip_reservation(action="update", resource_id="ipam/fixed_address/abc", comment="Updated")
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    valid, err = validate_action(action, ["reserve", "release", "list", "get", "update"])
    if not valid:
        return intent_response("failed", err)

    steps = []
    warnings = []

    try:
        if action == "reserve":
            if not address:
                return intent_response("failed", "Reserve requires 'address'.", steps)
            valid_ip, ip_err = validate_ip(address)
            if not valid_ip:
                return intent_response("failed", ip_err)
            if not space:
                return intent_response("failed", "Reserve requires 'space'.", steps)

            space_id, s, err = resolve_space(space)
            if s:
                steps.append(s)
            if err:
                return intent_response("failed", f"Cannot resolve IP space: {err}", steps)

            # Check if IP is already in use
            existing = extract_results(client.list_addresses(filter=f'address=="{sanitize_filter(address)}"'))
            if existing:
                usage = existing[0].get("usage", [])
                if usage:
                    warnings.append(f"IP {address} has existing usage: {usage}")

            if mac:
                valid_mac, mac_err = validate_mac(mac)
                if not valid_mac:
                    return intent_response("failed", mac_err)

            kwargs = {}
            if mac:
                kwargs["match_type"] = "mac"
                kwargs["match_value"] = mac
            if hostname:
                kwargs["name"] = hostname

            resp = client.create_fixed_address(address=address, space=space_id, comment=comment, **kwargs)
            result = resp.get("result", resp)
            steps.append(step_result("Reserve IP", "success", {"id": result.get("id"), "address": address}))
            return intent_response("success", f"Reserved IP {address}", steps, result=result, warnings=warnings)

        elif action == "list":
            filters = []
            if space:
                space_id, s, err = resolve_space(space)
                if s:
                    steps.append(s)
                if space_id:
                    filters.append(f'ip_space=="{space_id}"')
            if address:
                filters.append(f'address~"{sanitize_filter(address)}"')

            filter_str = " and ".join(filters) if filters else None
            resp = client.list_addresses(filter=filter_str, limit=100)
            items = extract_results(resp)
            result = [
                {
                    "id": a.get("id"),
                    "address": a.get("address"),
                    "names": a.get("names", []),
                    "usage": a.get("usage", []),
                    "space": a.get("space"),
                    "comment": a.get("comment", ""),
                }
                for a in items
            ]
            steps.append(step_result("List addresses", "success", {"count": len(items)}))
            return intent_response("success", f"Found {len(items)} address(es)", steps, result=result)

        elif action == "get":
            if not resource_id:
                if address:
                    # Lookup by address
                    resp = client.list_addresses(filter=f'address=="{sanitize_filter(address)}"')
                    items = extract_results(resp)
                    if items:
                        resource_id = items[0].get("id")
                        steps.append(step_result("Lookup address", "success", {"id": resource_id}))
                    else:
                        return intent_response("failed", f"No address record found for '{address}'", steps)
                else:
                    return intent_response("failed", "Get requires 'resource_id' or 'address'.", steps)
            resp = client.get_fixed_address(resource_id)
            result = resp.get("result", resp)
            steps.append(step_result("Get fixed address", "success", {"id": resource_id}))
            return intent_response("success", f"Retrieved reservation {resource_id}", steps, result=result)

        elif action == "update":
            if not resource_id:
                return intent_response("failed", "Update requires 'resource_id'.", steps)
            updates = {}
            if comment is not None:
                updates["comment"] = comment
            if hostname is not None:
                updates["name"] = hostname
            if mac is not None:
                updates["match_value"] = mac
            if not updates:
                return intent_response("failed", "No update fields provided.", steps)
            resp = client.update_fixed_address(resource_id, updates)
            result = resp.get("result", resp)
            steps.append(step_result("Update reservation", "success", {"id": resource_id}))
            return intent_response("success", f"Updated reservation {resource_id}", steps, result=result)

        elif action == "release":
            if not resource_id and not address:
                return intent_response("failed", "Release requires 'resource_id' or 'address'.", steps)

            # Find the fixed address
            if address and not resource_id:
                valid_ip, ip_err = validate_ip(address)
                if not valid_ip:
                    return intent_response("failed", ip_err)
                addr_records = extract_results(client.list_addresses(filter=f'address=="{sanitize_filter(address)}"'))
                if not addr_records:
                    return intent_response("failed", f"No address record found for '{address}'", steps)
                resource_id = addr_records[0].get("id")
                steps.append(step_result("Lookup fixed address", "success", {"id": resource_id}))

            # Check for host associations
            if address:
                try:
                    hosts = extract_results(client.list_ipam_hosts(filter=f'address=="{sanitize_filter(address)}"'))
                    if hosts:
                        warnings.append(f"IP {address} is associated with host(s): {[h.get('name') for h in hosts]}")
                except Exception as e:
                    warnings.append(f"Host association lookup failed: {e}")

            if dry_run:
                return intent_response(
                    "success",
                    f"DRY RUN: Would release IP reservation {address or resource_id}",
                    steps,
                    result={"resource_id": resource_id, "address": address},
                    warnings=warnings + ["This is a DRY RUN. Set dry_run=False to actually release."],
                    next_actions=[
                        f"Execute: manage_ip_reservation(action='release', resource_id='{resource_id}', dry_run=False)"
                    ],
                )

            client.delete_fixed_address(resource_id)
            steps.append(step_result("Release IP reservation", "success", {"id": resource_id}))
            return intent_response(
                "success", f"Released IP reservation {address or resource_id}", steps, warnings=warnings
            )

    except Exception as e:
        return intent_response("failed", f"Failed to {action} IP reservation: {e}", steps)


# ==================== Security Policy Tools ====================


@mcp.tool(annotations={"destructiveHint": True, "idempotentHint": False})
def manage_security_policy(
    resource_type: Literal["policy", "named_list", "app_filter", "internal_domains", "access_code", "category_filter"],
    action: Literal["create", "update", "delete", "list", "get", "add_items", "remove_items"],
    name: str | None = None,
    resource_id: str | None = None,
    items: list[str] | None = None,
    categories: list[str] | None = None,
    description: str | None = None,
    list_type: str | None = None,
    criteria: list[dict[str, Any]] | None = None,
    activation: str | None = None,
    expiration: str | None = None,
    rules: list[dict[str, Any]] | None = None,
    dry_run: bool = True,
) -> dict:
    """
    Manage DNS security resources: policies (read-only), named lists, application filters, internal domains, access codes, and category filters.
    USE THIS for security policy CRUD. For posture assessment use assess_security_posture(). For threat investigation use investigate_threat().

    NOTE: Security policies are read-only via API (list/get only). Named lists support full CRUD + partial item updates.
    Category filters use full replace (PUT) for updates — both name and categories are required.

    Args:
        resource_type: Type of security resource to manage
        action: Operation to perform. "add_items" and "remove_items" are for named_list only —
                they add/remove domains from an existing list without replacing the entire list.
        name: Resource name
        resource_id: Resource ID for get/update/delete/add_items/remove_items
        items: List of domains/IPs for named lists or internal domain lists.
               For "add_items": items to add. For "remove_items": items to remove.
        categories: List of content category names — for category_filter create/update
        description: Description text
        list_type: Named list type (e.g., "custom_list") — for named_list create
        criteria: Application filter criteria — for app_filter create
        activation: Access code activation date (ISO 8601) — for access_code create
        expiration: Access code expiration date (ISO 8601) — for access_code create
        rules: Access code rules — for access_code create
        dry_run: If True (default), delete shows resource only. Set False to execute.

    Returns:
        Security resource operation result

    Examples:
        - manage_security_policy(resource_type="policy", action="list") → all security policies
        - manage_security_policy(resource_type="named_list", action="list")
        - manage_security_policy(resource_type="named_list", action="create", name="block-list", list_type="custom_list", items=["bad.com"])
        - manage_security_policy(resource_type="named_list", action="update", resource_id="...", items=["bad.com", "evil.com"])
        - manage_security_policy(resource_type="named_list", action="add_items", resource_id="...", items=["new-bad.com"])
        - manage_security_policy(resource_type="named_list", action="remove_items", resource_id="...", items=["old-entry.com"])
        - manage_security_policy(resource_type="category_filter", action="list") → all category filters
        - manage_security_policy(resource_type="category_filter", action="create", name="block-adult", categories=["Adult Content"])
        - manage_security_policy(resource_type="category_filter", action="update", resource_id="123", name="block-adult", categories=["Adult Content", "Malware"])
        - manage_security_policy(resource_type="internal_domains", action="create", name="corp-domains", items=["corp.local"])
    """
    if not atcfw_client:
        return intent_response(
            "failed",
            "Security client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    valid, err = validate_resource_type(
        resource_type, ["policy", "named_list", "app_filter", "internal_domains", "access_code", "category_filter"]
    )
    if not valid:
        return intent_response("failed", err)

    # Policies are read-only
    if resource_type == "policy" and action not in ("list", "get"):
        return intent_response("failed", "Security policies are read-only via API. Use 'list' or 'get' only.")

    # add_items/remove_items only for named_list
    if action in ("add_items", "remove_items") and resource_type != "named_list":
        return intent_response("failed", f"'{action}' is only supported for named_list, not {resource_type}.")

    valid, err = validate_action(action, ["create", "update", "delete", "list", "get", "add_items", "remove_items"])
    if not valid:
        return intent_response("failed", err)

    steps = []

    try:
        if action == "list":
            if resource_type == "policy":
                resp = atcfw_client.list_security_policies(limit=100)
                items_list = extract_results(resp)
                result = [
                    {"id": p.get("id"), "name": p.get("name"), "description": p.get("description", "")}
                    for p in items_list
                ]
            elif resource_type == "named_list":
                resp = atcfw_client.list_named_lists(limit=100)
                items_list = extract_results(resp)
                result = [
                    {
                        "id": n.get("id"),
                        "name": n.get("name"),
                        "type": n.get("type", ""),
                        "item_count": n.get("item_count", len(n.get("items", []))),
                    }
                    for n in items_list
                ]
            elif resource_type == "app_filter":
                resp = atcfw_client.list_application_filters(limit=100)
                items_list = extract_results(resp)
                result = [
                    {"id": f.get("id"), "name": f.get("name"), "description": f.get("description", "")}
                    for f in items_list
                ]
            elif resource_type == "internal_domains":
                resp = atcfw_client.list_internal_domain_lists(limit=100)
                items_list = extract_results(resp)
                result = [
                    {"id": d.get("id"), "name": d.get("name"), "description": d.get("description", "")}
                    for d in items_list
                ]
            elif resource_type == "access_code":
                resp = atcfw_client.list_access_codes(limit=100)
                items_list = extract_results(resp)
                result = [
                    {
                        "id": a.get("id"),
                        "name": a.get("name"),
                        "activation": a.get("activation"),
                        "expiration": a.get("expiration"),
                    }
                    for a in items_list
                ]
            elif resource_type == "category_filter":
                resp = atcfw_client.list_category_filters(limit=100)
                items_list = extract_results(resp)
                result = [
                    {
                        "id": cf.get("id"),
                        "name": cf.get("name"),
                        "description": cf.get("description", ""),
                        "categories": cf.get("categories", []),
                    }
                    for cf in items_list
                ]
            steps.append(step_result(f"List {resource_type}s", "success", {"count": len(items_list)}))
            return intent_response("success", f"Found {len(items_list)} {resource_type}(s)", steps, result=result)

        elif action == "get":
            if not resource_id:
                return intent_response("failed", "Get requires 'resource_id'.", steps)
            if resource_type == "policy":
                resp = atcfw_client.get_security_policy(resource_id)
            elif resource_type == "category_filter":
                resp = atcfw_client.get_category_filter(resource_id)
            else:
                return intent_response(
                    "failed",
                    "Get by ID only supported for 'policy' and 'category_filter'. Use 'list' + filter for others.",
                    steps,
                )
            result = resp.get("result", resp)
            steps.append(step_result(f"Get {resource_type}", "success", {"id": resource_id}))
            return intent_response("success", f"Retrieved {resource_type}", steps, result=result)

        elif action == "create":
            if not name:
                return intent_response("failed", "Create requires 'name'.", steps)

            if resource_type == "named_list":
                resp = atcfw_client.create_named_list(
                    name=name, type=list_type or "custom_list", items=items, description=description or ""
                )
            elif resource_type == "app_filter":
                if not criteria:
                    return intent_response("failed", "App filter create requires 'criteria'.", steps)
                resp = atcfw_client.create_application_filter(
                    name=name, criteria=criteria, description=description or ""
                )
            elif resource_type == "internal_domains":
                if not items:
                    return intent_response("failed", "Internal domains create requires 'items' (domain list).", steps)
                resp = atcfw_client.create_internal_domain_list(
                    name=name, internal_domains=items, description=description or ""
                )
            elif resource_type == "access_code":
                if not activation or not expiration:
                    return intent_response(
                        "failed", "Access code create requires 'activation' and 'expiration' dates.", steps
                    )
                resp = atcfw_client.create_access_code(
                    name=name, activation=activation, expiration=expiration, rules=rules, description=description or ""
                )
            elif resource_type == "category_filter":
                if not categories:
                    return intent_response(
                        "failed", "Category filter create requires 'categories' (list of category names).", steps
                    )
                resp = atcfw_client.create_category_filter(
                    name=name, categories=categories, description=description or ""
                )
            result = resp.get("result", resp)
            steps.append(step_result(f"Create {resource_type}", "success", {"id": result.get("id")}))
            return intent_response("success", f"Created {resource_type} '{name}'", steps, result=result)

        elif action == "update":
            if not resource_id:
                return intent_response("failed", "Update requires 'resource_id'.", steps)
            if resource_type == "named_list":
                kwargs = {}
                if name:
                    kwargs["name"] = name
                if items is not None:
                    kwargs["items"] = items
                if description is not None:
                    kwargs["description"] = description
                if not kwargs:
                    return intent_response("failed", "No update fields provided.", steps)
                resp = atcfw_client.update_named_list(resource_id, **kwargs)
                result = resp.get("result", resp)
                steps.append(step_result("Update named list", "success", {"id": resource_id}))
                return intent_response("success", f"Updated named list {resource_id}", steps, result=result)
            elif resource_type == "category_filter":
                if not name or not categories:
                    return intent_response(
                        "failed",
                        "Category filter update requires both 'name' and 'categories' (full replace via PUT).",
                        steps,
                    )
                resp = atcfw_client.update_category_filter(
                    filter_id=resource_id, name=name, categories=categories, description=description or ""
                )
                result = resp.get("result", resp)
                steps.append(step_result("Update category filter", "success", {"id": resource_id}))
                return intent_response("success", f"Updated category filter {resource_id}", steps, result=result)
            else:
                return intent_response(
                    "failed",
                    "Update only supported for 'named_list' and 'category_filter'. Other types: recreate.",
                    steps,
                )

        elif action in ("add_items", "remove_items"):
            if not resource_id:
                return intent_response("failed", f"'{action}' requires 'resource_id'.", steps)
            if not items:
                return intent_response("failed", f"'{action}' requires 'items' list.", steps)
            inserts = items if action == "add_items" else None
            deletes = items if action == "remove_items" else None
            resp = atcfw_client.partial_update_named_list_items(resource_id, inserts=inserts, deletes=deletes)
            result = resp.get("result", resp)
            verb = "Added" if action == "add_items" else "Removed"
            steps.append(step_result(f"{verb} items from named list", "success", {"id": resource_id, "items": items}))
            return intent_response(
                "success", f"{verb} {len(items)} item(s) in named list {resource_id}", steps, result=result
            )

        elif action == "delete":
            if not resource_id:
                return intent_response("failed", "Delete requires 'resource_id'.", steps)
            if resource_type not in ("named_list", "category_filter"):
                return intent_response(
                    "failed",
                    "Delete only supported for 'named_list' and 'category_filter'. Other types: use Infoblox Portal.",
                    steps,
                )

            if dry_run:
                return intent_response(
                    "success",
                    f"DRY RUN: Would delete {resource_type} {resource_id}",
                    steps,
                    result={"resource_id": resource_id},
                    warnings=["This is a DRY RUN. Set dry_run=False to actually delete."],
                    next_actions=[
                        f"Execute: manage_security_policy(resource_type='{resource_type}', action='delete', resource_id='{resource_id}', dry_run=False)"
                    ],
                )
            if resource_type == "named_list":
                atcfw_client.delete_named_list(resource_id)
            elif resource_type == "category_filter":
                atcfw_client.delete_category_filter(resource_id)
            steps.append(step_result(f"Delete {resource_type}", "success", {"id": resource_id}))
            return intent_response("success", f"Deleted {resource_type} {resource_id}", steps)

    except Exception as e:
        return intent_response("failed", f"Failed to {action} {resource_type}: {e}", steps)


# ==================== Federation Tools ====================


@mcp.tool(annotations={"destructiveHint": True, "idempotentHint": False})
def manage_federation(
    resource_type: Literal[
        "realm", "block", "delegation", "pool", "overlapping_block", "reserved_block", "forward_delegation"
    ],
    action: Literal["create", "update", "delete", "get", "list", "allocate_next"],
    name: str | None = None,
    resource_id: str | None = None,
    address: str | None = None,
    realm: str | None = None,
    cidr: int | None = None,
    delegated_to: str | None = None,
    comment: str | None = None,
    dry_run: bool = True,
) -> dict:
    """
    Manage federated IPAM: realms, blocks, delegations, pools, overlapping blocks, reserved blocks, and forward delegations.
    USE THIS for federated/multi-site IPAM operations. For local IPAM use manage_network(). For IP reservations use manage_ip_reservation().

    Args:
        resource_type: Type of federation resource to manage
        action: Operation to perform ("allocate_next" only for blocks)
        name: Resource name (for realms, pools)
        resource_id: Resource ID for get/update/delete
        address: CIDR address for blocks/delegations
        realm: Federated realm name or ID
        cidr: CIDR prefix length for allocate_next
        delegated_to: Delegation target identifier
        comment: Description
        dry_run: If True (default), delete shows resource only. Set False to execute.

    Returns:
        Federation operation result

    Examples:
        - manage_federation(resource_type="realm", action="list")
        - manage_federation(resource_type="realm", action="create", name="region-us-east")
        - manage_federation(resource_type="block", action="create", address="10.0.0.0/8", realm="region-us-east")
        - manage_federation(resource_type="block", action="allocate_next", resource_id="federation/block/abc", cidr=24)
        - manage_federation(resource_type="delegation", action="create", address="10.1.0.0/16", realm="us-east", delegated_to="team-a")
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    valid, err = validate_resource_type(
        resource_type,
        ["realm", "block", "delegation", "pool", "overlapping_block", "reserved_block", "forward_delegation"],
    )
    if not valid:
        return intent_response("failed", err)

    allowed_actions = ["create", "update", "delete", "get", "list"]
    if resource_type == "block":
        allowed_actions.append("allocate_next")
    valid, err = validate_action(action, allowed_actions)
    if not valid:
        return intent_response("failed", err)

    steps = []

    # Method dispatch table
    dispatch = {
        "realm": {
            "list": lambda: client.list_federated_realms(limit=100),
            "get": lambda rid: client.get_federated_realm(rid),
            "create": lambda: client.create_federated_realm(name=name, comment=comment),
            "update": lambda rid, u: client.update_federated_realm(rid, u),
            "delete": lambda rid: client.delete_federated_realm(rid),
        },
        "block": {
            "list": lambda: client.list_federated_blocks(limit=100),
            "get": lambda rid: client.get_federated_block(rid),
            "update": lambda rid, u: client.update_federated_block(rid, u),
            "delete": lambda rid: client.delete_federated_block(rid),
        },
        "delegation": {
            "list": lambda: client.list_delegations(limit=100),
            "get": lambda rid: client.get_delegation(rid),
            "update": lambda rid, u: client.update_delegation(rid, u),
            "delete": lambda rid: client.delete_delegation(rid),
        },
        "pool": {
            "list": lambda: client.list_federated_pools(limit=100),
            "get": lambda rid: client.get_federated_pool(rid),
            "update": lambda rid, u: client.update_federated_pool(rid, u),
            "delete": lambda rid: client.delete_federated_pool(rid),
        },
        "overlapping_block": {
            "list": lambda: client.list_overlapping_blocks(limit=100),
            "get": lambda rid: client.get_overlapping_block(rid),
            "update": lambda rid, u: client.update_overlapping_block(rid, u),
            "delete": lambda rid: client.delete_overlapping_block(rid),
        },
        "reserved_block": {
            "list": lambda: client.list_reserved_blocks(limit=100),
            "get": lambda rid: client.get_reserved_block(rid),
            "update": lambda rid, u: client.update_reserved_block(rid, u),
            "delete": lambda rid: client.delete_reserved_block(rid),
        },
        "forward_delegation": {
            "list": lambda: client.list_forward_delegations(limit=100),
            "get": lambda rid: client.get_forward_delegation(rid),
            "update": lambda rid, u: client.update_forward_delegation(rid, u),
            "delete": lambda rid: client.delete_forward_delegation(rid),
        },
    }

    try:
        if action == "list":
            resp = dispatch[resource_type]["list"]()
            items = extract_results(resp)
            result = []
            for item in items:
                entry = {"id": item.get("id")}
                if "name" in item:
                    entry["name"] = item["name"]
                if "address" in item:
                    entry["address"] = item["address"]
                if "cidr" in item:
                    entry["cidr"] = item["cidr"]
                if "federated_realm" in item:
                    entry["federated_realm"] = item["federated_realm"]
                entry["comment"] = item.get("comment", "")
                result.append(entry)
            steps.append(step_result(f"List {resource_type}s", "success", {"count": len(items)}))
            return intent_response("success", f"Found {len(items)} {resource_type}(s)", steps, result=result)

        elif action == "get":
            if not resource_id:
                return intent_response("failed", "Get requires 'resource_id'.", steps)
            resp = dispatch[resource_type]["get"](resource_id)
            result = resp.get("result", resp)
            steps.append(step_result(f"Get {resource_type}", "success", {"id": resource_id}))
            return intent_response("success", f"Retrieved {resource_type}", steps, result=result)

        elif action == "create":
            # Resolve realm if needed
            realm_id = None
            if realm and resource_type != "realm":
                realm_id, s, err = resolve_realm(realm)
                if s:
                    steps.append(s)
                if err:
                    return intent_response("failed", f"Cannot resolve realm: {err}", steps)

            if resource_type == "realm":
                if not name:
                    return intent_response("failed", "Realm create requires 'name'.", steps)
                resp = dispatch["realm"]["create"]()
            elif resource_type == "block":
                if not address or not realm_id:
                    return intent_response("failed", "Block create requires 'address' (CIDR) and 'realm'.", steps)
                resp = client.create_federated_block(address=address, federated_realm=realm_id, comment=comment)
            elif resource_type == "delegation":
                if not address or not realm_id or not delegated_to:
                    return intent_response(
                        "failed", "Delegation create requires 'address', 'realm', and 'delegated_to'.", steps
                    )
                resp = client.create_delegation(
                    address=address, federated_realm=realm_id, delegated_to=delegated_to, comment=comment
                )
            elif resource_type == "pool":
                if not name or not realm_id:
                    return intent_response("failed", "Pool create requires 'name' and 'realm'.", steps)
                resp = client.create_federated_pool(name=name, federated_realm=realm_id, comment=comment)
            elif resource_type == "overlapping_block":
                if not address or not realm_id:
                    return intent_response("failed", "Overlapping block create requires 'address' and 'realm'.", steps)
                resp = client.create_overlapping_block(address=address, federated_realm=realm_id, comment=comment)
            elif resource_type == "reserved_block":
                if not address or not realm_id:
                    return intent_response("failed", "Reserved block create requires 'address' and 'realm'.", steps)
                resp = client.create_reserved_block(address=address, federated_realm=realm_id, comment=comment)
            elif resource_type == "forward_delegation":
                if not address or not realm_id or not delegated_to:
                    return intent_response(
                        "failed", "Forward delegation create requires 'address', 'realm', and 'delegated_to'.", steps
                    )
                resp = client.create_forward_delegation(
                    address=address, federated_realm=realm_id, delegated_to=delegated_to, comment=comment
                )

            result = resp.get("result", resp)
            steps.append(step_result(f"Create {resource_type}", "success", {"id": result.get("id")}))
            return intent_response("success", f"Created {resource_type}", steps, result=result)

        elif action == "allocate_next":
            if resource_type != "block":
                return intent_response("failed", "allocate_next is only available for 'block' resource_type.", steps)
            if not resource_id or cidr is None:
                return intent_response(
                    "failed", "allocate_next requires 'resource_id' (parent block) and 'cidr' (prefix length).", steps
                )
            resp = client.allocate_next_available_federated_block(
                federated_block_id=resource_id, cidr=cidr, comment=comment
            )
            result = resp.get("result", resp)
            steps.append(step_result("Allocate next block", "success", {"id": result.get("id"), "cidr": cidr}))
            return intent_response("success", f"Allocated /{cidr} block from {resource_id}", steps, result=result)

        elif action == "update":
            if not resource_id:
                return intent_response("failed", "Update requires 'resource_id'.", steps)
            updates = {}
            if comment is not None:
                updates["comment"] = comment
            if name is not None:
                updates["name"] = name
            if not updates:
                return intent_response("failed", "No update fields provided.", steps)
            resp = dispatch[resource_type]["update"](resource_id, updates)
            result = resp.get("result", resp)
            steps.append(step_result(f"Update {resource_type}", "success", {"id": resource_id}))
            return intent_response("success", f"Updated {resource_type} {resource_id}", steps, result=result)

        elif action == "delete":
            if not resource_id:
                return intent_response("failed", "Delete requires 'resource_id'.", steps)

            if dry_run:
                # Preview: show resource details + forward delegation preview if applicable
                try:
                    resp = dispatch[resource_type]["get"](resource_id)
                    result = resp.get("result", resp)
                    steps.append(step_result(f"Dry run: inspect {resource_type}", "success", result))
                except Exception as e:
                    steps.append(step_result(f"Dry run: inspect {resource_type}", "failed", error=str(e)))
                return intent_response(
                    "success",
                    f"DRY RUN: Would delete {resource_type} {resource_id}",
                    steps,
                    result={"resource_id": resource_id, "resource_type": resource_type},
                    warnings=["This is a DRY RUN. Set dry_run=False to actually delete."],
                    next_actions=[
                        f"Execute: manage_federation(resource_type='{resource_type}', action='delete', resource_id='{resource_id}', dry_run=False)"
                    ],
                )

            dispatch[resource_type]["delete"](resource_id)
            steps.append(step_result(f"Delete {resource_type}", "success", {"id": resource_id}))
            return intent_response("success", f"Deleted {resource_type} {resource_id}", steps)

    except Exception as e:
        return intent_response("failed", f"Failed to {action} {resource_type}: {e}", steps)


@mcp.tool(annotations={"destructiveHint": True, "idempotentHint": False})
def manage_dtc(
    resource_type: Literal["lbdn", "pool", "server", "policy"],
    action: Literal["create", "update", "delete", "get", "list"],
    name: str | None = None,
    resource_id: str | None = None,
    view: str | None = None,
    dtc_policy: str | None = None,
    comment: str | None = None,
    dry_run: bool = True,
) -> dict:
    """
    Manage DNS Traffic Control (DTC/GSLB): LBDNs, pools, servers, and policies.
    USE THIS for global server load balancing and traffic steering. For DNS zones use manage_dns_zone(). For DNS records use manage_dns_record().

    IMPORTANT: Delete runs in dry_run mode by default. LBDN is the primary resource; pools, servers, and policies are supporting configuration.

    Args:
        resource_type: Type of DTC resource to manage
        action: Operation to perform
        name: Resource name (for create/update)
        resource_id: Resource ID for get/update/delete
        view: DNS view ID (for LBDN create)
        dtc_policy: DTC policy ID (for LBDN create)
        comment: Description
        dry_run: If True (default), delete shows resource only. Set False to execute.

    Returns:
        DTC operation result

    Examples:
        - manage_dtc(resource_type="lbdn", action="list") → all LBDNs
        - manage_dtc(resource_type="lbdn", action="create", name="app.example.com", view="dns/view/1", dtc_policy="dtc/policy/1")
        - manage_dtc(resource_type="pool", action="list") → all DTC pools
        - manage_dtc(resource_type="server", action="list") → all DTC servers
        - manage_dtc(resource_type="policy", action="list") → all DTC policies
    """
    if not client:
        return intent_response(
            "failed",
            "Infoblox client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    valid, err = validate_resource_type(resource_type, ["lbdn", "pool", "server", "policy"])
    if not valid:
        return intent_response("failed", err)

    valid, err = validate_action(action, ["create", "update", "delete", "get", "list"])
    if not valid:
        return intent_response("failed", err)

    steps = []

    # Dispatch table
    dispatch = {
        "lbdn": {
            "list": lambda: client.list_lbdn(limit=100),
            "get": lambda rid: client.get_lbdn(rid),
            "delete": lambda rid: client.delete_lbdn(rid),
            "update": lambda rid, u: client.update_lbdn(rid, u),
        },
        "pool": {
            "list": lambda: client.list_dtc_pools(limit=100),
            "get": lambda rid: client.get_dtc_pool(rid),
            "delete": lambda rid: client.delete_dtc_pool(rid),
            "update": lambda rid, u: client.update_dtc_pool(rid, u),
        },
        "server": {
            "list": lambda: client.list_dtc_servers(limit=100),
            "get": lambda rid: client.get_dtc_server(rid),
            "delete": lambda rid: client.delete_dtc_server(rid),
            "update": lambda rid, u: client.update_dtc_server(rid, u),
        },
        "policy": {
            "list": lambda: client.list_dtc_policies(limit=100),
            "get": lambda rid: client.get_dtc_policy(rid),
            "delete": lambda rid: client.delete_dtc_policy(rid),
            "update": lambda rid, u: client.update_dtc_policy(rid, u),
        },
    }

    try:
        if action == "list":
            resp = dispatch[resource_type]["list"]()
            items = extract_results(resp)
            result = []
            for item in items:
                entry = {"id": item.get("id")}
                if "name" in item:
                    entry["name"] = item["name"]
                if "view" in item:
                    entry["view"] = item["view"]
                if "dtc_policy" in item:
                    entry["dtc_policy"] = item["dtc_policy"]
                entry["comment"] = item.get("comment", "")
                result.append(entry)
            steps.append(step_result(f"List {resource_type}s", "success", {"count": len(items)}))
            return intent_response("success", f"Found {len(items)} {resource_type}(s)", steps, result=result)

        elif action == "get":
            if not resource_id:
                return intent_response("failed", "Get requires 'resource_id'.", steps)
            resp = dispatch[resource_type]["get"](resource_id)
            result = resp.get("result", resp)
            steps.append(step_result(f"Get {resource_type}", "success", {"id": resource_id}))
            return intent_response("success", f"Retrieved {resource_type}", steps, result=result)

        elif action == "create":
            if not name:
                return intent_response("failed", "Create requires 'name'.", steps)

            if resource_type == "lbdn":
                resp = client.create_lbdn(name=name, view=view, dtc_policy=dtc_policy, comment=comment)
            elif resource_type == "pool":
                resp = client.create_dtc_pool(name=name, comment=comment)
            elif resource_type == "server":
                resp = client.create_dtc_server(name=name, comment=comment)
            elif resource_type == "policy":
                resp = client.create_dtc_policy(name=name, comment=comment)

            result = resp.get("result", resp)
            steps.append(step_result(f"Create {resource_type}", "success", {"id": result.get("id")}))
            return intent_response("success", f"Created {resource_type} '{name}'", steps, result=result)

        elif action == "update":
            if not resource_id:
                return intent_response("failed", "Update requires 'resource_id'.", steps)
            updates = {}
            if comment is not None:
                updates["comment"] = comment
            if name is not None:
                updates["name"] = name
            if not updates:
                return intent_response("failed", "No update fields provided.", steps)
            resp = dispatch[resource_type]["update"](resource_id, updates)
            result = resp.get("result", resp)
            steps.append(step_result(f"Update {resource_type}", "success", {"id": resource_id}))
            return intent_response("success", f"Updated {resource_type} {resource_id}", steps, result=result)

        elif action == "delete":
            if not resource_id:
                return intent_response("failed", "Delete requires 'resource_id'.", steps)
            if dry_run:
                try:
                    resp = dispatch[resource_type]["get"](resource_id)
                    result = resp.get("result", resp)
                    steps.append(step_result(f"Dry run: inspect {resource_type}", "success", result))
                except Exception as e:
                    steps.append(step_result(f"Dry run: inspect {resource_type}", "failed", error=str(e)))
                return intent_response(
                    "success",
                    f"DRY RUN: Would delete {resource_type} {resource_id}",
                    steps,
                    result={"resource_id": resource_id, "resource_type": resource_type},
                    warnings=["This is a DRY RUN. Set dry_run=False to actually delete."],
                    next_actions=[
                        f"Execute: manage_dtc(resource_type='{resource_type}', action='delete', resource_id='{resource_id}', dry_run=False)"
                    ],
                )
            dispatch[resource_type]["delete"](resource_id)
            steps.append(step_result(f"Delete {resource_type}", "success", {"id": resource_id}))
            return intent_response("success", f"Deleted {resource_type} {resource_id}", steps)

    except Exception as e:
        return intent_response("failed", f"Failed to {action} {resource_type}: {e}", steps)


# ==================== Security Insight Triage Tools ====================


@mcp.tool(annotations={"destructiveHint": True, "idempotentHint": False})
def triage_security_insight(
    action: Literal["update_status", "bulk_triage", "get_history"],
    insight_id: str | None = None,
    insight_ids: list[str] | None = None,
    status: Literal["IN_PROGRESS", "RESOLVED", "CLOSED", "FALSE_POSITIVE"] | None = None,
    comment: str | None = None,
    priority_filter: Literal["critical", "high", "medium", "low"] | None = None,
    dry_run: bool = True,
) -> dict:
    """
    Triage security insights: update status, bulk triage by priority, or get comment history.
    USE THIS for incident response actions. For investigation use investigate_threat(). For posture review use assess_security_posture().

    Args:
        action: Triage operation to perform
        insight_id: Single insight ID (for update_status, get_history)
        insight_ids: List of insight IDs (for bulk_triage; auto-populated from priority_filter if not set)
        status: New status for the insight(s)
        comment: Triage comment
        priority_filter: For bulk_triage — fetches matching open insights by priority
        dry_run: If True (default), bulk_triage shows what would be updated. Set False to execute.

    Returns:
        Triage operation result

    Examples:
        - triage_security_insight(action="get_history", insight_id="abc123")
        - triage_security_insight(action="update_status", insight_id="abc123", status="IN_PROGRESS", comment="Investigating")
        - triage_security_insight(action="bulk_triage", priority_filter="low", status="CLOSED", comment="Low priority batch close")
        - triage_security_insight(action="bulk_triage", insight_ids=["id1", "id2"], status="FALSE_POSITIVE", dry_run=False)
    """
    if not insights_client:
        return intent_response(
            "failed",
            "Insights client not initialized. Check INFOBLOX_API_KEY.",
            next_actions=[
                "Run check_api_health() to verify connectivity",
                "Ensure INFOBLOX_API_KEY is set in environment or .env file",
            ],
        )

    valid, err = validate_action(action, ["update_status", "bulk_triage", "get_history"])
    if not valid:
        return intent_response("failed", err)

    valid_statuses = ["IN_PROGRESS", "RESOLVED", "CLOSED", "FALSE_POSITIVE"]
    if status and status not in valid_statuses:
        return intent_response("failed", f"Invalid status '{status}'. Allowed: {', '.join(valid_statuses)}")

    steps = []

    try:
        if action == "get_history":
            if not insight_id:
                return intent_response("failed", "get_history requires 'insight_id'.", steps)

            # Get insight details
            insight_resp = insights_client.get_insight(insight_id)
            insight = insight_resp.get("result", insight_resp)
            steps.append(
                step_result(
                    "Get insight details",
                    "success",
                    {"id": insight_id, "status": insight.get("status"), "priority": insight.get("priority")},
                )
            )

            # Get comments/history
            comments_resp = insights_client.get_insight_comments(insight_id)
            comments = extract_results(comments_resp)
            steps.append(step_result("Get comment history", "success", {"count": len(comments)}))

            return intent_response(
                "success",
                f"Insight {insight_id}: {insight.get('status', 'unknown')} — {len(comments)} comment(s)",
                steps,
                result={
                    "insight": {
                        "id": insight_id,
                        "title": insight.get("title"),
                        "status": insight.get("status"),
                        "priority": insight.get("priority"),
                        "threat_type": insight.get("threat_type"),
                    },
                    "comments": comments,
                },
            )

        elif action == "update_status":
            if not insight_id:
                return intent_response("failed", "update_status requires 'insight_id'.", steps)
            if not status:
                return intent_response("failed", "update_status requires 'status'.", steps)

            # Validate current state
            try:
                current = insights_client.get_insight(insight_id)
                current_status = current.get("result", current).get("status", "UNKNOWN")
                steps.append(
                    step_result("Check current status", "success", {"current": current_status, "target": status})
                )
            except Exception:
                current_status = "UNKNOWN"

            resp = insights_client.update_insight_status(insight_ids=[insight_id], status=status, comment=comment)
            steps.append(step_result("Update insight status", "success", {"id": insight_id, "new_status": status}))
            return intent_response(
                "success",
                f"Insight {insight_id} status updated: {current_status} → {status}",
                steps,
                result={"insight_id": insight_id, "previous_status": current_status, "new_status": status},
            )

        elif action == "bulk_triage":
            if not status:
                return intent_response("failed", "bulk_triage requires 'status'.", steps)

            # Build list of insight IDs
            ids_to_triage = insight_ids or []
            if not ids_to_triage and priority_filter:
                resp = insights_client.list_insights(status="OPEN", priority=priority_filter, limit=100)
                open_insights = extract_results(resp)
                ids_to_triage = [i.get("id") for i in open_insights if i.get("id")]
                steps.append(
                    step_result(
                        f"Find {priority_filter} open insights",
                        "success",
                        {
                            "count": len(ids_to_triage),
                            "insights": [{"id": i.get("id"), "title": i.get("title", "")} for i in open_insights[:10]],
                        },
                    )
                )

            if not ids_to_triage:
                return intent_response("success", "No insights matched the filter — nothing to triage.", steps)

            if dry_run:
                return intent_response(
                    "success",
                    f"DRY RUN: Would update {len(ids_to_triage)} insight(s) to status '{status}'",
                    steps,
                    result={"count": len(ids_to_triage), "insight_ids": ids_to_triage[:20], "target_status": status},
                    warnings=["This is a DRY RUN. Set dry_run=False to actually update."],
                    next_actions=[
                        f"Execute: triage_security_insight(action='bulk_triage', insight_ids={ids_to_triage[:20]}, status='{status}', dry_run=False)"
                    ],
                )

            resp = insights_client.update_insight_status(
                insight_ids=ids_to_triage, status=status, comment=comment or f"Bulk triage: set to {status}"
            )
            steps.append(step_result("Bulk update status", "success", {"count": len(ids_to_triage), "status": status}))
            return intent_response(
                "success",
                f"Bulk triaged {len(ids_to_triage)} insight(s) → {status}",
                steps,
                result={"updated_count": len(ids_to_triage), "status": status},
            )

    except Exception as e:
        return intent_response("failed", f"Failed to {action} security insight: {e}", steps)


# ==================== MCP Resources ====================


@mcp.resource("infoblox://tools")
def resource_tool_catalog() -> str:
    """Catalog of all 23 intent tools with descriptions, grouped by domain."""
    return json.dumps(
        {
            "version": __version__,
            "tool_count": 23,
            "domains": {
                "discovery": {
                    "tools": ["explore_network", "search_infrastructure", "get_network_summary"],
                    "description": "Read-only exploration and search across the DDI infrastructure",
                },
                "provisioning": {
                    "tools": ["provision_host", "provision_dns", "decommission_host"],
                    "description": "Create and remove hosts with automatic DNS and IP management",
                },
                "troubleshooting": {
                    "tools": [
                        "diagnose_dns",
                        "diagnose_ip_conflict",
                        "check_api_health",
                        "check_infrastructure_health",
                    ],
                    "description": "Diagnose DNS, IP, API connectivity, and infrastructure issues",
                },
                "security": {
                    "tools": [
                        "investigate_threat",
                        "assess_security_posture",
                        "manage_security_policy",
                        "triage_security_insight",
                    ],
                    "description": "Threat investigation, posture assessment, policy management, and triage",
                },
                "ipam": {
                    "tools": ["manage_network", "manage_ip_reservation", "get_ip_utilization"],
                    "description": "CRUD for subnets, address blocks, ranges, and IP reservations",
                },
                "dns": {
                    "tools": ["manage_dns_zone", "manage_dns_record", "manage_dtc"],
                    "description": "CRUD for DNS zones, records, and DNS Traffic Control (DTC/GSLB)",
                },
                "dhcp": {
                    "tools": ["manage_dhcp", "manage_dhcp_lease"],
                    "description": "CRUD for HA groups, option codes, filters, hardware, and lease management",
                },
                "federation": {
                    "tools": ["manage_federation"],
                    "description": "CRUD for federated realms, blocks, delegations, and pools",
                },
            },
        },
        indent=2,
    )


@mcp.resource("infoblox://status")
def resource_connection_status() -> str:
    """Current connection status for all Infoblox service clients."""
    return json.dumps(
        {
            "infoblox_client": "connected" if client else "not_initialized",
            "insights_client": "connected" if insights_client else "not_initialized",
            "atcfw_client": "connected" if atcfw_client else "not_initialized",
            "base_url": os.environ.get("INFOBLOX_BASE_URL", "https://csp.infoblox.com"),
            "api_key_set": bool(os.environ.get("INFOBLOX_API_KEY")),
        },
        indent=2,
    )


@mcp.resource("infoblox://dns/record-types")
def resource_dns_record_types() -> str:
    """Reference: supported DNS record types and their rdata formats."""
    return json.dumps(
        {
            "A": {"rdata": {"address": "10.0.0.1"}, "description": "IPv4 address"},
            "AAAA": {"rdata": {"address": "2001:db8::1"}, "description": "IPv6 address"},
            "CNAME": {"rdata": {"dname": "target.example.com"}, "description": "Canonical name alias"},
            "MX": {"rdata": {"preference": 10, "exchange": "mail.example.com"}, "description": "Mail exchange"},
            "TXT": {"rdata": {"text": "v=spf1 include:example.com ~all"}, "description": "Text record"},
            "PTR": {"rdata": {"dname": "host.example.com"}, "description": "Reverse DNS pointer"},
            "SRV": {
                "rdata": {"priority": 10, "weight": 60, "port": 5060, "target": "sip.example.com"},
                "description": "Service locator",
            },
            "NS": {"rdata": {"dname": "ns1.example.com"}, "description": "Nameserver delegation"},
            "CAA": {
                "rdata": {"flags": 0, "tag": "issue", "value": "letsencrypt.org"},
                "description": "Certificate authority authorization",
            },
        },
        indent=2,
    )


@mcp.resource("infoblox://spaces")
def resource_ip_spaces() -> str:
    """Live list of all IP spaces with names, IDs, and utilization."""
    if not client:
        return json.dumps({"error": "Infoblox client not initialized"})
    try:
        spaces = extract_results(client.list_ip_spaces())
        return json.dumps(
            [
                {
                    "id": s.get("id", ""),
                    "name": s.get("name", ""),
                    "comment": s.get("comment", ""),
                    "utilization": s.get("utilization", {}),
                }
                for s in spaces
            ],
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.resource("infoblox://zones")
def resource_dns_zones() -> str:
    """Live list of all authoritative DNS zones with FQDNs and status."""
    if not client:
        return json.dumps({"error": "Infoblox client not initialized"})
    try:
        zones = extract_results(client.list_auth_zones())
        return json.dumps(
            [
                {
                    "id": z.get("id", ""),
                    "fqdn": z.get("fqdn", ""),
                    "view": z.get("view_name", z.get("view", "")),
                    "primary_type": z.get("primary_type", ""),
                    "comment": z.get("comment", ""),
                }
                for z in zones
            ],
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ==================== MCP Prompts ====================


@mcp.prompt()
def provision_complete_host() -> str:
    """Guided workflow: provision a host with IP and DNS records step by step."""
    return """You are helping the user provision a new host in Infoblox DDI.

Follow these steps:
1. Ask for: hostname, IP space (or use explore_network() to show available spaces)
2. Ask if they want a specific IP or auto-assignment
3. Ask if they want DNS records (need a zone name)
4. Call provision_host() with the collected parameters
5. Show the result and suggest verification with search_infrastructure()

Always confirm before executing. If the zone doesn't exist, suggest manage_dns_zone(action="create") first."""


@mcp.prompt()
def diagnose_dns_issues() -> str:
    """Guided workflow: troubleshoot DNS resolution problems."""
    return """You are helping the user troubleshoot DNS issues.

Follow these steps:
1. Ask for the domain name that isn't resolving
2. Call diagnose_dns(domain="...") to check zone, records, and security
3. If zone is missing: suggest manage_dns_zone(action="create")
4. If records are missing: suggest provision_dns() to create them
5. If security is blocking: suggest manage_security_policy() to review named lists
6. Summarize all findings and recommended fixes"""


@mcp.prompt()
def security_incident_triage() -> str:
    """Guided workflow: investigate and triage a security incident."""
    return """You are helping the user investigate and triage a security incident.

Follow these steps:
1. Call investigate_threat() to get current open insights
2. For critical/high priority insights, call triage_security_insight(action="get_history") for context
3. Present findings: threat type, indicators, affected assets
4. Ask the user what status to set (IN_PROGRESS, RESOLVED, CLOSED, FALSE_POSITIVE)
5. For bulk operations, use triage_security_insight(action="bulk_triage", dry_run=True) first
6. Always dry_run before executing bulk changes"""


@mcp.prompt()
def capacity_planning() -> str:
    """Guided workflow: assess IP space capacity and plan expansions."""
    return """You are helping the user with IP address capacity planning.

Follow these steps:
1. Call get_ip_utilization() to see current usage across all spaces
2. Highlight any subnets above 80% utilization
3. For high-utilization spaces, call explore_network(scope="...", depth="full") for detail
4. Suggest manage_network(resource_type="subnet", action="create") for new subnets
5. If federation is in use, suggest manage_federation() for block allocation"""


# ==================== OpenTelemetry (optional) ====================


def _setup_otel():
    """Configure OpenTelemetry tracing if OTEL_EXPORTER_OTLP_ENDPOINT is set.

    Install the optional extra to enable:  pip install infoblox-ddi-mcp[otel]
    """
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create(
            {
                "service.name": "infoblox-ddi-mcp",
                "service.version": __version__,
            }
        )
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        trace.set_tracer_provider(provider)
        logger.info("OpenTelemetry tracing enabled", endpoint=endpoint)
    except ImportError:
        logger.warning("OpenTelemetry packages not installed. Install with: pip install infoblox-ddi-mcp[otel]")


# ==================== Server Entry Point ====================


def main():
    """Entry point for both `python mcp_intent.py` and the `infoblox-ddi-mcp` CLI."""
    global mcp

    _setup_otel()

    host = os.environ.get("MCP_HOST", "0.0.0.0")
    port = int(os.environ.get("MCP_PORT", "4005"))
    path = os.environ.get("MCP_PATH", "/mcp")

    # Support both transports:
    #   python mcp_intent.py          → stdio (for Claude Desktop, Cursor, etc.)
    #   python mcp_intent.py --http   → HTTP (for AEX, remote clients)
    if "--http" in sys.argv:
        # Optional bearer token auth via FastMCP's native auth support
        auth_token = os.environ.get("MCP_AUTH_TOKEN")
        auth_status = "enabled" if auth_token else "disabled (set MCP_AUTH_TOKEN to enable)"

        if auth_token:
            from fastmcp.server.auth import RemoteAuthProvider, StaticTokenVerifier

            verifier = StaticTokenVerifier(tokens={auth_token: {"sub": "mcp-client"}})
            auth_provider = RemoteAuthProvider(
                token_verifier=verifier,
                authorization_servers=["https://localhost"],
                base_url=f"http://{host}:{port}",
            )
            mcp.auth = auth_provider
            logger.info("Bearer token authentication enabled for HTTP transport")

        print("=" * 60, file=sys.stderr)
        print(f"  Infoblox DDI Intent Layer v{__version__} — MCP Server (HTTP)", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print(f"  Endpoint:  http://{host}:{port}{path}", file=sys.stderr)
        print("  Transport: HTTP streamable (spec-compliant)", file=sys.stderr)
        print("  Tools:     23 intent-level workflow tools", file=sys.stderr)
        print(f"  Auth:      Bearer token {auth_status}", file=sys.stderr)
        print("=" * 60, file=sys.stderr)

        mcp.run(transport="http", host=host, port=port, path=path)
    else:
        # stdio transport — used by Claude Desktop, Cursor, Windsurf
        mcp.run()


if __name__ == "__main__":
    main()
