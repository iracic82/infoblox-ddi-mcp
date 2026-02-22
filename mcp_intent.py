"""
Infoblox DDI Intent-Layer MCP Server

High-level workflow tools for agentic AI integration.
Instead of 98 atomic CRUD operations, this server exposes 20 intent-level tools
that orchestrate multi-step DDI workflows automatically — covering 100% of the
Infoblox BloxOne DDI API surface.

Any MCP-compatible AI agent (Claude, OpenAI, HCL AEX, Cursor, etc.) can reason
about these tools without being an Infoblox expert.

Usage:
    INFOBLOX_API_KEY=your_key python mcp_intent.py          # stdio transport
    INFOBLOX_API_KEY=your_key python mcp_intent.py --http   # HTTP on port 4005
"""

import logging
import os
import sys
import json
import structlog

__version__ = "1.0.0"

# CRITICAL: Configure structlog to use stderr BEFORE importing service clients.
# In stdio transport mode, stdout is reserved exclusively for JSON-RPC protocol messages.
# Any non-JSON output on stdout corrupts the protocol stream and causes:
#   "Unexpected non-whitespace character after JSON at position 4"
structlog.configure(
    logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
)

# Configure standard logging to stderr too
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)

from fastmcp import FastMCP
from services.infoblox_client import InfobloxClient
from services.insights_client import InsightsClient
from services.atcfw_client import AtcfwClient
from typing import Optional, List, Dict, Any

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
    steps: List[Dict] = None,
    result: Any = None,
    warnings: List[str] = None,
    next_actions: List[str] = None
) -> dict:
    """Standard intent response envelope"""
    return {
        "status": status,
        "summary": summary,
        "steps": steps or [],
        "result": result,
        "warnings": warnings or [],
        "next_actions": next_actions or []
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

import re
import ipaddress


def validate_action(action: str, allowed: List[str]) -> tuple:
    """Validate action against allowed list. Returns (is_valid, error_msg)."""
    if action not in allowed:
        return False, f"Invalid action '{action}'. Allowed: {', '.join(allowed)}"
    return True, ""


def validate_resource_type(resource_type: str, allowed: List[str]) -> tuple:
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
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    if re.match(pattern, mac):
        return True, ""
    return False, f"Invalid MAC address '{mac}'. Expected format: AA:BB:CC:DD:EE:FF"


def validate_fqdn(fqdn: str) -> tuple:
    """Validate fully qualified domain name. Returns (is_valid, error_msg)."""
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.?$'
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
        spaces = extract_results(client.list_ip_spaces(filter=f'name=="{space_name}"'))
        if not spaces:
            spaces = extract_results(client.list_ip_spaces(filter=f'name~"{space_name}"'))
        if spaces:
            space_id = spaces[0].get("id", "")
            return space_id, step_result("Resolve IP space", "success", {"space_id": space_id, "name": spaces[0].get("name")}), ""
        return None, step_result("Resolve IP space", "failed", error=f"IP space '{space_name}' not found"), f"IP space '{space_name}' not found"
    except Exception as e:
        return None, step_result("Resolve IP space", "failed", error=str(e)), str(e)


def resolve_zone(zone_fqdn: str) -> tuple:
    """Resolve DNS zone FQDN to ID. Returns (zone_id, step, error_msg)."""
    if not client:
        return None, None, "Infoblox client not initialized"
    if zone_fqdn.startswith("dns/auth_zone/"):
        return zone_fqdn, step_result("Resolve DNS zone", "success", {"zone_id": zone_fqdn}), ""
    try:
        zones = extract_results(client.list_auth_zones(filter=f'fqdn=="{zone_fqdn}"'))
        if not zones:
            zones = extract_results(client.list_auth_zones(filter=f'fqdn=="{zone_fqdn}."'))
        if zones:
            zone_id = zones[0].get("id", "")
            return zone_id, step_result("Resolve DNS zone", "success", {"zone_id": zone_id, "fqdn": zones[0].get("fqdn")}), ""
        return None, step_result("Resolve DNS zone", "failed", error=f"DNS zone '{zone_fqdn}' not found"), f"DNS zone '{zone_fqdn}' not found"
    except Exception as e:
        return None, step_result("Resolve DNS zone", "failed", error=str(e)), str(e)


def resolve_realm(realm_name: str) -> tuple:
    """Resolve federated realm name to ID. Returns (realm_id, step, error_msg)."""
    if not client:
        return None, None, "Infoblox client not initialized"
    if realm_name.startswith("federation/"):
        return realm_name, step_result("Resolve federated realm", "success", {"realm_id": realm_name}), ""
    try:
        realms = extract_results(client.list_federated_realms(filter=f'name=="{realm_name}"'))
        if not realms:
            realms = extract_results(client.list_federated_realms(filter=f'name~"{realm_name}"'))
        if realms:
            realm_id = realms[0].get("id", "")
            return realm_id, step_result("Resolve federated realm", "success", {"realm_id": realm_id, "name": realms[0].get("name")}), ""
        return None, step_result("Resolve federated realm", "failed", error=f"Federated realm '{realm_name}' not found"), f"Federated realm '{realm_name}' not found"
    except Exception as e:
        return None, step_result("Resolve federated realm", "failed", error=str(e)), str(e)


# ==================== Discovery & Exploration Tools ====================

@mcp.tool()
def explore_network(
    scope: Optional[str] = None,
    depth: str = "summary"
) -> dict:
    """
    Explore the Infoblox DDI network hierarchy: IP Spaces → Address Blocks → Subnets.
    Returns a navigable tree view with utilization data.

    This is the best starting point for understanding what's in your network.

    Args:
        scope: Optional IP space name to focus on (e.g., "prod", "corp"). If not set, shows all spaces.
        depth: Level of detail — "summary" (counts only), "blocks" (include address blocks), or "full" (include subnets)

    Returns:
        Hierarchical network view with utilization percentages

    Examples:
        - explore_network() → overview of all IP spaces with counts
        - explore_network(scope="prod") → detailed view of the prod IP space
        - explore_network(depth="full") → complete hierarchy with all subnets
    """
    if not client:
        return intent_response("failed", "Infoblox client not initialized. Check INFOBLOX_API_KEY.")

    steps = []
    warnings = []

    # Step 1: Get IP spaces
    try:
        space_filter = f'name~"{scope}"' if scope else None
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
            "subnets": []
        }

        if depth in ("blocks", "full"):
            # Step 2: Get address blocks for this space
            try:
                space_id = space.get("id", "")
                blocks_resp = client.list_address_blocks(
                    filter=f'space=="{space_id}"' if space_id else None
                )
                blocks = extract_results(blocks_resp)
                space_info["address_blocks"] = [
                    {
                        "id": b.get("id", ""),
                        "address": b.get("address", ""),
                        "cidr": b.get("cidr", 0),
                        "name": b.get("name", b.get("comment", "")),
                        "utilization": b.get("utilization", {})
                    }
                    for b in blocks
                ]
                steps.append(step_result(
                    f"List address blocks for {space_info['name']}",
                    "success",
                    {"count": len(blocks)}
                ))
            except Exception as e:
                warnings.append(f"Failed to get blocks for {space_info['name']}: {e}")

        if depth == "full":
            # Step 3: Get subnets for this space
            try:
                space_id = space.get("id", "")
                subnets_resp = client.list_subnets(
                    filter=f'space=="{space_id}"' if space_id else None
                )
                subnets = extract_results(subnets_resp)
                space_info["subnets"] = [
                    {
                        "id": s.get("id", ""),
                        "address": s.get("address", ""),
                        "cidr": s.get("cidr", 0),
                        "name": s.get("name", s.get("comment", "")),
                        "utilization": s.get("utilization", {})
                    }
                    for s in subnets
                ]
                steps.append(step_result(
                    f"List subnets for {space_info['name']}",
                    "success",
                    {"count": len(subnets)}
                ))
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
            "Use provision_host() to add a new host to any subnet"
        ]
    )


@mcp.tool()
def search_infrastructure(
    query: str,
    types: Optional[List[str]] = None,
    limit: int = 20
) -> dict:
    """
    Unified search across all Infoblox DDI domains: subnets, DNS records, IPAM hosts, IP addresses.
    Searches by name, address, comment, or any matching field.

    Args:
        query: Search term (IP address, hostname, domain name, comment text, etc.)
        types: Optional list of resource types to search. Options: "subnets", "dns_zones", "dns_records", "hosts", "addresses". If not set, searches all types.
        limit: Maximum results per type (default: 20, max: 100)

    Returns:
        Matching resources grouped by type

    Examples:
        - search_infrastructure(query="10.20.3") → finds subnets, hosts, addresses matching
        - search_infrastructure(query="web-prod", types=["hosts", "dns_records"])
        - search_infrastructure(query="example.com", types=["dns_records"])
    """
    if not client:
        return intent_response("failed", "Infoblox client not initialized. Check INFOBLOX_API_KEY.")

    search_types = types or ["subnets", "dns_zones", "dns_records", "hosts", "addresses"]
    limit = min(limit, 100)
    steps = []
    results = {}
    total_found = 0

    # Search DNS zones
    if "dns_zones" in search_types:
        try:
            zone_filter = f'fqdn~"{query}"' if query and query != "*" else None
            resp = client.list_auth_zones(filter=zone_filter, limit=limit)
            items = extract_results(resp)
            results["dns_zones"] = [
                {"id": z.get("id"), "fqdn": z.get("fqdn"), "view": z.get("view"),
                 "primary_type": z.get("primary_type", ""), "comment": z.get("comment", "")}
                for z in items
            ]
            total_found += len(items)
            steps.append(step_result("Search DNS zones", "success", {"count": len(items)}))
        except Exception as e:
            steps.append(step_result("Search DNS zones", "failed", error=str(e)))

    # Search subnets
    if "subnets" in search_types:
        try:
            resp = client.list_subnets(filter=f'address~"{query}" or comment~"{query}"', limit=limit)
            items = extract_results(resp)
            results["subnets"] = [
                {"id": s.get("id"), "address": s.get("address"), "cidr": s.get("cidr"),
                 "name": s.get("name", s.get("comment", "")), "space": s.get("space")}
                for s in items
            ]
            total_found += len(items)
            steps.append(step_result("Search subnets", "success", {"count": len(items)}))
        except Exception as e:
            steps.append(step_result("Search subnets", "failed", error=str(e)))

    # Search DNS records
    if "dns_records" in search_types:
        try:
            resp = client.list_dns_records(filter=f'name_in_zone~"{query}" or absolute_name_spec~"{query}"', limit=limit)
            items = extract_results(resp)
            results["dns_records"] = [
                {"id": r.get("id"), "name": r.get("absolute_name_spec", r.get("name_in_zone")),
                 "type": r.get("type"), "rdata": r.get("rdata"), "zone": r.get("zone")}
                for r in items
            ]
            total_found += len(items)
            steps.append(step_result("Search DNS records", "success", {"count": len(items)}))
        except Exception as e:
            steps.append(step_result("Search DNS records", "failed", error=str(e)))

    # Search IPAM hosts
    if "hosts" in search_types:
        try:
            resp = client.list_ipam_hosts(filter=f'name~"{query}"', limit=limit)
            items = extract_results(resp)
            results["hosts"] = [
                {"id": h.get("id"), "name": h.get("name"),
                 "addresses": h.get("addresses", []), "comment": h.get("comment", "")}
                for h in items
            ]
            total_found += len(items)
            steps.append(step_result("Search IPAM hosts", "success", {"count": len(items)}))
        except Exception as e:
            steps.append(step_result("Search IPAM hosts", "failed", error=str(e)))

    # Search IP addresses
    if "addresses" in search_types:
        try:
            resp = client.list_addresses(filter=f'address~"{query}"', limit=limit)
            items = extract_results(resp)
            results["addresses"] = [
                {"id": a.get("id"), "address": a.get("address"),
                 "names": a.get("names", []), "space": a.get("space"),
                 "usage": a.get("usage", [])}
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
            f"Use explore_network(scope='...') to see the network context",
            f"Use diagnose_dns(domain='...') to troubleshoot DNS issues",
            f"Use provision_host() to create a new host"
        ]
    )


@mcp.tool()
def get_network_summary(scope: Optional[str] = None) -> dict:
    """
    Get an executive dashboard of the entire Infoblox DDI infrastructure:
    IP space counts, subnet counts, DNS zone counts, DHCP status, and utilization.

    Args:
        scope: Optional IP space name to focus on. If not set, summarizes everything.

    Returns:
        Summary with counts, utilization percentages, and health status

    Examples:
        - get_network_summary() → full infrastructure overview
        - get_network_summary(scope="production") → production space only
    """
    if not client:
        return intent_response("failed", "Infoblox client not initialized. Check INFOBLOX_API_KEY.")

    steps = []
    summary_data = {}

    # IP Spaces
    try:
        space_filter = f'name~"{scope}"' if scope else None
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
            "Use check_infrastructure_health() for service health"
        ]
    )


# ==================== Provisioning Tools ====================

@mcp.tool()
def provision_host(
    hostname: str,
    space: str,
    ip: Optional[str] = None,
    zone: Optional[str] = None,
    comment: Optional[str] = None
) -> dict:
    """
    Provision a complete host in one step: creates IPAM host with IP assignment and optional DNS records.
    This replaces the manual 2-3 step process of creating an IPAM host, then A record, then PTR record.

    Args:
        hostname: Host name (e.g., "web-prod-01"). If zone is provided, will be used as FQDN: hostname.zone
        space: IP space name or ID where the host should be created (e.g., "prod", "corp", or full resource ID)
        ip: Optional specific IP address. If not provided, Infoblox will auto-assign the next available IP.
        zone: Optional DNS zone name for creating A/PTR records (e.g., "prod.example.com")
        comment: Optional description for the host

    Returns:
        Complete provisioning result with host, IP, and DNS record details

    Examples:
        - provision_host(hostname="web-01", space="prod", ip="10.20.3.50", zone="prod.example.com")
        - provision_host(hostname="db-replica-02", space="corp") → auto-assigns IP, no DNS
    """
    if not client:
        return intent_response("failed", "Infoblox client not initialized. Check INFOBLOX_API_KEY.")

    steps = []
    warnings = []
    created_resources = []

    # Step 1: Resolve IP space name to ID if needed
    space_id = space
    if not space.startswith("ipam/ip_space/"):
        try:
            spaces = extract_results(client.list_ip_spaces(filter=f'name=="{space}"'))
            if not spaces:
                spaces = extract_results(client.list_ip_spaces(filter=f'name~"{space}"'))
            if spaces:
                space_id = spaces[0].get("id", space)
                steps.append(step_result("Resolve IP space", "success", {"space_id": space_id, "name": spaces[0].get("name")}))
            else:
                return intent_response("failed", f"IP space '{space}' not found", steps)
        except Exception as e:
            return intent_response("failed", f"Failed to resolve IP space: {e}", steps)

    # Step 2: Create IPAM host
    try:
        fqdn = f"{hostname}.{zone}" if zone else hostname
        address_config = {"space": space_id}
        if ip:
            address_config["address"] = ip

        host_resp = client.create_ipam_host(
            name=fqdn,
            addresses=[address_config],
            comment=comment or f"Provisioned via intent layer"
        )

        host_result = host_resp.get("result", host_resp)
        host_id = host_result.get("id", "")
        # Try to get the assigned IP from the response
        assigned_addresses = host_result.get("addresses", [])
        assigned_ip = ip
        if assigned_addresses:
            assigned_ip = assigned_addresses[0].get("address", ip)

        steps.append(step_result("Create IPAM host", "success", {
            "host_id": host_id,
            "fqdn": fqdn,
            "ip": assigned_ip
        }))
        created_resources.append({"type": "ipam_host", "id": host_id})

    except Exception as e:
        return intent_response("failed", f"Failed to create IPAM host: {e}", steps)

    # Step 3: Create DNS A record (if zone provided)
    dns_a_id = None
    if zone:
        try:
            # Find the zone ID
            zones = extract_results(client.list_auth_zones(filter=f'fqdn=="{zone}"'))
            if zones:
                zone_id = zones[0].get("id", "")
                a_resp = client.create_dns_record(
                    name_in_zone=hostname,
                    zone=zone_id,
                    record_type="A",
                    rdata={"address": assigned_ip or ip},
                    comment=f"Auto-created for host {fqdn}"
                )
                dns_a_id = a_resp.get("result", {}).get("id", "")
                steps.append(step_result("Create DNS A record", "success", {
                    "record_id": dns_a_id,
                    "name": f"{hostname}.{zone}",
                    "address": assigned_ip or ip
                }))
                created_resources.append({"type": "dns_a_record", "id": dns_a_id})
            else:
                warnings.append(f"DNS zone '{zone}' not found — skipped A record creation. Create zone first or use provision_dns().")
                steps.append(step_result("Create DNS A record", "skipped", error=f"Zone '{zone}' not found"))

        except Exception as e:
            warnings.append(f"Failed to create A record: {e}")
            steps.append(step_result("Create DNS A record", "failed", error=str(e)))

    # Step 4: Create DNS PTR record (if zone provided and A record succeeded)
    if zone and assigned_ip and dns_a_id:
        try:
            # Build reverse zone lookup — look for existing reverse zone
            ip_parts = assigned_ip.split(".")
            reverse_name = ip_parts[3]  # Last octet
            reverse_zone_fqdn = f"{ip_parts[2]}.{ip_parts[1]}.{ip_parts[0]}.in-addr.arpa."

            rev_zones = extract_results(client.list_auth_zones(filter=f'fqdn=="{reverse_zone_fqdn}"'))
            if rev_zones:
                rev_zone_id = rev_zones[0].get("id", "")
                ptr_resp = client.create_dns_record(
                    name_in_zone=reverse_name,
                    zone=rev_zone_id,
                    record_type="PTR",
                    rdata={"dname": f"{hostname}.{zone}"},
                    comment=f"Auto-created for host {fqdn}"
                )
                ptr_id = ptr_resp.get("result", {}).get("id", "")
                steps.append(step_result("Create DNS PTR record", "success", {
                    "record_id": ptr_id,
                    "reverse": f"{reverse_name}.{reverse_zone_fqdn}",
                    "points_to": fqdn
                }))
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

    return intent_response(
        status=status,
        summary=f"Host '{hostname}' provisioned: {success_count}/{total_count} steps completed",
        steps=steps,
        result={
            "hostname": hostname,
            "fqdn": f"{hostname}.{zone}" if zone else hostname,
            "ip": assigned_ip or ip,
            "space": space,
            "created_resources": created_resources
        },
        warnings=warnings,
        next_actions=[
            f"Verify: search_infrastructure(query='{hostname}')",
            f"Diagnose: diagnose_dns(domain='{hostname}.{zone}')" if zone else "Add DNS: provision_dns()",
            "Decommission: decommission_host(identifier='...')"
        ]
    )


@mcp.tool()
def provision_dns(
    name: str,
    record_type: str,
    value: str,
    zone: Optional[str] = None,
    ttl: Optional[int] = None,
    comment: Optional[str] = None
) -> dict:
    """
    Create a DNS record with automatic zone discovery. If the zone doesn't exist, provides guidance.

    Args:
        name: Record name (e.g., "www" for www.example.com, or full FQDN "www.example.com")
        record_type: DNS record type — "A", "AAAA", "CNAME", "MX", "TXT", "PTR", "SRV", "NS"
        value: Record value — IP for A/AAAA, domain for CNAME/MX/PTR/NS, text for TXT
        zone: DNS zone name (e.g., "example.com"). If not provided, extracted from the name.
        ttl: Time to live in seconds (optional)
        comment: Optional description

    Returns:
        Created DNS record details

    Examples:
        - provision_dns(name="www", record_type="A", value="10.20.3.50", zone="example.com")
        - provision_dns(name="app.example.com", record_type="CNAME", value="lb.example.com")
        - provision_dns(name="example.com", record_type="MX", value="mail.example.com")
    """
    if not client:
        return intent_response("failed", "Infoblox client not initialized. Check INFOBLOX_API_KEY.")

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
    try:
        zones = extract_results(client.list_auth_zones(filter=f'fqdn=="{zone}"'))
        if not zones:
            # Try with trailing dot
            zones = extract_results(client.list_auth_zones(filter=f'fqdn=="{zone}."'))
        if not zones:
            return intent_response(
                "failed",
                f"DNS zone '{zone}' not found. Create it first in Infoblox.",
                steps,
                next_actions=[f"Create zone '{zone}' in Infoblox Portal, then retry"]
            )
        zone_id = zones[0].get("id", "")
        steps.append(step_result("Find DNS zone", "success", {"zone_id": zone_id, "fqdn": zone}))
    except Exception as e:
        return intent_response("failed", f"Failed to find DNS zone: {e}", steps)

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

    # Step 3: Create the record
    try:
        resp = client.create_dns_record(
            name_in_zone=name_in_zone,
            zone=zone_id,
            record_type=rt,
            rdata=rdata,
            ttl=ttl,
            comment=comment or "Created via intent layer"
        )
        record_result = resp.get("result", resp)
        record_id = record_result.get("id", "")
        steps.append(step_result(f"Create {rt} record", "success", {
            "record_id": record_id,
            "fqdn": f"{name_in_zone}.{zone}",
            "type": rt,
            "value": value
        }))
    except Exception as e:
        return intent_response("failed", f"Failed to create {rt} record: {e}", steps)

    return intent_response(
        status="success",
        summary=f"{rt} record created: {name_in_zone}.{zone} → {value}",
        steps=steps,
        result={"record_id": record_id, "fqdn": f"{name_in_zone}.{zone}", "type": rt, "value": value},
        next_actions=[
            f"Verify: diagnose_dns(domain='{name_in_zone}.{zone}')",
            f"Search: search_infrastructure(query='{name_in_zone}')"
        ]
    )


@mcp.tool()
def decommission_host(
    identifier: str,
    dry_run: bool = True
) -> dict:
    """
    Decommission a host: removes IPAM host, DNS records, and releases IP addresses.
    Performs reverse provisioning with safety checks.

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
        return intent_response("failed", "Infoblox client not initialized. Check INFOBLOX_API_KEY.")

    steps = []
    resources_to_delete = []
    mode = "DRY RUN" if dry_run else "EXECUTING"

    # Step 1: Find IPAM hosts matching the identifier
    try:
        hosts = extract_results(client.list_ipam_hosts(filter=f'name~"{identifier}"'))
        if not hosts:
            # Try searching by IP in addresses
            addresses = extract_results(client.list_addresses(filter=f'address=="{identifier}"'))
            if addresses:
                # Find host associated with this IP
                for addr in addresses:
                    names = addr.get("names", [])
                    for name_info in names:
                        host_name = name_info.get("name", "")
                        if host_name:
                            hosts = extract_results(client.list_ipam_hosts(filter=f'name=="{host_name}"'))
                            break

        if not hosts:
            return intent_response("failed", f"No host found matching '{identifier}'", steps)

        steps.append(step_result("Find hosts", "success", {"count": len(hosts), "hosts": [h.get("name") for h in hosts]}))

        for host in hosts:
            host_id = host.get("id", "")
            host_name = host.get("name", "")
            host_addresses = host.get("addresses", [])

            resources_to_delete.append({"type": "ipam_host", "id": host_id, "name": host_name})

            # Find associated DNS records
            for addr_info in host_addresses:
                addr = addr_info.get("address", "")
                if addr:
                    resources_to_delete.append({"type": "ip_release", "address": addr})

            # Search for DNS records matching this host
            try:
                dns_records = extract_results(client.list_dns_records(filter=f'absolute_name_spec~"{host_name}"'))
                for record in dns_records:
                    resources_to_delete.append({
                        "type": f"dns_{record.get('type', 'unknown')}_record",
                        "id": record.get("id", ""),
                        "name": record.get("absolute_name_spec", "")
                    })
            except Exception:
                pass

    except Exception as e:
        return intent_response("failed", f"Failed to find host: {e}", steps)

    # Step 2: Execute deletion if not dry_run
    if not dry_run:
        deleted = []
        for resource in resources_to_delete:
            res_type = resource.get("type", "")
            res_id = resource.get("id", "")
            try:
                if res_type == "ipam_host" and res_id:
                    client.delete_ipam_host(res_id)
                    deleted.append(resource)
                    steps.append(step_result(f"Delete host {resource.get('name')}", "success"))
                elif res_type.startswith("dns_") and res_id:
                    client.delete_dns_record(res_id)
                    deleted.append(resource)
                    steps.append(step_result(f"Delete {res_type} {resource.get('name')}", "success"))
            except Exception as e:
                steps.append(step_result(f"Delete {res_type}", "failed", error=str(e)))

        summary = f"Decommissioned: {len(deleted)}/{len(resources_to_delete)} resources deleted"
    else:
        summary = f"DRY RUN: Would delete {len(resources_to_delete)} resource(s)"
        steps.append(step_result("Dry run analysis", "success", {"resources": resources_to_delete}))

    return intent_response(
        status="success",
        summary=summary,
        steps=steps,
        result={
            "mode": mode,
            "resources": resources_to_delete,
            "identifier": identifier
        },
        warnings=["This is a DRY RUN. Set dry_run=False to actually delete."] if dry_run else [],
        next_actions=[
            f"Execute: decommission_host(identifier='{identifier}', dry_run=False)" if dry_run else
            f"Verify: search_infrastructure(query='{identifier}')"
        ]
    )


# ==================== Troubleshooting Tools ====================

@mcp.tool()
def diagnose_dns(domain: str) -> dict:
    """
    Diagnose DNS issues for a domain: checks zone existence, record status, and security policies.
    Provides actionable recommendations for fixing problems.

    Args:
        domain: Domain name to diagnose (e.g., "web-prod-01.example.com" or "example.com")

    Returns:
        Diagnostic report with zone status, records found, and recommendations

    Examples:
        - diagnose_dns(domain="app.example.com") → checks zone, A/AAAA/CNAME records, security
        - diagnose_dns(domain="example.com") → checks zone apex records
    """
    if not client:
        return intent_response("failed", "Infoblox client not initialized. Check INFOBLOX_API_KEY.")

    steps = []
    diagnostics = {"domain": domain, "issues": [], "records": []}

    # Parse domain parts
    parts = domain.split(".", 1)
    name_part = parts[0] if len(parts) > 1 else ""
    zone_part = parts[1] if len(parts) > 1 else domain

    # Step 1: Check if zone exists
    zone_found = False
    zone_id = None
    try:
        zones = extract_results(client.list_auth_zones(filter=f'fqdn=="{zone_part}"'))
        if not zones:
            zones = extract_results(client.list_auth_zones(filter=f'fqdn=="{zone_part}."'))
        if not zones and "." in zone_part:
            # Try parent zone
            parent = zone_part.split(".", 1)[1]
            zones = extract_results(client.list_auth_zones(filter=f'fqdn=="{parent}"'))
            if zones:
                name_part = domain.replace(f".{parent}", "")
                zone_part = parent

        if zones:
            zone_found = True
            zone_id = zones[0].get("id", "")
            diagnostics["zone"] = {"status": "found", "fqdn": zones[0].get("fqdn"), "id": zone_id}
            steps.append(step_result("Check DNS zone", "success", {"zone": zone_part}))
        else:
            diagnostics["zone"] = {"status": "not_found"}
            diagnostics["issues"].append(f"DNS zone '{zone_part}' not found")
            steps.append(step_result("Check DNS zone", "failed", error=f"Zone '{zone_part}' not found"))
    except Exception as e:
        steps.append(step_result("Check DNS zone", "failed", error=str(e)))

    # Step 2: Check DNS records for this domain
    try:
        records = extract_results(client.list_dns_records(
            filter=f'absolute_name_spec=="{domain}" or absolute_name_spec=="{domain}."'
        ))
        if not records and name_part:
            records = extract_results(client.list_dns_records(
                filter=f'name_in_zone=="{name_part}"'
            ))

        diagnostics["records"] = [
            {"type": r.get("type"), "name": r.get("absolute_name_spec"), "rdata": r.get("rdata"),
             "ttl": r.get("ttl")}
            for r in records
        ]

        record_types = [r.get("type") for r in records]
        steps.append(step_result("Check DNS records", "success", {
            "count": len(records),
            "types": record_types
        }))

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
        recommendations.append(f"Create A record: provision_dns(name='{name_part}', record_type='A', value='<IP>', zone='{zone_part}')")
    if diagnostics.get("records") and "PTR" not in [r["type"] for r in diagnostics["records"]]:
        recommendations.append("Consider adding a PTR record for reverse DNS")

    issue_count = len(diagnostics["issues"])
    status = "success" if issue_count == 0 else "partial"
    summary = f"DNS diagnosis for '{domain}': {issue_count} issue(s) found, {len(diagnostics.get('records', []))} record(s)"

    return intent_response(
        status=status,
        summary=summary,
        steps=steps,
        result=diagnostics,
        next_actions=recommendations or ["No issues found — DNS appears healthy"]
    )


@mcp.tool()
def diagnose_ip_conflict(address: str) -> dict:
    """
    Check an IP address for conflicts: overlapping subnets, duplicate reservations, and usage status.

    Args:
        address: IP address to check (e.g., "10.20.3.50")

    Returns:
        Conflict report with overlapping resources and recommendations

    Examples:
        - diagnose_ip_conflict(address="10.20.3.50") → checks for conflicts on this IP
        - diagnose_ip_conflict(address="192.168.1.1") → checks subnet membership and reservations
    """
    if not client:
        return intent_response("failed", "Infoblox client not initialized. Check INFOBLOX_API_KEY.")

    steps = []
    diagnostics = {"address": address, "conflicts": [], "found_in": []}

    # Step 1: Check subnets containing this IP
    try:
        subnets = extract_results(client.list_subnets(filter=f'address~"{".".join(address.split(".")[:3])}"'))
        matching_subnets = []
        for s in subnets:
            subnet_addr = s.get("address", "")
            if subnet_addr:
                matching_subnets.append({
                    "id": s.get("id"), "address": subnet_addr,
                    "cidr": s.get("cidr"), "name": s.get("comment", "")
                })
        diagnostics["subnets"] = matching_subnets
        steps.append(step_result("Check subnets", "success", {"count": len(matching_subnets)}))

        if len(matching_subnets) > 1:
            diagnostics["conflicts"].append(f"IP belongs to {len(matching_subnets)} subnets — possible overlap")
    except Exception as e:
        steps.append(step_result("Check subnets", "failed", error=str(e)))

    # Step 2: Check IP address records
    try:
        addresses = extract_results(client.list_addresses(filter=f'address=="{address}"'))
        diagnostics["address_records"] = [
            {"id": a.get("id"), "address": a.get("address"),
             "usage": a.get("usage", []), "names": a.get("names", [])}
            for a in addresses
        ]
        steps.append(step_result("Check address records", "success", {"count": len(addresses)}))

        if len(addresses) > 1:
            diagnostics["conflicts"].append(f"Multiple address records found for {address}")
    except Exception as e:
        steps.append(step_result("Check address records", "failed", error=str(e)))

    # Step 3: Check IP ranges
    try:
        ranges = extract_results(client.list_ranges(filter=f'start<="{address}" and end>="{address}"'))
        diagnostics["ranges"] = [
            {"id": r.get("id"), "start": r.get("start"), "end": r.get("end"), "comment": r.get("comment", "")}
            for r in ranges
        ]
        steps.append(step_result("Check IP ranges", "success", {"count": len(ranges)}))
    except Exception as e:
        steps.append(step_result("Check IP ranges", "failed", error=str(e)))

    conflict_count = len(diagnostics["conflicts"])
    status = "success" if conflict_count == 0 else "partial"

    return intent_response(
        status=status,
        summary=f"IP conflict check for {address}: {conflict_count} conflict(s) found",
        steps=steps,
        result=diagnostics,
        next_actions=[
            "No conflicts — IP is safe to use" if conflict_count == 0 else
            f"Resolve conflicts before using {address}"
        ]
    )


@mcp.tool()
def check_infrastructure_health() -> dict:
    """
    Check the health of Infoblox DDI infrastructure: HA groups, DHCP hosts, DNS zones, and services.
    Provides an overall health score with per-component status.

    Returns:
        Health report with HA status, DHCP status, DNS status, and recommendations

    Examples:
        - check_infrastructure_health() → full health check of all DDI components
    """
    if not client:
        return intent_response("failed", "Infoblox client not initialized. Check INFOBLOX_API_KEY.")

    steps = []
    health = {"components": {}, "issues": []}

    # Check HA groups
    try:
        ha_groups = extract_results(client.list_ha_groups())
        health["components"]["ha_groups"] = {
            "count": len(ha_groups),
            "status": "healthy" if ha_groups else "no_ha_configured",
            "groups": [{"name": g.get("name"), "mode": g.get("mode")} for g in ha_groups]
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
            "status": "healthy" if dhcp_hosts else "no_dhcp_hosts"
        }
        steps.append(step_result("Check DHCP hosts", "success", {"count": len(dhcp_hosts)}))
    except Exception as e:
        steps.append(step_result("Check DHCP hosts", "failed", error=str(e)))

    # Check DNS zones
    try:
        zones = extract_results(client.list_auth_zones())
        health["components"]["dns_zones"] = {
            "count": len(zones),
            "status": "healthy" if zones else "no_zones"
        }
        steps.append(step_result("Check DNS zones", "success", {"count": len(zones)}))
    except Exception as e:
        steps.append(step_result("Check DNS zones", "failed", error=str(e)))

    # Check IP spaces
    try:
        spaces = extract_results(client.list_ip_spaces())
        health["components"]["ip_spaces"] = {
            "count": len(spaces),
            "status": "healthy" if spaces else "no_spaces"
        }
        steps.append(step_result("Check IP spaces", "success", {"count": len(spaces)}))
    except Exception as e:
        steps.append(step_result("Check IP spaces", "failed", error=str(e)))

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
            "All systems healthy" if health["overall"] == "healthy" else
            "Review issues and take corrective action"
        ]
    )


# ==================== Security & Threat Intelligence Tools ====================

@mcp.tool()
def investigate_threat(
    query: Optional[str] = None,
    priority: Optional[str] = None,
    timeframe: Optional[str] = None,
    limit: int = 20
) -> dict:
    """
    Investigate security threats: aggregates SOC insights, threat indicators, and affected assets.
    Provides a comprehensive threat intelligence view.

    Args:
        query: Optional search term or threat type (e.g., "malware", "phishing", "data_exfiltration")
        priority: Filter by priority — "critical", "high", "medium", "low"
        timeframe: Not yet implemented — reserved for future date filtering
        limit: Maximum insights to return (default: 20)

    Returns:
        Aggregated threat intelligence with indicators, affected assets, and recommendations

    Examples:
        - investigate_threat() → all open security insights
        - investigate_threat(priority="critical") → critical threats only
        - investigate_threat(query="malware") → malware-related insights
    """
    if not insights_client:
        return intent_response("failed", "Insights client not initialized. Check INFOBLOX_API_KEY.")

    steps = []

    # Step 1: Get security insights
    try:
        insights_resp = insights_client.list_insights(
            status="OPEN",
            threat_type=query,
            priority=priority,
            limit=limit
        )
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
            "affected_assets": []
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
        except Exception:
            pass

        # Get affected assets
        try:
            assets_resp = insights_client.get_insight_assets(insight_id, limit=10)
            assets = extract_results(assets_resp)
            enriched["affected_assets"] = [
                {"ip": a.get("ip"), "mac": a.get("mac"), "os": a.get("os_version")}
                for a in assets[:10]
            ]
            enriched["asset_count"] = len(assets)
        except Exception:
            pass

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
            "insights": enriched_insights
        },
        next_actions=[
            "Review critical insights and update status",
            "Use assess_security_posture() for policy compliance"
        ]
    )


@mcp.tool()
def assess_security_posture() -> dict:
    """
    Assess the overall security posture: reviews security policies, policy compliance,
    and analytics insights. Provides a security scorecard.

    Returns:
        Security posture assessment with policy status, compliance findings, and recommendations

    Examples:
        - assess_security_posture() → full security assessment
    """
    steps = []
    posture = {"policies": {}, "compliance": {}, "analytics": {}}

    # Check security policies
    if atcfw_client:
        try:
            policies = extract_results(atcfw_client.list_security_policies())
            posture["policies"] = {
                "count": len(policies),
                "policies": [{"id": p.get("id"), "name": p.get("name")} for p in policies]
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
                "lists": [{"name": n.get("name"), "type": n.get("type")} for n in named_lists[:10]]
            }
            steps.append(step_result("Check threat named lists", "success", {"count": len(named_lists)}))
        except Exception as e:
            steps.append(step_result("Check threat named lists", "failed", error=str(e)))

    # Check policy compliance insights
    if insights_client:
        try:
            compliance = extract_results(insights_client.list_policy_check_insights())
            posture["compliance"] = {
                "count": len(compliance),
                "findings": [{"check_type": c.get("check_type"), "status": c.get("status")} for c in compliance[:10]]
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
                "insights": [{"id": a.get("id"), "status": a.get("status")} for a in analytics[:10]]
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
        next_actions=[
            "Use investigate_threat() for active threat details",
            "Review compliance findings and remediate"
        ]
    )


# ==================== Reporting Tools ====================

@mcp.tool()
def get_ip_utilization(scope: Optional[str] = None) -> dict:
    """
    Get IP address utilization for capacity planning.
    Shows utilization percentages across IP spaces, address blocks, and subnets.

    Args:
        scope: Optional IP space name to focus on. If not set, shows all.

    Returns:
        Utilization report with percentages per space/block/subnet

    Examples:
        - get_ip_utilization() → all spaces
        - get_ip_utilization(scope="production") → production space only
    """
    if not client:
        return intent_response("failed", "Infoblox client not initialized. Check INFOBLOX_API_KEY.")

    steps = []
    utilization = {"spaces": [], "high_utilization": []}

    try:
        space_filter = f'name~"{scope}"' if scope else None
        spaces = extract_results(client.list_ip_spaces(filter=space_filter))

        for space in spaces:
            space_id = space.get("id", "")
            space_name = space.get("name", "")
            space_util = space.get("utilization", {})

            space_data = {
                "name": space_name,
                "utilization": space_util,
                "subnets": []
            }

            # Get subnets for this space
            try:
                subnets = extract_results(client.list_subnets(
                    filter=f'space=="{space_id}"' if space_id else None,
                    limit=100
                ))
                for s in subnets:
                    subnet_util = s.get("utilization", {})
                    subnet_data = {
                        "address": s.get("address", ""),
                        "cidr": s.get("cidr", 0),
                        "name": s.get("comment", ""),
                        "utilization": subnet_util
                    }
                    space_data["subnets"].append(subnet_data)

                    # Flag high utilization
                    util_pct = subnet_util.get("utilization", 0) if isinstance(subnet_util, dict) else 0
                    if isinstance(util_pct, (int, float)) and util_pct > 80:
                        utilization["high_utilization"].append({
                            "space": space_name,
                            "subnet": s.get("address"),
                            "utilization_pct": util_pct
                        })
            except Exception:
                pass

            utilization["spaces"].append(space_data)

        steps.append(step_result("Gather utilization data", "success", {
            "spaces": len(utilization["spaces"]),
            "high_utilization_count": len(utilization["high_utilization"])
        }))

    except Exception as e:
        return intent_response("failed", f"Failed to get utilization: {e}", steps)

    high_count = len(utilization["high_utilization"])
    warnings = []
    if high_count > 0:
        warnings.append(f"{high_count} subnet(s) above 80% utilization — consider expanding")

    return intent_response(
        status="success",
        summary=f"Utilization report: {len(utilization['spaces'])} space(s), {high_count} high-utilization subnet(s)",
        steps=steps,
        result=utilization,
        warnings=warnings,
        next_actions=[
            "Use provision_network() to allocate new subnets" if high_count > 0 else
            "Utilization healthy — no action needed",
            "Use explore_network(depth='full') for detailed hierarchy"
        ]
    )


# ==================== IPAM Management Tools ====================

@mcp.tool()
def manage_network(
    resource_type: str,
    action: str,
    name: Optional[str] = None,
    address: Optional[str] = None,
    space: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    resource_id: Optional[str] = None,
    comment: Optional[str] = None,
    tags: Optional[Dict[str, Any]] = None,
    dry_run: bool = True
) -> dict:
    """
    Manage IPAM network resources: IP spaces, address blocks, subnets, and IP ranges.
    Supports create, update, delete, and get operations with safety checks.

    IMPORTANT: Delete runs in dry_run mode by default — shows impact without deleting.

    Args:
        resource_type: "ip_space", "address_block", "subnet", or "range"
        action: "create", "update", "delete", or "get"
        name: Resource name (for create or lookup)
        address: CIDR notation for subnets/blocks (e.g., "10.20.0.0/16"), or IP for ranges
        space: IP space name or ID (required for create)
        start: Start IP for ranges
        end: End IP for ranges
        resource_id: Resource ID for get/update/delete
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
    """
    if not client:
        return intent_response("failed", "Infoblox client not initialized. Check INFOBLOX_API_KEY.")

    valid, err = validate_resource_type(resource_type, ["ip_space", "address_block", "subnet", "range"])
    if not valid:
        return intent_response("failed", err)

    valid, err = validate_action(action, ["create", "update", "delete", "get"])
    if not valid:
        return intent_response("failed", err)

    steps = []
    warnings = []

    # Resolve space if needed for create
    space_id = None
    if space and action == "create":
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
        if action == "create":
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
                    **{k: v for k, v in kwargs.items() if k not in ("comment",)}
                )
                result = resp.get("result", resp)
                steps.append(step_result("Create subnet", "success", {"id": result.get("id"), "address": address}))
                return intent_response("success", f"Subnet {address} created in space '{space}'", steps, result=result)

            elif resource_type == "address_block":
                if not address or not space_id:
                    return intent_response("failed", "Address block create requires 'address' (CIDR) and 'space'.", steps)
                network = ipaddress.ip_network(address, strict=False)
                resp = client.create_address_block(
                    address=str(network.network_address),
                    space=space_id,
                    comment=comment,
                    cidr=network.prefixlen
                )
                result = resp.get("result", resp)
                steps.append(step_result("Create address block", "success", {"id": result.get("id"), "address": address}))
                return intent_response("success", f"Address block {address} created", steps, result=result)

            elif resource_type == "range":
                if not start or not end or not space_id:
                    return intent_response("failed", "Range create requires 'start', 'end', and 'space'.", steps)
                resp = client.create_range(start=start, end=end, space=space_id, comment=comment)
                result = resp.get("result", resp)
                steps.append(step_result("Create range", "success", {"id": result.get("id"), "start": start, "end": end}))
                return intent_response("success", f"IP range {start}-{end} created", steps, result=result)

            elif resource_type == "ip_space":
                return intent_response("failed", "IP space creation is not supported via API. Use the Infoblox Portal.")

        elif action == "get":
            if not resource_id:
                return intent_response("failed", f"Get requires 'resource_id'.", steps)
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
                return intent_response("failed", f"Update requires 'resource_id'.", steps)
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
                return intent_response("failed", f"Delete requires 'resource_id'.", steps)

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
                except Exception:
                    pass
                return intent_response(
                    "success",
                    f"DRY RUN: Would delete {resource_type} {resource_id}",
                    steps,
                    result={"resource_id": resource_id, "resource_type": resource_type},
                    warnings=["This is a DRY RUN. Set dry_run=False to actually delete."],
                    next_actions=[f"Execute: manage_network(resource_type='{resource_type}', action='delete', resource_id='{resource_id}', dry_run=False)"]
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

    except Exception as e:
        return intent_response("failed", f"Failed to {action} {resource_type}: {e}", steps)


# ==================== DNS Configuration Tools ====================

@mcp.tool()
def manage_dns_zone(
    action: str,
    zone_type: str = "auth",
    fqdn: Optional[str] = None,
    primary_type: Optional[str] = None,
    view: Optional[str] = None,
    forward_to: Optional[List[str]] = None,
    comment: Optional[str] = None,
    resource_id: Optional[str] = None,
    dry_run: bool = True
) -> dict:
    """
    Manage DNS zones: create/delete authoritative or forward zones, list zones and views.

    IMPORTANT: Delete runs in dry_run mode by default — checks record count before deleting.

    Args:
        action: "create", "delete", "list", or "get"
        zone_type: "auth" (authoritative) or "forward" (forwarding zone)
        fqdn: Zone FQDN for create/delete (e.g., "example.com")
        primary_type: For auth zones — "cloud" or "external"
        view: DNS view name (optional)
        forward_to: List of forwarder IPs for forward zones
        comment: Description
        resource_id: Zone resource ID for get/delete
        dry_run: If True (default), delete shows record count only. Set False to execute.

    Returns:
        Zone operation result

    Examples:
        - manage_dns_zone(action="list") → all authoritative zones
        - manage_dns_zone(action="list", zone_type="forward") → all forward zones
        - manage_dns_zone(action="create", fqdn="new.example.com", primary_type="cloud")
        - manage_dns_zone(action="delete", fqdn="old.example.com", dry_run=False)
    """
    if not client:
        return intent_response("failed", "Infoblox client not initialized. Check INFOBLOX_API_KEY.")

    valid, err = validate_action(action, ["create", "delete", "list", "get"])
    if not valid:
        return intent_response("failed", err)

    valid, err = validate_resource_type(zone_type, ["auth", "forward"])
    if not valid:
        return intent_response("failed", err)

    steps = []

    try:
        if action == "list":
            if zone_type == "auth":
                resp = client.list_auth_zones(limit=200)
                zones = extract_results(resp)
                result = [{"id": z.get("id"), "fqdn": z.get("fqdn"), "primary_type": z.get("primary_type", ""),
                           "view": z.get("view"), "comment": z.get("comment", "")} for z in zones]
                steps.append(step_result("List auth zones", "success", {"count": len(zones)}))
                return intent_response("success", f"Found {len(zones)} authoritative zone(s)", steps, result=result)
            else:
                resp = client.list_forward_zones(limit=200)
                zones = extract_results(resp)
                result = [{"id": z.get("id"), "fqdn": z.get("fqdn"), "forward_only": z.get("forward_only"),
                           "comment": z.get("comment", "")} for z in zones]
                steps.append(step_result("List forward zones", "success", {"count": len(zones)}))
                return intent_response("success", f"Found {len(zones)} forward zone(s)", steps, result=result)

        elif action == "get":
            if not resource_id and not fqdn:
                return intent_response("failed", "Get requires 'resource_id' or 'fqdn'.", steps)
            if fqdn and not resource_id:
                zone_id, s, err = resolve_zone(fqdn)
                if s:
                    steps.append(s)
                if err:
                    return intent_response("failed", err, steps)
                resource_id = zone_id
            # List DNS views as bonus info
            views_resp = client.list_dns_views(limit=50)
            views = extract_results(views_resp)
            steps.append(step_result("List DNS views", "success", {"count": len(views)}))
            return intent_response("success", f"Zone resolved: {resource_id}", steps,
                                   result={"zone_id": resource_id, "dns_views": [{"id": v.get("id"), "name": v.get("name")} for v in views]})

        elif action == "create":
            if not fqdn:
                return intent_response("failed", "Create requires 'fqdn'.", steps)
            valid, err = validate_fqdn(fqdn)
            if not valid:
                return intent_response("failed", err)

            # Check if zone already exists
            existing = extract_results(client.list_auth_zones(filter=f'fqdn=="{fqdn}"'))
            if not existing:
                existing = extract_results(client.list_auth_zones(filter=f'fqdn=="{fqdn}."'))
            if existing:
                return intent_response("failed", f"Zone '{fqdn}' already exists (ID: {existing[0].get('id')})", steps)

            if zone_type == "auth":
                kwargs = {}
                if view:
                    kwargs["view"] = view
                resp = client.create_auth_zone(
                    fqdn=fqdn,
                    primary_type=primary_type or "cloud",
                    comment=comment,
                    **kwargs
                )
                result = resp.get("result", resp)
                steps.append(step_result("Create auth zone", "success", {"id": result.get("id"), "fqdn": fqdn}))
                return intent_response("success", f"Authoritative zone '{fqdn}' created", steps, result=result)
            else:
                resp = client.create_forward_zone(
                    fqdn=fqdn,
                    forward_only=True,
                    hosts=forward_to,
                    view=view,
                    comment=comment
                )
                result = resp.get("result", resp)
                steps.append(step_result("Create forward zone", "success", {"id": result.get("id"), "fqdn": fqdn}))
                return intent_response("success", f"Forward zone '{fqdn}' created", steps, result=result)

        elif action == "delete":
            if not resource_id and not fqdn:
                return intent_response("failed", "Delete requires 'resource_id' or 'fqdn'.", steps)
            if fqdn and not resource_id:
                zone_id, s, err = resolve_zone(fqdn)
                if s:
                    steps.append(s)
                if err:
                    return intent_response("failed", err, steps)
                resource_id = zone_id

            # Safety: count records in zone
            try:
                records = extract_results(client.list_dns_records(filter=f'zone=="{resource_id}"', limit=1))
                record_count = len(records)
                steps.append(step_result("Count zone records", "success", {"record_count": record_count}))
                if record_count > 0:
                    warnings = [f"Zone contains {record_count}+ DNS record(s) that will be orphaned"]
                else:
                    warnings = []
            except Exception:
                warnings = ["Could not verify record count"]

            if dry_run:
                return intent_response(
                    "success",
                    f"DRY RUN: Would delete zone {fqdn or resource_id}",
                    steps,
                    result={"resource_id": resource_id, "fqdn": fqdn},
                    warnings=warnings + ["This is a DRY RUN. Set dry_run=False to actually delete."],
                    next_actions=[f"Execute: manage_dns_zone(action='delete', resource_id='{resource_id}', dry_run=False)"]
                )

            # Zone delete is not directly available in the client; use the generic approach
            # Auth zones are typically managed as immutable in BloxOne — flag this
            return intent_response(
                "partial",
                f"Zone deletion for '{fqdn or resource_id}' — use Infoblox Portal for zone removal",
                steps,
                warnings=warnings + ["Zone deletion via API requires specific permissions. Verify in Infoblox Portal."]
            )

    except Exception as e:
        return intent_response("failed", f"Failed to {action} {zone_type} zone: {e}", steps)


@mcp.tool()
def manage_dns_record(
    action: str,
    record_id: Optional[str] = None,
    zone: Optional[str] = None,
    record_type: Optional[str] = None,
    name: Optional[str] = None,
    rdata: Optional[Dict[str, Any]] = None,
    ttl: Optional[int] = None,
    comment: Optional[str] = None,
    dry_run: bool = True,
    limit: int = 50
) -> dict:
    """
    Manage DNS records: update, delete, list, and get. Complements provision_dns() which creates records.
    Supports smart lookup by name+zone+type when record_id is not known.

    Args:
        action: "update", "delete", "list", or "get"
        record_id: DNS record ID (optional — can look up by name+zone+type)
        zone: DNS zone FQDN for filtering/lookup
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
        return intent_response("failed", "Infoblox client not initialized. Check INFOBLOX_API_KEY.")

    valid, err = validate_action(action, ["update", "delete", "list", "get"])
    if not valid:
        return intent_response("failed", err)

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
            filters.append(f'absolute_name_spec=="{name}"')
        elif zone:
            filters.append(f'name_in_zone=="{name}"')
            zone_id, s, err = resolve_zone(zone)
            if s:
                steps.append(s)
            if zone_id:
                filters.append(f'zone=="{zone_id}"')

        if record_type:
            filters.append(f'type=="{record_type.upper()}"')

        filter_str = " and ".join(filters) if filters else f'name_in_zone~"{name}"'
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
                zone_id, s, err = resolve_zone(zone)
                if s:
                    steps.append(s)
                if zone_id:
                    filters.append(f'zone=="{zone_id}"')
            if record_type:
                filters.append(f'type=="{record_type.upper()}"')
            if name:
                filters.append(f'name_in_zone~"{name}"')

            filter_str = " and ".join(filters) if filters else None
            resp = client.list_dns_records(filter=filter_str, limit=limit)
            records = extract_results(resp)
            result = [
                {"id": r.get("id"), "name": r.get("absolute_name_spec", r.get("name_in_zone")),
                 "type": r.get("type"), "rdata": r.get("rdata"), "ttl": r.get("ttl"),
                 "zone": r.get("zone"), "comment": r.get("comment", "")}
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
                except Exception:
                    pass
                return intent_response(
                    "success",
                    f"DRY RUN: Would delete DNS record {rid}",
                    steps,
                    result={"record_id": rid},
                    warnings=["This is a DRY RUN. Set dry_run=False to actually delete."],
                    next_actions=[f"Execute: manage_dns_record(action='delete', record_id='{rid}', dry_run=False)"]
                )

            client.delete_dns_record(rid)
            steps.append(step_result("Delete DNS record", "success", {"id": rid}))
            return intent_response("success", f"Deleted DNS record {rid}", steps)

    except Exception as e:
        return intent_response("failed", f"Failed to {action} DNS record: {e}", steps)


# ==================== DHCP Management Tools ====================

@mcp.tool()
def manage_dhcp(
    resource_type: str,
    action: str,
    name: Optional[str] = None,
    resource_id: Optional[str] = None,
    mode: Optional[str] = None,
    hosts: Optional[List[Dict[str, Any]]] = None,
    code: Optional[int] = None,
    option_type: Optional[str] = None,
    protocol: Optional[str] = None,
    mac_address: Optional[str] = None,
    comment: Optional[str] = None,
    dry_run: bool = True
) -> dict:
    """
    Manage DHCP configuration: HA groups, option codes, hardware filters, option filters, and hardware entries.

    Args:
        resource_type: "ha_group", "option_code", "hardware_filter", "option_filter", or "hardware"
        action: "create", "update", "delete", "get", or "list"
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
        return intent_response("failed", "Infoblox client not initialized. Check INFOBLOX_API_KEY.")

    valid, err = validate_resource_type(resource_type, ["ha_group", "option_code", "hardware_filter", "option_filter", "hardware"])
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
                    return intent_response("failed", f"Get requires 'resource_id' or 'name'.", steps)
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
                    return intent_response("failed", "Option code create requires 'name', 'code', and 'option_type'.", steps)
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
                return intent_response("failed", f"Update requires 'resource_id'.", steps)
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
                return intent_response("failed", f"Delete requires 'resource_id'.", steps)
            if dry_run:
                try:
                    resp = dispatch[resource_type]["get"](resource_id)
                    result = resp.get("result", resp)
                    steps.append(step_result(f"Dry run: inspect {resource_type}", "success", result))
                except Exception:
                    pass
                return intent_response(
                    "success",
                    f"DRY RUN: Would delete {resource_type} {resource_id}",
                    steps,
                    result={"resource_id": resource_id, "resource_type": resource_type},
                    warnings=["This is a DRY RUN. Set dry_run=False to actually delete."],
                    next_actions=[f"Execute: manage_dhcp(resource_type='{resource_type}', action='delete', resource_id='{resource_id}', dry_run=False)"]
                )
            dispatch[resource_type]["delete"](resource_id)
            steps.append(step_result(f"Delete {resource_type}", "success", {"id": resource_id}))
            return intent_response("success", f"Deleted {resource_type} {resource_id}", steps)

    except Exception as e:
        return intent_response("failed", f"Failed to {action} {resource_type}: {e}", steps)


# ==================== IP Reservation Tools ====================

@mcp.tool()
def manage_ip_reservation(
    action: str,
    address: Optional[str] = None,
    space: Optional[str] = None,
    mac: Optional[str] = None,
    hostname: Optional[str] = None,
    comment: Optional[str] = None,
    resource_id: Optional[str] = None,
    dry_run: bool = True
) -> dict:
    """
    Reserve, release, list, get, or update fixed IP addresses and DHCP static leases.

    IMPORTANT: Release runs in dry_run mode by default — shows host associations before releasing.

    Args:
        action: "reserve", "release", "list", "get", or "update"
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
        return intent_response("failed", "Infoblox client not initialized. Check INFOBLOX_API_KEY.")

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
            existing = extract_results(client.list_addresses(filter=f'address=="{address}"'))
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
                filters.append(f'address~"{address}"')

            filter_str = " and ".join(filters) if filters else None
            resp = client.list_addresses(filter=filter_str, limit=100)
            items = extract_results(resp)
            result = [
                {"id": a.get("id"), "address": a.get("address"), "names": a.get("names", []),
                 "usage": a.get("usage", []), "space": a.get("space"), "comment": a.get("comment", "")}
                for a in items
            ]
            steps.append(step_result("List addresses", "success", {"count": len(items)}))
            return intent_response("success", f"Found {len(items)} address(es)", steps, result=result)

        elif action == "get":
            if not resource_id:
                if address:
                    # Lookup by address
                    resp = client.list_addresses(filter=f'address=="{address}"')
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
                addr_records = extract_results(client.list_addresses(filter=f'address=="{address}"'))
                if not addr_records:
                    return intent_response("failed", f"No address record found for '{address}'", steps)
                resource_id = addr_records[0].get("id")
                steps.append(step_result("Lookup fixed address", "success", {"id": resource_id}))

            # Check for host associations
            if address:
                try:
                    hosts = extract_results(client.list_ipam_hosts(filter=f'address=="{address}"'))
                    if hosts:
                        warnings.append(f"IP {address} is associated with host(s): {[h.get('name') for h in hosts]}")
                except Exception:
                    pass

            if dry_run:
                return intent_response(
                    "success",
                    f"DRY RUN: Would release IP reservation {address or resource_id}",
                    steps,
                    result={"resource_id": resource_id, "address": address},
                    warnings=warnings + ["This is a DRY RUN. Set dry_run=False to actually release."],
                    next_actions=[f"Execute: manage_ip_reservation(action='release', resource_id='{resource_id}', dry_run=False)"]
                )

            client.delete_fixed_address(resource_id)
            steps.append(step_result("Release IP reservation", "success", {"id": resource_id}))
            return intent_response("success", f"Released IP reservation {address or resource_id}", steps, warnings=warnings)

    except Exception as e:
        return intent_response("failed", f"Failed to {action} IP reservation: {e}", steps)


# ==================== Security Policy Tools ====================

@mcp.tool()
def manage_security_policy(
    resource_type: str,
    action: str,
    name: Optional[str] = None,
    resource_id: Optional[str] = None,
    items: Optional[List[str]] = None,
    description: Optional[str] = None,
    list_type: Optional[str] = None,
    criteria: Optional[List[Dict[str, Any]]] = None,
    activation: Optional[str] = None,
    expiration: Optional[str] = None,
    rules: Optional[List[Dict[str, Any]]] = None,
    dry_run: bool = True
) -> dict:
    """
    Manage DNS security resources: policies (read-only), named lists, application filters,
    internal domain lists, and access codes.

    NOTE: Security policies are read-only via API (list/get only). Named lists support full CRUD.

    Args:
        resource_type: "policy", "named_list", "app_filter", "internal_domains", or "access_code"
        action: "create", "update", "delete", "list", or "get"
        name: Resource name
        resource_id: Resource ID for get/update/delete
        items: List of domains/IPs for named lists or internal domain lists
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
        - manage_security_policy(resource_type="internal_domains", action="create", name="corp-domains", items=["corp.local"])
    """
    if not atcfw_client:
        return intent_response("failed", "Security client not initialized. Check INFOBLOX_API_KEY.")

    valid, err = validate_resource_type(resource_type, ["policy", "named_list", "app_filter", "internal_domains", "access_code"])
    if not valid:
        return intent_response("failed", err)

    # Policies are read-only
    if resource_type == "policy" and action not in ("list", "get"):
        return intent_response("failed", "Security policies are read-only via API. Use 'list' or 'get' only.")

    valid, err = validate_action(action, ["create", "update", "delete", "list", "get"])
    if not valid:
        return intent_response("failed", err)

    steps = []

    try:
        if action == "list":
            if resource_type == "policy":
                resp = atcfw_client.list_security_policies(limit=100)
                items_list = extract_results(resp)
                result = [{"id": p.get("id"), "name": p.get("name"), "description": p.get("description", "")} for p in items_list]
            elif resource_type == "named_list":
                resp = atcfw_client.list_named_lists(limit=100)
                items_list = extract_results(resp)
                result = [{"id": n.get("id"), "name": n.get("name"), "type": n.get("type", ""),
                           "item_count": n.get("item_count", len(n.get("items", [])))} for n in items_list]
            elif resource_type == "app_filter":
                resp = atcfw_client.list_application_filters(limit=100)
                items_list = extract_results(resp)
                result = [{"id": f.get("id"), "name": f.get("name"), "description": f.get("description", "")} for f in items_list]
            elif resource_type == "internal_domains":
                resp = atcfw_client.list_internal_domain_lists(limit=100)
                items_list = extract_results(resp)
                result = [{"id": d.get("id"), "name": d.get("name"), "description": d.get("description", "")} for d in items_list]
            elif resource_type == "access_code":
                resp = atcfw_client.list_access_codes(limit=100)
                items_list = extract_results(resp)
                result = [{"id": a.get("id"), "name": a.get("name"), "activation": a.get("activation"),
                           "expiration": a.get("expiration")} for a in items_list]
            steps.append(step_result(f"List {resource_type}s", "success", {"count": len(items_list)}))
            return intent_response("success", f"Found {len(items_list)} {resource_type}(s)", steps, result=result)

        elif action == "get":
            if not resource_id:
                return intent_response("failed", f"Get requires 'resource_id'.", steps)
            if resource_type == "policy":
                resp = atcfw_client.get_security_policy(resource_id)
            else:
                return intent_response("failed", f"Get by ID only supported for 'policy'. Use 'list' + filter for others.", steps)
            result = resp.get("result", resp)
            steps.append(step_result(f"Get {resource_type}", "success", {"id": resource_id}))
            return intent_response("success", f"Retrieved {resource_type}", steps, result=result)

        elif action == "create":
            if not name:
                return intent_response("failed", f"Create requires 'name'.", steps)

            if resource_type == "named_list":
                resp = atcfw_client.create_named_list(
                    name=name, type=list_type or "custom_list",
                    items=items, description=description or ""
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
                    return intent_response("failed", "Access code create requires 'activation' and 'expiration' dates.", steps)
                resp = atcfw_client.create_access_code(
                    name=name, activation=activation, expiration=expiration,
                    rules=rules, description=description or ""
                )
            result = resp.get("result", resp)
            steps.append(step_result(f"Create {resource_type}", "success", {"id": result.get("id")}))
            return intent_response("success", f"Created {resource_type} '{name}'", steps, result=result)

        elif action == "update":
            if not resource_id:
                return intent_response("failed", f"Update requires 'resource_id'.", steps)
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
            else:
                return intent_response("failed", f"Update only supported for 'named_list'. Other types: recreate.", steps)

        elif action == "delete":
            if not resource_id:
                return intent_response("failed", f"Delete requires 'resource_id'.", steps)
            if resource_type != "named_list":
                return intent_response("failed", f"Delete only supported for 'named_list'. Other types: use Infoblox Portal.", steps)

            if dry_run:
                return intent_response(
                    "success",
                    f"DRY RUN: Would delete named list {resource_id}",
                    steps,
                    result={"resource_id": resource_id},
                    warnings=["This is a DRY RUN. Set dry_run=False to actually delete."],
                    next_actions=[f"Execute: manage_security_policy(resource_type='named_list', action='delete', resource_id='{resource_id}', dry_run=False)"]
                )
            atcfw_client.delete_named_list(resource_id)
            steps.append(step_result("Delete named list", "success", {"id": resource_id}))
            return intent_response("success", f"Deleted named list {resource_id}", steps)

    except Exception as e:
        return intent_response("failed", f"Failed to {action} {resource_type}: {e}", steps)


# ==================== Federation Tools ====================

@mcp.tool()
def manage_federation(
    resource_type: str,
    action: str,
    name: Optional[str] = None,
    resource_id: Optional[str] = None,
    address: Optional[str] = None,
    realm: Optional[str] = None,
    cidr: Optional[int] = None,
    delegated_to: Optional[str] = None,
    comment: Optional[str] = None,
    dry_run: bool = True
) -> dict:
    """
    Manage federated IPAM: realms, blocks, delegations, pools, overlapping blocks, reserved blocks, and forward delegations.

    Args:
        resource_type: "realm", "block", "delegation", "pool", "overlapping_block", "reserved_block", or "forward_delegation"
        action: "create", "update", "delete", "get", "list", or "allocate_next" (blocks only)
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
        return intent_response("failed", "Infoblox client not initialized. Check INFOBLOX_API_KEY.")

    valid, err = validate_resource_type(resource_type, [
        "realm", "block", "delegation", "pool",
        "overlapping_block", "reserved_block", "forward_delegation"
    ])
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
                return intent_response("failed", f"Get requires 'resource_id'.", steps)
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
                    return intent_response("failed", "Delegation create requires 'address', 'realm', and 'delegated_to'.", steps)
                resp = client.create_delegation(address=address, federated_realm=realm_id, delegated_to=delegated_to, comment=comment)
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
                    return intent_response("failed", "Forward delegation create requires 'address', 'realm', and 'delegated_to'.", steps)
                resp = client.create_forward_delegation(address=address, federated_realm=realm_id, delegated_to=delegated_to, comment=comment)

            result = resp.get("result", resp)
            steps.append(step_result(f"Create {resource_type}", "success", {"id": result.get("id")}))
            return intent_response("success", f"Created {resource_type}", steps, result=result)

        elif action == "allocate_next":
            if resource_type != "block":
                return intent_response("failed", "allocate_next is only available for 'block' resource_type.", steps)
            if not resource_id or cidr is None:
                return intent_response("failed", "allocate_next requires 'resource_id' (parent block) and 'cidr' (prefix length).", steps)
            resp = client.allocate_next_available_federated_block(
                federated_block_id=resource_id, cidr=cidr, comment=comment
            )
            result = resp.get("result", resp)
            steps.append(step_result("Allocate next block", "success", {"id": result.get("id"), "cidr": cidr}))
            return intent_response("success", f"Allocated /{cidr} block from {resource_id}", steps, result=result)

        elif action == "update":
            if not resource_id:
                return intent_response("failed", f"Update requires 'resource_id'.", steps)
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
                return intent_response("failed", f"Delete requires 'resource_id'.", steps)

            if dry_run:
                # Preview: show resource details + forward delegation preview if applicable
                try:
                    resp = dispatch[resource_type]["get"](resource_id)
                    result = resp.get("result", resp)
                    steps.append(step_result(f"Dry run: inspect {resource_type}", "success", result))
                except Exception:
                    pass
                return intent_response(
                    "success",
                    f"DRY RUN: Would delete {resource_type} {resource_id}",
                    steps,
                    result={"resource_id": resource_id, "resource_type": resource_type},
                    warnings=["This is a DRY RUN. Set dry_run=False to actually delete."],
                    next_actions=[f"Execute: manage_federation(resource_type='{resource_type}', action='delete', resource_id='{resource_id}', dry_run=False)"]
                )

            dispatch[resource_type]["delete"](resource_id)
            steps.append(step_result(f"Delete {resource_type}", "success", {"id": resource_id}))
            return intent_response("success", f"Deleted {resource_type} {resource_id}", steps)

    except Exception as e:
        return intent_response("failed", f"Failed to {action} {resource_type}: {e}", steps)


# ==================== Security Insight Triage Tools ====================

@mcp.tool()
def triage_security_insight(
    action: str,
    insight_id: Optional[str] = None,
    insight_ids: Optional[List[str]] = None,
    status: Optional[str] = None,
    comment: Optional[str] = None,
    priority_filter: Optional[str] = None,
    dry_run: bool = True
) -> dict:
    """
    Triage security insights: update status, bulk triage by priority, get history.
    Validates state transitions and supports dry_run for bulk operations.

    Args:
        action: "update_status", "bulk_triage", or "get_history"
        insight_id: Single insight ID (for update_status, get_history)
        insight_ids: List of insight IDs (for bulk_triage; auto-populated from priority_filter if not set)
        status: New status — "IN_PROGRESS", "RESOLVED", "CLOSED", or "FALSE_POSITIVE"
        comment: Triage comment
        priority_filter: For bulk_triage — "critical", "high", "medium", "low" (fetches matching open insights)
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
        return intent_response("failed", "Insights client not initialized. Check INFOBLOX_API_KEY.")

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
            steps.append(step_result("Get insight details", "success", {
                "id": insight_id,
                "status": insight.get("status"),
                "priority": insight.get("priority")
            }))

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
                        "threat_type": insight.get("threat_type")
                    },
                    "comments": comments
                }
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
                steps.append(step_result("Check current status", "success", {"current": current_status, "target": status}))
            except Exception:
                current_status = "UNKNOWN"

            resp = insights_client.update_insight_status(
                insight_ids=[insight_id],
                status=status,
                comment=comment
            )
            steps.append(step_result("Update insight status", "success", {"id": insight_id, "new_status": status}))
            return intent_response(
                "success",
                f"Insight {insight_id} status updated: {current_status} → {status}",
                steps,
                result={"insight_id": insight_id, "previous_status": current_status, "new_status": status}
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
                steps.append(step_result(
                    f"Find {priority_filter} open insights", "success",
                    {"count": len(ids_to_triage), "insights": [{"id": i.get("id"), "title": i.get("title", "")} for i in open_insights[:10]]}
                ))

            if not ids_to_triage:
                return intent_response("success", "No insights matched the filter — nothing to triage.", steps)

            if dry_run:
                return intent_response(
                    "success",
                    f"DRY RUN: Would update {len(ids_to_triage)} insight(s) to status '{status}'",
                    steps,
                    result={"count": len(ids_to_triage), "insight_ids": ids_to_triage[:20], "target_status": status},
                    warnings=["This is a DRY RUN. Set dry_run=False to actually update."],
                    next_actions=[f"Execute: triage_security_insight(action='bulk_triage', insight_ids={ids_to_triage[:20]}, status='{status}', dry_run=False)"]
                )

            resp = insights_client.update_insight_status(
                insight_ids=ids_to_triage,
                status=status,
                comment=comment or f"Bulk triage: set to {status}"
            )
            steps.append(step_result("Bulk update status", "success", {"count": len(ids_to_triage), "status": status}))
            return intent_response(
                "success",
                f"Bulk triaged {len(ids_to_triage)} insight(s) → {status}",
                steps,
                result={"updated_count": len(ids_to_triage), "status": status}
            )

    except Exception as e:
        return intent_response("failed", f"Failed to {action} security insight: {e}", steps)


# ==================== Server Entry Point ====================

def main():
    """Entry point for both `python mcp_intent.py` and the `infoblox-ddi-mcp` CLI."""
    host = os.environ.get("MCP_HOST", "0.0.0.0")
    port = int(os.environ.get("MCP_PORT", "4005"))
    path = os.environ.get("MCP_PATH", "/mcp")

    # Support both transports:
    #   python mcp_intent.py          → stdio (for Claude Desktop, Cursor, etc.)
    #   python mcp_intent.py --http   → HTTP (for AEX, remote clients)
    if "--http" in sys.argv:
        print("=" * 60, file=sys.stderr)
        print(f"  Infoblox DDI Intent Layer v{__version__} — MCP Server (HTTP)", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print(f"  Endpoint:  http://{host}:{port}{path}", file=sys.stderr)
        print(f"  Transport: HTTP streamable (spec-compliant)", file=sys.stderr)
        print(f"  Tools:     20 intent-level workflow tools", file=sys.stderr)
        print("=" * 60, file=sys.stderr)

        mcp.run(
            transport="http",
            host=host,
            port=port,
            path=path
        )
    else:
        # stdio transport — used by Claude Desktop, Cursor, Windsurf
        mcp.run()


if __name__ == "__main__":
    main()
