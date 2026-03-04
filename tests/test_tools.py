"""Tests for all 20 MCP tools via FastMCP Client (~60 tests).

Each tool gets 2-4 tests:
  1. Happy path with mocked API responses
  2. Client not initialised (None)
  3. For manage_* tools: invalid action/resource_type
  4. For destructive tools: dry_run=True behaviour
"""

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from tests.conftest import parse_tool_result

# ── helpers ──────────────────────────────────────────────────────────


def _api(results: list | dict = ()) -> dict:
    """Shortcut to build a BloxOne-style response."""
    if isinstance(results, dict):
        return results
    return {"results": list(results)}


SPACE = {"id": "ipam/ip_space/1", "name": "prod", "comment": "", "utilization": {}}
SUBNET = {"id": "ipam/subnet/1", "address": "10.0.0.0", "cidr": 24, "name": "web", "space": "ipam/ip_space/1"}
ZONE = {"id": "dns/auth_zone/1", "fqdn": "example.com.", "view": "default", "primary_type": "cloud", "comment": ""}
RECORD = {
    "id": "dns/record/1",
    "absolute_name_spec": "www.example.com",
    "type": "A",
    "rdata": {"address": "10.0.0.1"},
    "zone": "dns/auth_zone/1",
    "name_in_zone": "www",
}
HOST = {"id": "ipam/host/1", "name": "web-01", "addresses": [{"address": "10.0.0.1"}], "comment": ""}
ADDR = {"id": "ipam/address/1", "address": "10.0.0.1", "names": [], "space": "ipam/ip_space/1", "usage": []}
HA_GROUP = {"id": "dhcp/ha_group/1", "name": "ha-1", "mode": "active-active"}
DHCP_HOST = {"id": "dhcp/host/1", "name": "dhcp-1"}
INSIGHT = {
    "id": "insight/1",
    "threat_type": "malware",
    "priority": "critical",
    "status": "OPEN",
    "title": "Malware detected",
}
POLICY = {"id": "atcfw/policy/1", "name": "default-policy"}
NAMED_LIST = {"id": "atcfw/named_list/1", "name": "blocklist", "items_described": []}
BLOCK = {"id": "ipam/address_block/1", "address": "10.0.0.0", "cidr": 16, "name": "main"}
REALM = {"id": "federation/realm/1", "name": "us-east"}


# ═══════════════════════════════════════════════════════════════════
# Discovery & Exploration
# ═══════════════════════════════════════════════════════════════════


class TestExploreNetwork:
    async def test_happy_path(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("explore_network"))
        assert r["status"] == "success"
        assert len(r["result"]["ip_spaces"]) == 1

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("explore_network"))
        assert r["status"] == "failed"


class TestSearchInfrastructure:
    async def test_happy_path(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_auth_zones.return_value = _api([ZONE])
        mock_infoblox_client.list_subnets.return_value = _api([SUBNET])
        mock_infoblox_client.list_dns_records.return_value = _api([RECORD])
        mock_infoblox_client.list_ipam_hosts.return_value = _api([HOST])
        mock_infoblox_client.list_addresses.return_value = _api([ADDR])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("search_infrastructure", {"query": "10.0.0"}))
        assert r["status"] == "success"
        assert "Found" in r["summary"]

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("search_infrastructure", {"query": "x"}))
        assert r["status"] == "failed"


class TestGetNetworkSummary:
    async def test_happy_path(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        mock_infoblox_client.list_subnets.return_value = _api([SUBNET])
        mock_infoblox_client.list_address_blocks.return_value = _api([BLOCK])
        mock_infoblox_client.list_auth_zones.return_value = _api([ZONE])
        mock_infoblox_client.list_dhcp_hosts.return_value = _api([DHCP_HOST])
        mock_infoblox_client.list_ha_groups.return_value = _api([HA_GROUP])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("get_network_summary"))
        assert r["status"] == "success"
        assert "ip_spaces" in r["result"]

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("get_network_summary"))
        assert r["status"] == "failed"


# ═══════════════════════════════════════════════════════════════════
# Provisioning
# ═══════════════════════════════════════════════════════════════════


class TestProvisionHost:
    async def test_happy_path(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        mock_infoblox_client.create_ipam_host.return_value = {"result": {"id": "ipam/host/new"}}
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "provision_host", {"hostname": "web-01", "space": "prod", "ip": "10.0.0.5", "dry_run": False}
                )
            )
        assert r["status"] == "success"

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("provision_host", {"hostname": "x", "space": "prod"}))
        assert r["status"] == "failed"

    async def test_auto_ip_single_subnet(self, mcp_server, mock_infoblox_client):
        """No IP provided, single subnet in space → auto-assigns from nextavailableip."""
        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        mock_infoblox_client.list_subnets.return_value = _api([SUBNET])
        mock_infoblox_client.get_next_available_ip.return_value = ["10.0.0.42"]
        mock_infoblox_client.create_ipam_host.return_value = {
            "result": {"id": "ipam/host/new", "addresses": [{"address": "10.0.0.42"}]}
        }
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool("provision_host", {"hostname": "web-01", "space": "prod", "dry_run": False})
            )
        assert r["status"] == "success"
        assert any(s["step"] == "Auto-assign IP" and s["result"]["ip"] == "10.0.0.42" for s in r["steps"])

    async def test_auto_ip_with_subnet(self, mcp_server, mock_infoblox_client):
        """No IP, multiple subnets, subnet specified → picks correct one."""
        subnet2 = {"id": "ipam/subnet/2", "address": "10.1.0.0", "cidr": 24, "name": "db", "space": "ipam/ip_space/1"}
        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        mock_infoblox_client.list_subnets.return_value = _api([SUBNET, subnet2])
        mock_infoblox_client.get_next_available_ip.return_value = ["10.1.0.10"]
        mock_infoblox_client.create_ipam_host.return_value = {
            "result": {"id": "ipam/host/new", "addresses": [{"address": "10.1.0.10"}]}
        }
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "provision_host",
                    {"hostname": "db-01", "space": "prod", "subnet": "10.1.0.0/24", "dry_run": False},
                )
            )
        assert r["status"] == "success"
        mock_infoblox_client.get_next_available_ip.assert_called_once_with("ipam/subnet/2")

    async def test_auto_ip_ambiguous_subnet(self, mcp_server, mock_infoblox_client):
        """No IP, multiple subnets, no subnet specified → error listing subnets."""
        subnet2 = {"id": "ipam/subnet/2", "address": "10.1.0.0", "cidr": 24, "name": "db", "space": "ipam/ip_space/1"}
        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        mock_infoblox_client.list_subnets.return_value = _api([SUBNET, subnet2])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("provision_host", {"hostname": "db-01", "space": "prod"}))
        assert r["status"] == "failed"
        assert "Multiple subnets" in r["summary"]

    async def test_auto_dns_with_zone(self, mcp_server, mock_infoblox_client):
        """auto_dns=True (default) with zone → passes auto_generate_records to host creation."""
        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        mock_infoblox_client.list_auth_zones.return_value = _api([ZONE])
        mock_infoblox_client.create_ipam_host.return_value = {
            "result": {"id": "ipam/host/new", "addresses": [{"address": "10.0.0.5"}]}
        }
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "provision_host",
                    {"hostname": "web-01", "space": "prod", "ip": "10.0.0.5", "zone": "example.com", "dry_run": False},
                )
            )
        assert r["status"] == "success"
        # Verify create_ipam_host was called with auto_generate_records and host_names
        call_kwargs = mock_infoblox_client.create_ipam_host.call_args.kwargs
        assert call_kwargs["auto_generate_records"] is True
        assert call_kwargs["host_names"] == [{"name": "web-01", "zone": ZONE["id"], "primary_name": True}]
        # No separate DNS record creation calls
        mock_infoblox_client.create_dns_record.assert_not_called()

    async def test_manual_dns_with_view(self, mcp_server, mock_infoblox_client):
        """auto_dns=False with view → creates DNS records as separate API calls."""
        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        mock_infoblox_client.create_ipam_host.return_value = {
            "result": {"id": "ipam/host/new", "addresses": [{"address": "10.0.0.5"}]}
        }
        mock_infoblox_client.list_dns_views.return_value = _api([{"id": "dns/view/default", "name": "default"}])
        mock_infoblox_client.list_auth_zones.return_value = _api(
            [
                {"id": "dns/auth_zone/azure", "fqdn": "example.com.", "view": "dns/view/azure"},
                {"id": "dns/auth_zone/default", "fqdn": "example.com.", "view": "dns/view/default"},
            ]
        )
        mock_infoblox_client.create_dns_record.return_value = {"result": {"id": "dns/record/new"}}
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "provision_host",
                    {
                        "hostname": "web-01",
                        "space": "prod",
                        "ip": "10.0.0.5",
                        "zone": "example.com",
                        "view": "default",
                        "auto_dns": False,
                        "dry_run": False,
                    },
                )
            )
        assert r["status"] == "success"
        # Verify create_ipam_host was NOT called with auto_generate_records
        call_kwargs = mock_infoblox_client.create_ipam_host.call_args.kwargs
        assert "auto_generate_records" not in call_kwargs
        # Verify the A record create_dns_record call used the correct view-specific zone ID
        a_record_call = mock_infoblox_client.create_dns_record.call_args_list[0]
        assert a_record_call.kwargs.get("zone") == "dns/auth_zone/default"

    async def test_ambiguous_zone_no_view(self, mcp_server, mock_infoblox_client):
        """provision_host with zone in multiple views and no view specified → warns about ambiguity."""
        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        mock_infoblox_client.create_ipam_host.return_value = {
            "result": {"id": "ipam/host/new", "addresses": [{"address": "10.0.0.5"}]}
        }
        mock_infoblox_client.list_auth_zones.return_value = _api(
            [
                {"id": "dns/auth_zone/1", "fqdn": "example.com.", "view": "dns/view/azure"},
                {"id": "dns/auth_zone/2", "fqdn": "example.com.", "view": "dns/view/default"},
            ]
        )
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "provision_host",
                    {"hostname": "web-01", "space": "prod", "ip": "10.0.0.5", "zone": "example.com", "dry_run": False},
                )
            )
        # Host creation succeeds but DNS A record is skipped due to ambiguous zone
        assert any("disambiguate" in w for w in r.get("warnings", []))


class TestProvisionDns:
    async def test_happy_path(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_auth_zones.return_value = _api([ZONE])
        mock_infoblox_client.create_dns_record.return_value = {"result": {"id": "dns/record/new"}}
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "provision_dns",
                    {"name": "www", "record_type": "A", "value": "10.0.0.1", "zone": "example.com", "dry_run": False},
                )
            )
        assert r["status"] == "success"

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "provision_dns", {"name": "www", "record_type": "A", "value": "10.0.0.1", "zone": "example.com"}
                )
            )
        assert r["status"] == "failed"

    async def test_no_zone_param_no_dot(self, mcp_server, mock_infoblox_client):
        """When name has no dots and zone is omitted → cannot determine zone."""
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool("provision_dns", {"name": "www", "record_type": "A", "value": "10.0.0.1"})
            )
        assert r["status"] == "failed"
        assert "zone" in r["summary"].lower()

    async def test_with_view(self, mcp_server, mock_infoblox_client):
        """provision_dns with view selects the correct zone."""
        mock_infoblox_client.list_dns_views.return_value = _api([{"id": "dns/view/default", "name": "default"}])
        mock_infoblox_client.list_auth_zones.return_value = _api(
            [
                {"id": "dns/auth_zone/azure", "fqdn": "example.com.", "view": "dns/view/azure"},
                {"id": "dns/auth_zone/default", "fqdn": "example.com.", "view": "dns/view/default"},
            ]
        )
        mock_infoblox_client.create_dns_record.return_value = {"result": {"id": "dns/record/new"}}
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "provision_dns",
                    {
                        "name": "www",
                        "record_type": "A",
                        "value": "10.0.0.1",
                        "zone": "example.com",
                        "view": "default",
                        "dry_run": False,
                    },
                )
            )
        assert r["status"] == "success"


class TestDecommissionHost:
    async def test_dry_run(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_ipam_hosts.return_value = _api([HOST])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("decommission_host", {"identifier": "web-01", "dry_run": True}))
        assert r["status"] == "success"
        assert "DRY RUN" in r["summary"]

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("decommission_host", {"identifier": "x"}))
        assert r["status"] == "failed"


# ═══════════════════════════════════════════════════════════════════
# Troubleshooting
# ═══════════════════════════════════════════════════════════════════


class TestDiagnoseDns:
    async def test_happy_path(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_auth_zones.return_value = _api([ZONE])
        mock_infoblox_client.list_dns_records.return_value = _api([RECORD])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("diagnose_dns", {"domain": "www.example.com"}))
        assert r["status"] == "success"

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("diagnose_dns", {"domain": "test.com"}))
        assert r["status"] == "failed"


class TestDiagnoseIpConflict:
    async def test_happy_path(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_subnets.return_value = _api([SUBNET])
        mock_infoblox_client.list_addresses.return_value = _api([ADDR])
        mock_infoblox_client.list_ipam_hosts.return_value = _api([])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("diagnose_ip_conflict", {"address": "10.0.0.1"}))
        assert r["status"] == "success"

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("diagnose_ip_conflict", {"address": "10.0.0.1"}))
        assert r["status"] == "failed"


class TestCheckInfrastructureHealth:
    async def test_happy_path(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_ha_groups.return_value = _api([HA_GROUP])
        mock_infoblox_client.list_dhcp_hosts.return_value = _api([DHCP_HOST])
        mock_infoblox_client.list_auth_zones.return_value = _api([ZONE])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("check_infrastructure_health"))
        assert r["status"] == "success"
        assert "components" in r["result"]

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("check_infrastructure_health"))
        assert r["status"] == "failed"


# ═══════════════════════════════════════════════════════════════════
# Security
# ═══════════════════════════════════════════════════════════════════


class TestInvestigateThreat:
    async def test_happy_path(self, mcp_server, mock_insights_client):
        mock_insights_client.list_insights.return_value = _api([INSIGHT])
        mock_insights_client.get_threat_indicators.return_value = _api([])
        mock_insights_client.get_affected_assets.return_value = _api([])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("investigate_threat"))
        assert r["status"] == "success"

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("investigate_threat"))
        assert r["status"] == "failed"


class TestAssessSecurityPosture:
    async def test_happy_path(self, mcp_server, mock_atcfw_client, mock_insights_client):
        mock_atcfw_client.list_security_policies.return_value = _api([POLICY])
        mock_atcfw_client.list_named_lists.return_value = _api([NAMED_LIST])
        mock_insights_client.list_insights.return_value = _api([INSIGHT])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("assess_security_posture"))
        assert r["status"] == "success"

    async def test_no_clients_partial(self, mcp_server, no_clients):
        """With no clients at all, returns failed (nothing to assess)."""
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("assess_security_posture"))
        assert r["status"] == "failed"


# ═══════════════════════════════════════════════════════════════════
# IPAM
# ═══════════════════════════════════════════════════════════════════


class TestGetIpUtilization:
    async def test_happy_path(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        mock_infoblox_client.list_subnets.return_value = _api([SUBNET])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("get_ip_utilization"))
        assert r["status"] == "success"

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("get_ip_utilization"))
        assert r["status"] == "failed"


class TestManageNetwork:
    async def test_get_subnet(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.get_subnet.return_value = {"result": SUBNET}
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "manage_network", {"resource_type": "subnet", "action": "get", "resource_id": "ipam/subnet/1"}
                )
            )
        assert r["status"] == "success"

    async def test_invalid_resource_type(self, mcp_server, mock_infoblox_client):
        async with Client(mcp_server) as c:
            with pytest.raises(ToolError, match="literal_error"):
                await c.call_tool("manage_network", {"resource_type": "vlan", "action": "list"})

    async def test_invalid_action(self, mcp_server, mock_infoblox_client):
        async with Client(mcp_server) as c:
            with pytest.raises(ToolError, match="literal_error"):
                await c.call_tool("manage_network", {"resource_type": "subnet", "action": "drop"})

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_network", {"resource_type": "subnet", "action": "list"}))
        assert r["status"] == "failed"


# ═══════════════════════════════════════════════════════════════════
# DNS Management
# ═══════════════════════════════════════════════════════════════════


class TestManageDnsZone:
    async def test_list(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_auth_zones.return_value = _api([ZONE])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_dns_zone", {"action": "list"}))
        assert r["status"] == "success"

    async def test_invalid_action(self, mcp_server, mock_infoblox_client):
        async with Client(mcp_server) as c:
            with pytest.raises(ToolError, match="literal_error"):
                await c.call_tool("manage_dns_zone", {"action": "drop"})

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_dns_zone", {"action": "list"}))
        assert r["status"] == "failed"


class TestManageDnsRecord:
    async def test_list(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_dns_records.return_value = _api([RECORD])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_dns_record", {"action": "list", "zone": "example.com"}))
        assert r["status"] == "success"

    async def test_invalid_action(self, mcp_server, mock_infoblox_client):
        async with Client(mcp_server) as c:
            with pytest.raises(ToolError, match="literal_error"):
                await c.call_tool("manage_dns_record", {"action": "create"})

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_dns_record", {"action": "list"}))
        assert r["status"] == "failed"


# ═══════════════════════════════════════════════════════════════════
# DHCP
# ═══════════════════════════════════════════════════════════════════


class TestManageDhcp:
    async def test_list_ha_groups(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_ha_groups.return_value = _api([HA_GROUP])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_dhcp", {"resource_type": "ha_group", "action": "list"}))
        assert r["status"] == "success"

    async def test_invalid_resource_type(self, mcp_server, mock_infoblox_client):
        async with Client(mcp_server) as c:
            with pytest.raises(ToolError, match="literal_error"):
                await c.call_tool("manage_dhcp", {"resource_type": "vlan", "action": "list"})

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_dhcp", {"resource_type": "ha_group", "action": "list"}))
        assert r["status"] == "failed"


# ═══════════════════════════════════════════════════════════════════
# IP Reservation
# ═══════════════════════════════════════════════════════════════════


class TestManageIpReservation:
    async def test_list(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_fixed_addresses.return_value = _api(
            [{"id": "dhcp/fixed_address/1", "address": "10.0.0.50", "match_type": "mac"}]
        )
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_ip_reservation", {"action": "list"}))
        assert r["status"] == "success"

    async def test_invalid_action(self, mcp_server, mock_infoblox_client):
        async with Client(mcp_server) as c:
            with pytest.raises(ToolError, match="literal_error"):
                await c.call_tool("manage_ip_reservation", {"action": "drop"})

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_ip_reservation", {"action": "list"}))
        assert r["status"] == "failed"


# ═══════════════════════════════════════════════════════════════════
# Security Policy Management
# ═══════════════════════════════════════════════════════════════════


class TestManageSecurityPolicy:
    async def test_list_policies(self, mcp_server, mock_atcfw_client):
        mock_atcfw_client.list_security_policies.return_value = _api([POLICY])
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool("manage_security_policy", {"resource_type": "policy", "action": "list"})
            )
        assert r["status"] == "success"

    async def test_invalid_resource_type(self, mcp_server, mock_atcfw_client):
        async with Client(mcp_server) as c:
            with pytest.raises(ToolError, match="literal_error"):
                await c.call_tool("manage_security_policy", {"resource_type": "firewall", "action": "list"})

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool("manage_security_policy", {"resource_type": "policy", "action": "list"})
            )
        assert r["status"] == "failed"


# ═══════════════════════════════════════════════════════════════════
# Federation
# ═══════════════════════════════════════════════════════════════════


class TestManageFederation:
    async def test_list_realms(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_federated_realms.return_value = _api([REALM])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_federation", {"resource_type": "realm", "action": "list"}))
        assert r["status"] == "success"

    async def test_invalid_resource_type(self, mcp_server, mock_infoblox_client):
        async with Client(mcp_server) as c:
            with pytest.raises(ToolError, match="literal_error"):
                await c.call_tool("manage_federation", {"resource_type": "zone", "action": "list"})

    async def test_invalid_action(self, mcp_server, mock_infoblox_client):
        async with Client(mcp_server) as c:
            with pytest.raises(ToolError, match="literal_error"):
                await c.call_tool("manage_federation", {"resource_type": "realm", "action": "drop"})

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_federation", {"resource_type": "realm", "action": "list"}))
        assert r["status"] == "failed"


# ═══════════════════════════════════════════════════════════════════
# Security Triage
# ═══════════════════════════════════════════════════════════════════


class TestTriageSecurityInsight:
    async def test_get_history(self, mcp_server, mock_insights_client):
        mock_insights_client.get_insight.return_value = {"result": INSIGHT}
        mock_insights_client.get_insight_comments.return_value = _api([])
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool("triage_security_insight", {"action": "get_history", "insight_id": "insight/1"})
            )
        assert r["status"] == "success"

    async def test_invalid_action(self, mcp_server, mock_insights_client):
        async with Client(mcp_server) as c:
            with pytest.raises(ToolError, match="literal_error"):
                await c.call_tool("triage_security_insight", {"action": "nuke"})

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool("triage_security_insight", {"action": "get_history", "insight_id": "x"})
            )
        assert r["status"] == "failed"


# ═══════════════════════════════════════════════════════════════════
# Enriched Tool Tests
# ═══════════════════════════════════════════════════════════════════


class TestManageNetworkList:
    """Tests for the new 'list' action on manage_network."""

    async def test_list_subnets(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_subnets.return_value = _api([SUBNET])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_network", {"resource_type": "subnet", "action": "list"}))
        assert r["status"] == "success"
        assert len(r["result"]) == 1
        assert r["result"][0]["address"] == "10.0.0.0"

    async def test_list_address_blocks(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_address_blocks.return_value = _api([BLOCK])
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool("manage_network", {"resource_type": "address_block", "action": "list"})
            )
        assert r["status"] == "success"
        assert len(r["result"]) == 1

    async def test_list_with_space_filter(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        mock_infoblox_client.list_subnets.return_value = _api([SUBNET])
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool("manage_network", {"resource_type": "subnet", "action": "list", "space": "prod"})
            )
        assert r["status"] == "success"


class TestDiagnoseIpConflictEnriched:
    """Tests for host association enrichment in diagnose_ip_conflict."""

    async def test_host_associations_included(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_subnets.return_value = _api([SUBNET])
        mock_infoblox_client.list_addresses.return_value = _api([ADDR])
        mock_infoblox_client.list_ranges.return_value = _api([])
        mock_infoblox_client.list_ipam_hosts.return_value = _api([HOST])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("diagnose_ip_conflict", {"address": "10.0.0.1"}))
        assert r["status"] == "success"
        assert "host_associations" in r["result"]
        assert len(r["result"]["host_associations"]) == 1


class TestInvestigateThreatEnriched:
    """Tests for events enrichment in investigate_threat."""

    async def test_events_included(self, mcp_server, mock_insights_client):
        event = {
            "type": "dns_query",
            "detected_at": "2024-01-01T00:00:00Z",
            "device_ip": "10.0.0.1",
            "threat_level": "high",
        }
        mock_insights_client.list_insights.return_value = _api([INSIGHT])
        mock_insights_client.get_insight_indicators.return_value = _api([])
        mock_insights_client.get_insight_assets.return_value = _api([])
        mock_insights_client.get_insight_events.return_value = _api([event])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("investigate_threat"))
        assert r["status"] == "success"
        assert "events" in r["result"]["insights"][0]
        assert r["result"]["insights"][0]["event_count"] == 1


class TestAssessSecurityPostureEnriched:
    """Tests for category filter enrichment in assess_security_posture."""

    async def test_category_filters_included(self, mcp_server, mock_atcfw_client, mock_insights_client):
        cat_filter = {"id": "cf/1", "name": "adult-content"}
        content_cat = {"id": "cc/1", "name": "Malware"}
        mock_atcfw_client.list_security_policies.return_value = _api([POLICY])
        mock_atcfw_client.list_named_lists.return_value = _api([NAMED_LIST])
        mock_atcfw_client.list_category_filters.return_value = _api([cat_filter])
        mock_atcfw_client.list_content_categories.return_value = _api([content_cat])
        mock_insights_client.list_policy_check_insights.return_value = _api([])
        mock_insights_client.list_analytics_insights.return_value = _api([])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("assess_security_posture"))
        assert r["status"] == "success"
        assert "category_filters" in r["result"]
        assert r["result"]["category_filters"]["count"] == 1
        assert "content_categories" in r["result"]


class TestCheckInfrastructureHealthEnriched:
    """Tests for DNS views enrichment in check_infrastructure_health."""

    async def test_dns_views_included(self, mcp_server, mock_infoblox_client):
        view = {"id": "dns/view/1", "name": "default"}
        mock_infoblox_client.list_ha_groups.return_value = _api([HA_GROUP])
        mock_infoblox_client.list_dhcp_hosts.return_value = _api([DHCP_HOST])
        mock_infoblox_client.list_auth_zones.return_value = _api([ZONE])
        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        mock_infoblox_client.list_dns_views.return_value = _api([view])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("check_infrastructure_health"))
        assert r["status"] == "success"
        assert "dns_views" in r["result"]["components"]
        assert r["result"]["components"]["dns_views"]["count"] == 1


# ═══════════════════════════════════════════════════════════════════
# DHCP Lease Management (v1.6.0)
# ═══════════════════════════════════════════════════════════════════

LEASE = {
    "id": "dhcp/lease/1",
    "address": "10.0.0.50",
    "hardware": "AA:BB:CC:DD:EE:FF",
    "hostname": "client-01",
    "state": "used",
    "starts": "2026-03-01T00:00:00Z",
    "ends": "2026-03-08T00:00:00Z",
    "space": "ipam/ip_space/1",
}
LBDN = {"id": "dtc/lbdn/1", "name": "app.example.com", "view": "dns/view/1", "comment": ""}
VIEW = {"id": "dns/view/1", "name": "default", "comment": ""}
DELEGATION = {"id": "dns/delegation/1", "fqdn": "sub.example.com.", "view": "dns/view/1", "comment": ""}
CAT_FILTER = {"id": 1, "name": "block-adult", "description": "", "categories": ["Adult Content"]}


class TestManageDhcpLease:
    async def test_list(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_dhcp_leases.return_value = _api([LEASE])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_dhcp_lease", {"action": "list"}))
        assert r["status"] == "success"
        assert len(r["result"]) == 1
        assert r["result"][0]["address"] == "10.0.0.50"

    async def test_get(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.get_dhcp_lease.return_value = {"result": LEASE}
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool("manage_dhcp_lease", {"action": "get", "resource_id": "dhcp/lease/1"})
            )
        assert r["status"] == "success"

    async def test_clear(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        mock_infoblox_client.send_lease_command.return_value = {"success": True}
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "manage_dhcp_lease",
                    {"action": "clear", "address": "10.0.0.50", "space": "prod", "dry_run": False},
                )
            )
        assert r["status"] == "success"
        mock_infoblox_client.send_lease_command.assert_called_once()

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_dhcp_lease", {"action": "list"}))
        assert r["status"] == "failed"


# ═══════════════════════════════════════════════════════════════════
# DTC / GSLB Management (v1.6.0)
# ═══════════════════════════════════════════════════════════════════


class TestManageDtc:
    async def test_list_lbdn(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_lbdn.return_value = _api([LBDN])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_dtc", {"resource_type": "lbdn", "action": "list"}))
        assert r["status"] == "success"
        assert len(r["result"]) == 1
        assert r["result"][0]["name"] == "app.example.com"

    async def test_invalid_resource_type(self, mcp_server, mock_infoblox_client):
        async with Client(mcp_server) as c:
            with pytest.raises(ToolError, match="literal_error"):
                await c.call_tool("manage_dtc", {"resource_type": "zone", "action": "list"})

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_dtc", {"resource_type": "lbdn", "action": "list"}))
        assert r["status"] == "failed"


# ═══════════════════════════════════════════════════════════════════
# Expanded DNS Zone Management (v1.6.0)
# ═══════════════════════════════════════════════════════════════════


class TestManageDnsZoneExpanded:
    async def test_list_views(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_dns_views.return_value = _api([VIEW])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_dns_zone", {"action": "list", "resource_type": "dns_view"}))
        assert r["status"] == "success"
        assert len(r["result"]) == 1
        assert r["result"][0]["name"] == "default"

    async def test_list_rpz(self, mcp_server, mock_infoblox_client):
        rpz = {
            "id": "dns/auth_zone/rpz1",
            "fqdn": "rpz.example.com.",
            "primary_type": "cloud",
            "view": "dns/view/1",
            "comment": "",
        }
        mock_infoblox_client.list_rpz_zones.return_value = _api([rpz])
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_dns_zone", {"action": "list", "resource_type": "rpz"}))
        assert r["status"] == "success"
        assert len(r["result"]) == 1

    async def test_list_delegations(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_dns_delegations.return_value = _api([DELEGATION])
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool("manage_dns_zone", {"action": "list", "resource_type": "delegation"})
            )
        assert r["status"] == "success"
        assert len(r["result"]) == 1

    async def test_sign_non_auth_fails(self, mcp_server, mock_infoblox_client):
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "manage_dns_zone",
                    {"action": "sign", "resource_type": "forward_zone", "zone_ids": ["dns/auth_zone/1"]},
                )
            )
        assert r["status"] == "failed"
        assert "only supported for auth_zone" in r["summary"]

    async def test_sign_auth_zone(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.sign_auth_zone.return_value = {"success": True}
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "manage_dns_zone",
                    {"action": "sign", "resource_type": "auth_zone", "zone_ids": ["dns/auth_zone/1"]},
                )
            )
        assert r["status"] == "success"

    async def test_reorder_non_rpz_fails(self, mcp_server, mock_infoblox_client):
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "manage_dns_zone",
                    {"action": "reorder", "resource_type": "auth_zone", "zone_ids": ["id1"]},
                )
            )
        assert r["status"] == "failed"
        assert "only supported for rpz" in r["summary"]


# ═══════════════════════════════════════════════════════════════════
# Expanded Network Management (v1.6.0)
# ═══════════════════════════════════════════════════════════════════


class TestManageNetworkExpanded:
    async def test_next_available_subnet(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.allocate_next_available_subnet.return_value = {
            "result": {"id": "ipam/subnet/new", "address": "10.0.1.0", "cidr": 24}
        }
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "manage_network",
                    {
                        "resource_type": "address_block",
                        "action": "next_available_subnet",
                        "resource_id": "ipam/address_block/1",
                        "cidr": 24,
                    },
                )
            )
        assert r["status"] == "success"

    async def test_next_available_wrong_resource_type(self, mcp_server, mock_infoblox_client):
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "manage_network",
                    {
                        "resource_type": "subnet",
                        "action": "next_available_subnet",
                        "resource_id": "ipam/subnet/1",
                        "cidr": 28,
                    },
                )
            )
        assert r["status"] == "failed"
        assert "only supported for address_block" in r["summary"]

    async def test_next_available_address_block(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.allocate_next_available_address_block.return_value = {
            "result": {"id": "ipam/address_block/new", "address": "10.1.0.0", "cidr": 20}
        }
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "manage_network",
                    {
                        "resource_type": "address_block",
                        "action": "next_available_address_block",
                        "resource_id": "ipam/address_block/1",
                        "cidr": 20,
                    },
                )
            )
        assert r["status"] == "success"


# ═══════════════════════════════════════════════════════════════════
# Expanded Security Policy Management (v1.6.0)
# ═══════════════════════════════════════════════════════════════════


class TestManageSecurityPolicyExpanded:
    async def test_list_category_filters(self, mcp_server, mock_atcfw_client):
        mock_atcfw_client.list_category_filters.return_value = _api([CAT_FILTER])
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool("manage_security_policy", {"resource_type": "category_filter", "action": "list"})
            )
        assert r["status"] == "success"
        assert len(r["result"]) == 1
        assert r["result"][0]["name"] == "block-adult"

    async def test_create_category_filter(self, mcp_server, mock_atcfw_client):
        mock_atcfw_client.create_category_filter.return_value = {"result": {"id": 2, "name": "test-filter"}}
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "manage_security_policy",
                    {
                        "resource_type": "category_filter",
                        "action": "create",
                        "name": "test-filter",
                        "categories": ["Malware", "Phishing"],
                    },
                )
            )
        assert r["status"] == "success"
        mock_atcfw_client.create_category_filter.assert_called_once()

    async def test_delete_category_filter_dry_run(self, mcp_server, mock_atcfw_client):
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "manage_security_policy",
                    {"resource_type": "category_filter", "action": "delete", "resource_id": "1", "dry_run": True},
                )
            )
        assert r["status"] == "success"
        assert "DRY RUN" in r["summary"]


# ═══════════════════════════════════════════════════════════════════
# Error Scenarios & Edge Cases
# ═══════════════════════════════════════════════════════════════════


class TestErrorScenarios:
    """Tests for error paths: API failures, partial workflows, edge cases."""

    async def test_provision_host_api_error(self, mcp_server, mock_infoblox_client):
        """provision_host should return 'failed' when the API returns an HTTP error."""
        import requests

        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        mock_infoblox_client.list_auth_zones.return_value = _api([ZONE])
        mock_infoblox_client.create_ipam_host.side_effect = requests.exceptions.HTTPError("400 Bad Request")
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "provision_host",
                    {
                        "hostname": "fail-host",
                        "space": "prod",
                        "ip": "10.0.0.99",
                        "zone": "example.com",
                        "dry_run": False,
                    },
                )
            )
        assert r["status"] == "failed"
        assert "Failed to create IPAM host" in r["summary"]

    async def test_provision_dns_zone_not_found(self, mcp_server, mock_infoblox_client):
        """provision_dns should fail gracefully when zone doesn't exist."""
        mock_infoblox_client.list_auth_zones.return_value = _api([])
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "provision_dns",
                    {"name": "www", "record_type": "A", "value": "10.0.0.1", "zone": "nonexistent.com"},
                )
            )
        assert r["status"] == "failed"
        assert "not found" in r["summary"]

    async def test_explore_network_api_exception(self, mcp_server, mock_infoblox_client):
        """explore_network should return 'failed' on unexpected API exceptions."""
        mock_infoblox_client.list_ip_spaces.side_effect = Exception("Connection refused")
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("explore_network"))
        assert r["status"] == "failed"

    async def test_manage_dns_record_delete_not_found(self, mcp_server, mock_infoblox_client):
        """Deleting a non-existent DNS record should propagate the failure."""
        import requests

        mock_infoblox_client.delete_dns_record.side_effect = requests.exceptions.HTTPError("404 Not Found")
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "manage_dns_record",
                    {"action": "delete", "record_id": "dns/record/nonexistent", "dry_run": False},
                )
            )
        assert r["status"] == "failed"

    async def test_investigate_threat_no_insights_client(self, mcp_server, monkeypatch):
        """investigate_threat should handle missing insights client gracefully."""
        import mcp_intent

        monkeypatch.setattr(mcp_intent, "insights_client", None)
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("investigate_threat", {"query": "malware"}))
        # Should fail gracefully when insights client is not available
        assert r["status"] == "failed"

    async def test_provision_host_partial_dns_failure(self, mcp_server, mock_infoblox_client):
        """Host creation succeeds but manual DNS A record fails → partial success."""
        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        mock_infoblox_client.list_auth_zones.return_value = _api([ZONE])
        mock_infoblox_client.create_ipam_host.return_value = {
            "result": {"id": "ipam/host/1", "name": "web-01.example.com", "addresses": [{"address": "10.0.0.1"}]}
        }
        mock_infoblox_client.create_dns_record.side_effect = Exception("500 Internal Server Error")
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "provision_host",
                    {
                        "hostname": "web-01",
                        "space": "prod",
                        "ip": "10.0.0.1",
                        "zone": "example.com",
                        "auto_dns": False,
                        "dry_run": False,
                    },
                )
            )
        # Host created successfully but DNS failed → partial
        assert r["status"] == "partial"
        assert len(r["warnings"]) > 0


class TestSanitizeFilter:
    """Tests for sanitize_filter hardening against injection."""

    def test_basic_escaping(self):
        from mcp_intent import sanitize_filter

        assert sanitize_filter('hello"world') == 'hello\\"world'
        assert sanitize_filter("back\\slash") == "back\\\\slash"

    def test_operator_removal(self):
        from mcp_intent import sanitize_filter

        assert "==" not in sanitize_filter('foo" or name=="admin')
        assert "!=" not in sanitize_filter("test!=break")
        assert "~=" not in sanitize_filter("test~=break")

    def test_length_truncation(self):
        from mcp_intent import sanitize_filter

        long_input = "A" * 1000
        result = sanitize_filter(long_input)
        assert len(result) <= 512

    def test_combined_injection(self):
        from mcp_intent import sanitize_filter

        # Attempt to break out of a filter value
        malicious = 'evil" or name=="*'
        sanitized = sanitize_filter(malicious)
        # Must not contain unescaped quotes or operators
        assert '=="' not in sanitized


class TestDryRunProtection:
    """Tests for dry_run defaults on destructive operations."""

    async def test_provision_host_has_dry_run(self, mcp_server, mock_infoblox_client):
        """provision_host with dry_run=True should not create anything."""
        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        mock_infoblox_client.list_auth_zones.return_value = _api([ZONE])
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "provision_host",
                    {"hostname": "test", "space": "prod", "ip": "10.0.0.1", "zone": "example.com", "dry_run": True},
                )
            )
        assert r["status"] == "success"
        assert "DRY RUN" in r["summary"]
        mock_infoblox_client.create_ipam_host.assert_not_called()

    async def test_provision_dns_has_dry_run(self, mcp_server, mock_infoblox_client):
        """provision_dns with dry_run=True should not create anything."""
        mock_infoblox_client.list_auth_zones.return_value = _api([ZONE])
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "provision_dns",
                    {"name": "www", "record_type": "A", "value": "10.0.0.1", "zone": "example.com", "dry_run": True},
                )
            )
        assert r["status"] == "success"
        assert "DRY RUN" in r["summary"]
        mock_infoblox_client.create_dns_record.assert_not_called()

    async def test_manage_dhcp_lease_clear_has_dry_run(self, mcp_server, mock_infoblox_client):
        """manage_dhcp_lease clear with dry_run=True should not actually clear."""
        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "manage_dhcp_lease",
                    {"action": "clear", "address": "10.0.0.1", "space": "prod", "dry_run": True},
                )
            )
        assert r["status"] == "success"
        assert "DRY RUN" in r["summary"]
        mock_infoblox_client.send_lease_command.assert_not_called()


class TestHealthEndpoint:
    """Tests for the health check tool."""

    async def test_health_check_all_clients(
        self, mcp_server, mock_infoblox_client, mock_insights_client, mock_atcfw_client
    ):
        """check_api_health should report status for all three clients."""
        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        mock_insights_client.list_insights.return_value = {"results": []}
        mock_atcfw_client.list_security_policies.return_value = {"results": []}
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("check_api_health"))
        assert r["status"] == "success"
        assert "healthy" in r["summary"].lower() or "reachable" in r["summary"].lower()

    async def test_health_check_partial_failure(self, mcp_server, mock_infoblox_client, monkeypatch):
        """check_api_health should report partial when some clients fail."""
        import mcp_intent

        mock_infoblox_client.list_ip_spaces.return_value = _api([SPACE])
        monkeypatch.setattr(mcp_intent, "insights_client", None)
        monkeypatch.setattr(mcp_intent, "atcfw_client", None)
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("check_api_health"))
        assert r["status"] in ("success", "partial")
