"""Tests for all 20 MCP tools via FastMCP Client (~60 tests).

Each tool gets 2-4 tests:
  1. Happy path with mocked API responses
  2. Client not initialised (None)
  3. For manage_* tools: invalid action/resource_type
  4. For destructive tools: dry_run=True behaviour
"""

from fastmcp import Client

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
            r = parse_tool_result(await c.call_tool("provision_host", {"hostname": "web-01", "space": "prod"}))
        assert r["status"] == "success"

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("provision_host", {"hostname": "x", "space": "prod"}))
        assert r["status"] == "failed"


class TestProvisionDns:
    async def test_happy_path(self, mcp_server, mock_infoblox_client):
        mock_infoblox_client.list_auth_zones.return_value = _api([ZONE])
        mock_infoblox_client.create_dns_record.return_value = {"result": {"id": "dns/record/new"}}
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool(
                    "provision_dns", {"name": "www", "record_type": "A", "value": "10.0.0.1", "zone": "example.com"}
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
        """With no clients, still returns success (skipped components)."""
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("assess_security_posture"))
        # assess_security_posture doesn't fail on missing clients; it skips
        assert r["status"] == "success"


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
            r = parse_tool_result(await c.call_tool("manage_network", {"resource_type": "vlan", "action": "list"}))
        assert r["status"] == "failed"
        assert "Invalid resource_type" in r["summary"]

    async def test_invalid_action(self, mcp_server, mock_infoblox_client):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_network", {"resource_type": "subnet", "action": "drop"}))
        assert r["status"] == "failed"
        assert "Invalid action" in r["summary"]

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
            r = parse_tool_result(await c.call_tool("manage_dns_zone", {"action": "drop"}))
        assert r["status"] == "failed"

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
            r = parse_tool_result(await c.call_tool("manage_dns_record", {"action": "create"}))
        assert r["status"] == "failed"

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
            r = parse_tool_result(await c.call_tool("manage_dhcp", {"resource_type": "vlan", "action": "list"}))
        assert r["status"] == "failed"

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
            r = parse_tool_result(await c.call_tool("manage_ip_reservation", {"action": "drop"}))
        assert r["status"] == "failed"

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
            r = parse_tool_result(
                await c.call_tool("manage_security_policy", {"resource_type": "firewall", "action": "list"})
            )
        assert r["status"] == "failed"

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
            r = parse_tool_result(await c.call_tool("manage_federation", {"resource_type": "zone", "action": "list"}))
        assert r["status"] == "failed"

    async def test_invalid_action(self, mcp_server, mock_infoblox_client):
        async with Client(mcp_server) as c:
            r = parse_tool_result(await c.call_tool("manage_federation", {"resource_type": "realm", "action": "drop"}))
        assert r["status"] == "failed"

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
            r = parse_tool_result(await c.call_tool("triage_security_insight", {"action": "nuke"}))
        assert r["status"] == "failed"
        assert "Invalid action" in r["summary"]

    async def test_no_client(self, mcp_server, no_clients):
        async with Client(mcp_server) as c:
            r = parse_tool_result(
                await c.call_tool("triage_security_insight", {"action": "get_history", "insight_id": "x"})
            )
        assert r["status"] == "failed"
