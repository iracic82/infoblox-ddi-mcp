"""Tests for MCP resources (~6 tests)."""

import json

from fastmcp import Client


class TestToolCatalog:
    async def test_returns_20_tools(self, mcp_server):
        async with Client(mcp_server) as c:
            resources = await c.list_resources()
            # Find the tools resource
            tools_uri = None
            for res in resources:
                if "tools" in str(res.uri):
                    tools_uri = res.uri
                    break
            assert tools_uri is not None

            content = await c.read_resource(tools_uri)
            data = json.loads(content[0].text if hasattr(content[0], "text") else str(content[0]))
            assert data["tool_count"] == 20

    async def test_domains_grouped(self, mcp_server):
        async with Client(mcp_server) as c:
            resources = await c.list_resources()
            tools_uri = next(r.uri for r in resources if "tools" in str(r.uri))
            content = await c.read_resource(tools_uri)
            data = json.loads(content[0].text if hasattr(content[0], "text") else str(content[0]))
            assert "discovery" in data["domains"]
            assert "provisioning" in data["domains"]
            assert "security" in data["domains"]


class TestConnectionStatus:
    async def test_status_fields(self, mcp_server):
        async with Client(mcp_server) as c:
            resources = await c.list_resources()
            status_uri = next(r.uri for r in resources if "status" in str(r.uri))
            content = await c.read_resource(status_uri)
            data = json.loads(content[0].text if hasattr(content[0], "text") else str(content[0]))
            assert "infoblox_client" in data
            assert "api_key_set" in data


class TestDnsRecordTypes:
    async def test_record_types_present(self, mcp_server):
        async with Client(mcp_server) as c:
            resources = await c.list_resources()
            dns_uri = next(r.uri for r in resources if "record-types" in str(r.uri))
            content = await c.read_resource(dns_uri)
            data = json.loads(content[0].text if hasattr(content[0], "text") else str(content[0]))
            for rtype in ["A", "AAAA", "CNAME", "MX", "TXT", "PTR", "SRV"]:
                assert rtype in data, f"Missing record type: {rtype}"

    async def test_rdata_examples(self, mcp_server):
        async with Client(mcp_server) as c:
            resources = await c.list_resources()
            dns_uri = next(r.uri for r in resources if "record-types" in str(r.uri))
            content = await c.read_resource(dns_uri)
            data = json.loads(content[0].text if hasattr(content[0], "text") else str(content[0]))
            assert "address" in data["A"]["rdata"]
            assert "dname" in data["CNAME"]["rdata"]
