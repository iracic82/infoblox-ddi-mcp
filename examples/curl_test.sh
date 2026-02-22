#!/usr/bin/env bash
# Example: Test Infoblox DDI MCP Server with curl.
#
# Start the MCP server first:
#   INFOBLOX_API_KEY=your_key python mcp_intent.py --http
#
# Then run:
#   bash examples/curl_test.sh

set -euo pipefail

MCP_URL="${MCP_URL:-http://localhost:4005/mcp}"

echo "=== Infoblox DDI MCP Server — curl test ==="
echo "Endpoint: $MCP_URL"
echo

# ── 1. Initialize ────────────────────────────────────────────────────
echo "1. Initialize session..."
curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-03-26",
      "capabilities": {},
      "clientInfo": {"name": "curl-test", "version": "1.0.0"}
    }
  }' | python3 -m json.tool
echo

# ── 2. List tools ───────────────────────────────────────────────────
echo "2. List available tools..."
curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {}
  }' | python3 -c "
import sys, json
data = json.load(sys.stdin)
tools = data.get('result', {}).get('tools', [])
print(f'Found {len(tools)} tools:')
for t in tools:
    print(f'  - {t[\"name\"]}: {t[\"description\"][:80]}...')
"
echo

# ── 3. Call explore_network ──────────────────────────────────────────
echo "3. Call explore_network (summary)..."
curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "explore_network",
      "arguments": {"depth": "summary"}
    }
  }' | python3 -m json.tool
echo

echo "=== Done ==="
