[![CI](https://github.com/iracic82/infoblox-ddi-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/iracic82/infoblox-ddi-mcp/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-compatible-purple.svg)](https://modelcontextprotocol.io)
[![PyPI](https://img.shields.io/pypi/v/infoblox-ddi-mcp.svg)](https://pypi.org/project/infoblox-ddi-mcp/)

# Infoblox DDI — MCP Server

> **20 intent-level workflow tools** for managing Infoblox BloxOne DDI via the Model Context Protocol.

Any MCP-compatible AI agent can manage your entire DDI infrastructure — DNS, DHCP, IPAM, security, and federation — without being an Infoblox expert. Instead of 98 atomic CRUD operations, this server exposes 20 high-level tools that orchestrate multi-step workflows automatically.

---

## Quick Start

### Option A: uv (recommended)

```bash
cd infoblox-ddi-mcp

# Install dependencies
uv pip install -r requirements.txt

# Configure credentials
cp .env.example .env
# Edit .env — add INFOBLOX_API_KEY

# Run (stdio)
python mcp_intent.py

# Run (HTTP)
python mcp_intent.py --http
```

### Option B: Docker (one command)

```bash
docker build -t infoblox-ddi-mcp .
docker run -p 4005:4005 -e INFOBLOX_API_KEY=your_key infoblox-ddi-mcp
```

Or with docker compose (reads `.env` automatically):

```bash
cp .env.example .env   # add your INFOBLOX_API_KEY
docker compose up -d
```

### Option C: pip install

```bash
cd infoblox-ddi-mcp
pip install .

# Now available as a CLI command:
infoblox-ddi-mcp --http
```

## Transport Modes

| Mode | Command | Use Case |
|------|---------|----------|
| **stdio** (default) | `python mcp_intent.py` | Claude Desktop, Cursor, Windsurf, Claude Code |
| **HTTP streamable** | `python mcp_intent.py --http` | HCL AEX, LangChain, OpenAI SDK, remote clients |
| **Docker** | `docker run -p 4005:4005 ...` | Production, Kubernetes, HCL evaluation |

Stdio transport communicates via stdin/stdout JSON-RPC. HTTP transport runs a spec-compliant MCP server on port 4005 (configurable via `MCP_PORT`).

### Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `INFOBLOX_API_KEY` | (required) | Infoblox CSP API key |
| `INFOBLOX_BASE_URL` | `https://csp.infoblox.com` | CSP portal URL |
| `MCP_HOST` | `0.0.0.0` | HTTP bind address |
| `MCP_PORT` | `4005` | HTTP port |
| `MCP_PATH` | `/mcp` | HTTP endpoint path |
| `MCP_AUTH_TOKEN` | (optional) | Bearer token for HTTP transport authentication |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | (optional) | OTLP endpoint to enable tracing (requires `[otel]` extra) |

When `MCP_AUTH_TOKEN` is set, all HTTP requests must include `Authorization: Bearer <token>`. Stdio transport is unaffected (authentication is handled by the host process).

---

## Connect to AI Frameworks

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "infoblox-ddi": {
      "command": "python",
      "args": ["/absolute/path/to/infoblox-ddi-mcp/mcp_intent.py"],
      "env": {
        "INFOBLOX_API_KEY": "your_api_key_here",
        "INFOBLOX_BASE_URL": "https://csp.infoblox.com"
      }
    }
  }
}
```

Restart Claude Desktop — the 20 tools appear in the tool picker.

### Anthropic Python SDK

```python
import anthropic

client = anthropic.Anthropic()

response = client.beta.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    mcp_servers=[
        {
            "type": "url",
            "url": "https://your-gateway.example.com/mcp",  # must be HTTPS
            "name": "infoblox-ddi",
            "authorization_token": "your_mcp_auth_token",   # optional, if MCP_AUTH_TOKEN is set
        }
    ],
    tools=[
        {
            "type": "mcp_toolset",
            "mcp_server_name": "infoblox-ddi",
        }
    ],
    messages=[{"role": "user", "content": "Show me all IP spaces and their utilization"}],
    betas=["mcp-client-2025-11-20"],
)
```

> **Note:** The Anthropic MCP connector requires the server to be reachable via HTTPS. For local testing, use Claude Desktop (stdio) instead.

### LangChain / LangGraph

```python
from langchain_mcp_adapters.client import MultiServerMCPClient

client = MultiServerMCPClient(
    {
        "infoblox-ddi-stdio": {
            "command": "python",
            "args": ["/path/to/infoblox-ddi-mcp/mcp_intent.py"],
            "transport": "stdio",
        },
        # Or use HTTP (streamable_http is recommended over sse):
        # "infoblox-ddi-http": {
        #     "url": "http://127.0.0.1:4005/mcp",
        #     "transport": "streamable_http",
        # },
    }
)

tools = await client.get_tools()
# Use with any LangChain agent or LangGraph workflow
```

### OpenAI Agents SDK

```python
from agents import Agent, Runner
from agents.mcp import MCPServerStdio, MCPServerStreamableHttp

# Option A: stdio transport
async with MCPServerStdio(
    name="infoblox-ddi",
    params={
        "command": "python",
        "args": ["/path/to/infoblox-ddi-mcp/mcp_intent.py"],
    },
) as server:
    agent = Agent(name="ddi-agent", mcp_servers=[server])
    result = await Runner.run(agent, "Show me all IP spaces")
    print(result.final_output)

# Option B: HTTP streamable transport (start server first with --http)
async with MCPServerStreamableHttp(
    name="infoblox-ddi",
    params={"url": "http://127.0.0.1:4005/mcp"},
) as server:
    agent = Agent(name="ddi-agent", mcp_servers=[server])
    result = await Runner.run(agent, "List all DNS zones")
    print(result.final_output)
```

### Cursor IDE

Add to `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "infoblox-ddi": {
      "command": "python",
      "args": ["/absolute/path/to/infoblox-ddi-mcp/mcp_intent.py"],
      "env": {
        "INFOBLOX_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

### Windsurf IDE

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "infoblox-ddi": {
      "command": "python",
      "args": ["/absolute/path/to/infoblox-ddi-mcp/mcp_intent.py"],
      "env": {
        "INFOBLOX_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

### HCL BigFix AEX

AEX has native MCP client support. In **Admin Console → Agent Studio**:

1. Add an MCP Server tool source
2. Set the endpoint to `http://<host>:4005/mcp`
3. Start the server with `python mcp_intent.py --http`
4. The 20 DDI tools are auto-discovered and available to AEX agents

### Any HTTP Client

```bash
# Initialize session
curl -X POST http://127.0.0.1:4005/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {"name": "curl", "version": "1.0"}
    }
  }'

# List available tools
curl -X POST http://127.0.0.1:4005/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}'

# Call a tool
curl -X POST http://127.0.0.1:4005/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "explore_network",
      "arguments": {"depth": "summary"}
    }
  }'
```

---

## Available Tools

### Discovery & Exploration (Read-only)

| Tool | Description |
|------|-------------|
| `explore_network` | Browse the IP hierarchy tree (Spaces → Blocks → Subnets) with utilization. Use for navigating network structure |
| `search_infrastructure` | Find resources by keyword across all DDI domains (IP, hostname, domain, comment) |
| `get_network_summary` | Executive dashboard with counts and health across all DDI infrastructure |

### Provisioning (Write)

| Tool | Description |
|------|-------------|
| `provision_host` | Create host + IP + A record + PTR in one call (replaces 3 API calls) |
| `provision_dns` | Create a new DNS record with automatic zone discovery and validation |
| `decommission_host` | Reverse provisioning with dry-run safety — removes host, DNS, and IP |

### Troubleshooting (Read-only)

| Tool | Description |
|------|-------------|
| `diagnose_dns` | Diagnose DNS resolution problems: zone, records, and security policies |
| `diagnose_ip_conflict` | Detect overlapping subnets, duplicate reservations, DHCP usage, and host associations |
| `check_infrastructure_health` | HA groups, DHCP hosts, DNS zones, DNS views, IP spaces, and service health |

### Security (Read + Write)

| Tool | Description |
|------|-------------|
| `investigate_threat` | SOC insights with threat indicators, affected assets, and timeline events |
| `assess_security_posture` | Security policies, category filters, compliance, and analytics scorecard |
| `manage_security_policy` | CRUD for named lists, app filters, internal domains, access codes |
| `triage_security_insight` | Update status, bulk triage by priority, get comment history |

### IPAM Management (CRUD)

| Tool | Description |
|------|-------------|
| `manage_network` | Create, update, delete, get, or list IP spaces, address blocks, subnets, and ranges |
| `manage_ip_reservation` | Reserve/release fixed IPs and DHCP static leases |

### DNS Configuration (CRUD)

| Tool | Description |
|------|-------------|
| `manage_dns_zone` | Create, delete, list, or get authoritative and forward zones |
| `manage_dns_record` | Update, delete, list, or get DNS records (smart lookup by name+zone+type) |

### DHCP Configuration (CRUD)

| Tool | Description |
|------|-------------|
| `manage_dhcp` | CRUD for HA groups, option codes, hardware/option filters, hardware entries |

### Federation (CRUD)

| Tool | Description |
|------|-------------|
| `manage_federation` | Manage realms, blocks, delegations, pools, overlapping/reserved blocks |

### Reporting (Read-only)

| Tool | Description |
|------|-------------|
| `get_ip_utilization` | Capacity planning — utilization by space, block, and subnet |

---

## Response Format

Every tool returns a standard envelope:

```json
{
  "status": "success | partial | failed",
  "summary": "Human-readable one-liner",
  "steps": [
    {"step": "Resolve IP space", "status": "success", "result": {"space_id": "ipam/ip_space/abc"}},
    {"step": "Create subnet", "status": "success", "result": {"id": "ipam/subnet/xyz"}}
  ],
  "result": { "..." : "..." },
  "warnings": ["Optional warnings"],
  "next_actions": ["Suggested follow-up tool calls"]
}
```

This makes it easy for any LLM to:
- **Check `status`** to know if the operation succeeded
- **Read `summary`** for a one-line answer to show the user
- **Inspect `steps`** to understand the multi-step workflow
- **Follow `next_actions`** for intelligent follow-up suggestions

---

## Example Conversations

**"Show me what's in our network"**
```
→ explore_network(depth="full")
→ Returns hierarchical tree: IP spaces → address blocks → subnets with utilization %
```

**"Create a /24 subnet in the prod space for web servers"**
```
→ manage_network(resource_type="subnet", action="create", address="10.20.3.0/24", space="prod", comment="Web servers")
→ Resolves space name → ID, validates CIDR, creates subnet
```

**"Set up a new host called web-prod-01 at 10.20.3.50"**
```
→ provision_host(hostname="web-prod-01", ip="10.20.3.50", space="prod", zone="example.com")
→ Creates IPAM host + A record + PTR record in one step
```

**"DNS isn't working for api.example.com"**
```
→ diagnose_dns(domain="api.example.com")
→ Returns zone status, records found, security blocks, and fix recommendations
```

**"Reserve 10.20.3.100 for the new database server"**
```
→ manage_ip_reservation(action="reserve", address="10.20.3.100", space="prod", hostname="db-01", mac="AA:BB:CC:DD:EE:FF")
→ Checks availability, validates MAC, creates fixed address reservation
```

**"Close all low-priority security insights"**
```
→ triage_security_insight(action="bulk_triage", priority_filter="low", status="CLOSED", dry_run=True)
→ DRY RUN: Shows 15 insights that would be closed
→ triage_security_insight(action="bulk_triage", priority_filter="low", status="CLOSED", dry_run=False)
→ Bulk closes 15 insights
```

**"What would happen if I decommissioned web-prod-01?"**
```
→ decommission_host(identifier="web-prod-01", dry_run=True)
→ "Would delete: 1 host, 1 A record, 1 PTR, release IP 10.20.3.50"
```

---

## Docker Deployment

```bash
# Build
make docker-build        # or: docker build -t infoblox-ddi-mcp .

# Run standalone
make docker-run          # or: docker run --rm -p 4005:4005 -e INFOBLOX_API_KEY=... infoblox-ddi-mcp

# Run with compose (reads .env)
make docker-up           # or: docker compose up -d
make docker-down         # or: docker compose down
```

The Docker image:
- Uses **multi-stage build** (small final image)
- Runs as **non-root** user
- Has a **health check** built in
- Binds to `0.0.0.0:4005` by default
- Accepts all config via environment variables

## OpenTelemetry (Optional)

Distributed tracing is available as an optional extra:

```bash
pip install infoblox-ddi-mcp[otel]
```

Enable by setting `OTEL_EXPORTER_OTLP_ENDPOINT`:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
python mcp_intent.py --http
```

All MCP tool calls are auto-traced with service name `infoblox-ddi-mcp`. Works with Jaeger, Grafana Tempo, Datadog, or any OTLP-compatible backend. If the packages aren't installed, the server runs normally without tracing.

---

## Production Deployment

### Behind an API Gateway (Recommended)

For production environments, run the MCP server behind an API gateway for TLS termination, rate limiting, and centralized authentication.

```
                        ┌─────────────────────┐
  AI Agents             │   API Gateway        │        MCP Server
  (Claude, AEX,  ──────▶│   (Kong / AWS API    │──────▶  infoblox-ddi-mcp
   LangChain)    HTTPS  │    GW / Nginx / F5)  │ HTTP    :4005/mcp
                        │                     │
                        │  • TLS termination   │
                        │  • Rate limiting     │
                        │  • Auth (OAuth/JWT)  │
                        │  • Access logging    │
                        └─────────────────────┘
```

The MCP server runs plain HTTP internally. The gateway handles TLS and external auth. Set `MCP_AUTH_TOKEN` as a shared secret between the gateway and the server for an additional layer of security.

#### Kubernetes / Docker Compose

```yaml
# docker-compose.prod.yml
services:
  infoblox-mcp:
    image: infoblox-ddi-mcp:latest
    restart: always
    environment:
      - INFOBLOX_API_KEY=${INFOBLOX_API_KEY}
      - INFOBLOX_BASE_URL=${INFOBLOX_BASE_URL:-https://csp.infoblox.com}
      - MCP_HOST=0.0.0.0
      - MCP_PORT=4005
      - MCP_AUTH_TOKEN=${MCP_AUTH_TOKEN}
    ports:
      - "127.0.0.1:4005:4005"   # bind to localhost only — gateway handles external traffic
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:4005/mcp')"]
      interval: 30s
      timeout: 5s
      retries: 3
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: "0.5"
```

#### Nginx Reverse Proxy Example

```nginx
upstream mcp_backend {
    server 127.0.0.1:4005;
}

server {
    listen 443 ssl;
    server_name mcp.example.com;

    ssl_certificate     /etc/ssl/certs/mcp.crt;
    ssl_certificate_key /etc/ssl/private/mcp.key;

    location /mcp {
        proxy_pass http://mcp_backend/mcp;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Authorization "Bearer ${MCP_AUTH_TOKEN}";

        # Rate limiting
        limit_req zone=mcp burst=20 nodelay;
    }
}
```

#### AWS API Gateway

1. Create an HTTP API in API Gateway
2. Add a route: `POST /mcp` → integration to your ECS/EKS service on port 4005
3. Attach a Lambda authorizer or Cognito user pool for auth
4. Enable CloudWatch logging for audit trail

#### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: infoblox-mcp
spec:
  replicas: 2
  selector:
    matchLabels:
      app: infoblox-mcp
  template:
    metadata:
      labels:
        app: infoblox-mcp
    spec:
      containers:
        - name: mcp
          image: infoblox-ddi-mcp:latest
          ports:
            - containerPort: 4005
          env:
            - name: INFOBLOX_API_KEY
              valueFrom:
                secretKeyRef:
                  name: infoblox-secrets
                  key: api-key
            - name: MCP_AUTH_TOKEN
              valueFrom:
                secretKeyRef:
                  name: infoblox-secrets
                  key: mcp-token
          livenessProbe:
            httpGet:
              path: /mcp
              port: 4005
            initialDelaySeconds: 10
            periodSeconds: 30
          resources:
            limits:
              memory: "512Mi"
              cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: infoblox-mcp
spec:
  selector:
    app: infoblox-mcp
  ports:
    - port: 4005
      targetPort: 4005
```

### Deployment Checklist

| Step | Action |
|------|--------|
| 1 | Set `INFOBLOX_API_KEY` via secrets manager (never in plain text) |
| 2 | Set `MCP_AUTH_TOKEN` for server-to-gateway authentication |
| 3 | Bind to `127.0.0.1` or internal network only (gateway handles external) |
| 4 | Enable TLS on the gateway (never expose plain HTTP externally) |
| 5 | Configure rate limiting (recommended: 60 req/min per client) |
| 6 | Enable access logging on the gateway for audit |
| 7 | Set resource limits (512MB RAM, 0.5 CPU is sufficient) |
| 8 | Monitor health check endpoint |

---

## Makefile Targets

```
make install        Install dependencies with uv
make dev            Install in editable mode
make run            Run MCP server (stdio)
make run-http       Run MCP server (HTTP)
make lint           Run ruff linter
make format         Run ruff formatter
make test           Run test suite (108 tests)
make docker-build   Build Docker image
make docker-run     Run Docker container
make docker-up      Start with docker compose
make docker-down    Stop docker compose
make check          Verify syntax
make clean          Remove build artifacts
```

---

## Architecture

```
Your AI Agent (Claude, GPT, AEX, Cursor, LangChain, ...)
        │
        │  MCP Protocol (stdio or HTTP)
        ▼
┌──────────────────────────────┐
│  mcp_intent.py               │  ← This server (20 intent tools)
│  Validation · Resolvers      │
│  Multi-step orchestration    │
└──────────┬───────────────────┘
           │  Direct Python calls
           ▼
┌──────────────────────────────┐
│  Service Clients              │
│  ├─ InfobloxClient (85 ops)  │  ← IPAM, DNS, DHCP, Federation
│  ├─ InsightsClient (13 ops)  │  ← SOC Insights, Policy Analytics
│  └─ AtcfwClient (11 ops)     │  ← DNS Security, Threat Lists
│                               │
│  Circuit breakers · Caching   │
│  Connection pooling · Metrics │
└──────────┬───────────────────┘
           │  HTTPS (REST API)
           ▼
┌──────────────────────────────┐
│  Infoblox CSP Portal          │
│  BloxOne DDI APIs             │
│  Your tenant · Your API key   │
└──────────────────────────────┘
```

---

## Project Structure

```
infoblox-ddi-mcp/
├── mcp_intent.py              ← MCP server entry point (run this)
├── services/
│   ├── infoblox_client.py     ← Infoblox DDI API client (85 methods)
│   ├── insights_client.py     ← SOC Insights API client (13 methods)
│   ├── atcfw_client.py        ← DNS Security API client (11 methods)
│   └── metrics.py             ← Internal metrics collection
├── tests/                     ← 108 tests (validators, resolvers, tools, resources)
│   ├── conftest.py
│   ├── test_validation.py
│   ├── test_resolvers.py
│   ├── test_tools.py
│   └── test_resources.py
├── examples/                  ← Integration examples
│   ├── anthropic_sdk.py
│   ├── openai_agents.py
│   ├── langchain_example.py
│   └── curl_test.sh
├── .github/workflows/
│   ├── ci.yml                 ← Lint + test (3.10-3.13) + Docker
│   └── publish.yml            ← PyPI publishing on v* tags
├── pyproject.toml             ← Package metadata (uv/pip install)
├── requirements.txt           ← Pinned dependencies
├── Dockerfile                 ← Production container image
├── docker-compose.yml         ← One-command deployment
├── Makefile                   ← Developer shortcuts
├── .pre-commit-config.yaml    ← Ruff + pre-commit hooks
├── CHANGELOG.md
├── SECURITY.md
├── .env.example
└── README.md
```

---

## Troubleshooting

**"Unexpected non-whitespace character after JSON"**
→ Something is writing to stdout. This server routes all logging to stderr. If you added custom print statements, use `print(..., file=sys.stderr)`.

**"Infoblox client not initialized"**
→ `INFOBLOX_API_KEY` is missing or invalid. Check your `.env` file or environment variables.

**"IP space 'prod' not found"**
→ The space name doesn't match exactly. Use `explore_network()` to see available space names.

**"DNS zone 'example.com' not found"**
→ The zone doesn't exist in Infoblox. Use `manage_dns_zone(action="list")` to see available zones, or `manage_dns_zone(action="create", fqdn="example.com")` to create one.

**Tools not appearing in Claude Desktop**
→ Restart Claude Desktop after editing `claude_desktop_config.json`. Check the path to `mcp_intent.py` is absolute.

**HTTP server not responding**
→ Start with `python mcp_intent.py --http`. Test with: `curl -X POST http://127.0.0.1:4005/mcp -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`

**Dry run confusion**
→ All destructive operations (delete, release, bulk triage) default to `dry_run=True`. They show what *would* happen without making changes. Set `dry_run=False` to execute.

**Token overflow / response too large**
→ Use `limit` parameters to reduce result sizes. The intent layer already truncates large results, but specific queries return less data.
