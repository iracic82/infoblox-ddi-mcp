# =============================================================================
# Infoblox DDI MCP Server — Production Docker Image
# =============================================================================
# Build:  docker build -t infoblox-ddi-mcp .
# Run:    docker run -e INFOBLOX_API_KEY=... -p 4005:4005 infoblox-ddi-mcp
# =============================================================================

# --- Stage 1: Build dependencies ---
FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Install dependencies first (layer caching — only rebuilds when deps change)
COPY pyproject.toml uv.lock* requirements.txt ./
RUN uv pip install --system --no-cache -r requirements.txt

# Copy application code
COPY mcp_intent.py ./
COPY services/ ./services/

# --- Stage 2: Runtime ---
FROM python:3.12-slim

# Security: non-root user
RUN groupadd -r mcp && useradd -r -g mcp -d /app -s /sbin/nologin mcp

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application
COPY --from=builder /app /app

# Own files as mcp user
RUN chown -R mcp:mcp /app

USER mcp

# Configuration via environment
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=4005
ENV MCP_PATH=/mcp
# INFOBLOX_API_KEY must be provided at runtime
# INFOBLOX_BASE_URL defaults to https://csp.infoblox.com

EXPOSE 4005

# Health check: MCP HTTP endpoint responds to POST (GET returns 405 which is expected)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen(urllib.request.Request('http://localhost:${MCP_PORT}${MCP_PATH}', method='POST', headers={'Content-Type':'application/json'}, data=b'{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}'))" || exit 1

CMD ["python", "mcp_intent.py", "--http"]
