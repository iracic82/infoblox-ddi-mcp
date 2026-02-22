# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities through [GitHub Security Advisories](https://github.com/iracic/infoblox-ddi-mcp/security/advisories/new).

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response SLAs

| Severity | Initial Response | Fix Target |
|----------|-----------------|------------|
| Critical | 24 hours        | 7 days     |
| High     | 48 hours        | 14 days    |
| Medium   | 5 business days | 30 days    |
| Low      | 10 business days | Next release |

### Process

1. Report is acknowledged within the initial response SLA
2. We investigate and confirm the vulnerability
3. A fix is developed and tested
4. A security advisory is published alongside the fix release
5. Reporter is credited (unless they prefer anonymity)

## Security Best Practices

When using this MCP server:

- **Never commit API keys** — use environment variables or `.env` files (gitignored)
- **Enable bearer token auth** for HTTP transport: set `MCP_AUTH_TOKEN`
- **Restrict network access** — bind to `127.0.0.1` instead of `0.0.0.0` for local-only use
- **Use read-only API keys** when possible for discovery/exploration workloads
- **Review dry_run output** before executing destructive operations (`manage_network`, `decommission_host`, etc.)
