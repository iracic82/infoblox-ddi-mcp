"""Shared fixtures for the Infoblox DDI MCP test suite."""

import json
import os
from unittest.mock import MagicMock

import pytest

# Set env var BEFORE importing mcp_intent so the client constructors
# don't fail during module init.
os.environ.setdefault("INFOBLOX_API_KEY", "test_key_for_ci")

import mcp_intent  # noqa: E402

# ── helpers ──────────────────────────────────────────────────────────


def _make_api_response(results: list) -> dict:
    """Simulate a BloxOne API JSON response."""
    return {"results": results}


# ── fixtures ─────────────────────────────────────────────────────────


@pytest.fixture()
def mock_infoblox_client(monkeypatch):
    """Patch ``mcp_intent.client`` with a MagicMock."""
    mock = MagicMock()
    monkeypatch.setattr(mcp_intent, "client", mock)
    return mock


@pytest.fixture()
def mock_insights_client(monkeypatch):
    """Patch ``mcp_intent.insights_client`` with a MagicMock."""
    mock = MagicMock()
    monkeypatch.setattr(mcp_intent, "insights_client", mock)
    return mock


@pytest.fixture()
def mock_atcfw_client(monkeypatch):
    """Patch ``mcp_intent.atcfw_client`` with a MagicMock."""
    mock = MagicMock()
    monkeypatch.setattr(mcp_intent, "atcfw_client", mock)
    return mock


@pytest.fixture()
def all_clients(mock_infoblox_client, mock_insights_client, mock_atcfw_client):
    """Convenience fixture combining all three service client mocks."""
    return {
        "client": mock_infoblox_client,
        "insights": mock_insights_client,
        "atcfw": mock_atcfw_client,
    }


@pytest.fixture()
def no_clients(monkeypatch):
    """Set all service clients to ``None`` to test uninitialised paths."""
    monkeypatch.setattr(mcp_intent, "client", None)
    monkeypatch.setattr(mcp_intent, "insights_client", None)
    monkeypatch.setattr(mcp_intent, "atcfw_client", None)


@pytest.fixture()
def mcp_server():
    """Return the FastMCP server instance for Client-based testing."""
    return mcp_intent.mcp


def parse_tool_result(result) -> dict:
    """Parse a FastMCP Client CallToolResult into a dict.

    ``result`` is a ``CallToolResult`` with ``.content`` — a list of
    ``TextContent`` objects.  The first element's ``.text`` is JSON.
    """
    text = result.content[0].text
    return json.loads(text)
