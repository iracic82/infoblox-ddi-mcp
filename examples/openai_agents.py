#!/usr/bin/env python3
"""
Example: Use Infoblox DDI MCP Server with the OpenAI Agents SDK.

Prerequisites:
    pip install openai-agents

Start the MCP server first:
    INFOBLOX_API_KEY=your_key python mcp_intent.py --http

Then run:
    OPENAI_API_KEY=your_key python examples/openai_agents.py
"""

import asyncio
import os

from agents import Agent, Runner
from agents.mcp import MCPServerStreamableHttp


async def main():
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Set OPENAI_API_KEY environment variable")
        return

    mcp_url = os.environ.get("MCP_URL", "http://localhost:4005/mcp")

    async with MCPServerStreamableHttp(url=mcp_url, name="infoblox-ddi") as mcp:
        agent = Agent(
            name="Network Engineer",
            instructions=(
                "You are a network engineer with access to Infoblox DDI. "
                "Use the available tools to explore, provision, and troubleshoot "
                "network infrastructure. Always explain what you're doing."
            ),
            mcp_servers=[mcp],
        )

        result = await Runner.run(
            agent,
            "Show me the IP utilization across all spaces and flag any subnets above 80%.",
        )

        print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
