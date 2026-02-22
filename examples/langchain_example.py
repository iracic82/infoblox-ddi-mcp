#!/usr/bin/env python3
"""
Example: Use Infoblox DDI MCP Server with LangChain.

Prerequisites:
    pip install langchain-mcp-adapters langchain-anthropic langgraph

Start the MCP server first:
    INFOBLOX_API_KEY=your_key python mcp_intent.py --http

Then run:
    ANTHROPIC_API_KEY=your_key python examples/langchain_example.py
"""

import asyncio
import os

from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_anthropic import ChatAnthropic
from langgraph.prebuilt import create_react_agent


async def main():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Set ANTHROPIC_API_KEY environment variable")
        return

    mcp_url = os.environ.get("MCP_URL", "http://localhost:4005/mcp")

    async with MultiServerMCPClient(
        {
            "infoblox-ddi": {
                "url": mcp_url,
                "transport": "streamable_http",
            }
        }
    ) as client:
        tools = client.get_tools()
        print(f"Loaded {len(tools)} tools from Infoblox DDI MCP server\n")

        model = ChatAnthropic(model="claude-sonnet-4-20250514", api_key=api_key)
        agent = create_react_agent(model, tools)

        response = await agent.ainvoke(
            {"messages": [{"role": "user", "content": "Run a DNS diagnosis for app.example.com"}]}
        )

        # Print the final message
        for msg in response["messages"]:
            if hasattr(msg, "content") and isinstance(msg.content, str):
                print(msg.content)


if __name__ == "__main__":
    asyncio.run(main())
