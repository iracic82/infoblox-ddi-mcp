#!/usr/bin/env python3
"""
Example: Use Infoblox DDI MCP Server with the Anthropic SDK.

Prerequisites:
    pip install anthropic

Start the MCP server first:
    INFOBLOX_API_KEY=your_key python mcp_intent.py --http

Then run:
    ANTHROPIC_API_KEY=your_key python examples/anthropic_sdk.py
"""

import os
import json
import anthropic


def main():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Set ANTHROPIC_API_KEY environment variable")
        return

    mcp_url = os.environ.get("MCP_URL", "http://localhost:4005/mcp")

    client = anthropic.Anthropic(api_key=api_key)

    # Create a message with MCP server connection
    response = client.beta.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        betas=["mcp-client-2025-04-04"],
        mcp_servers=[
            {
                "type": "url",
                "url": mcp_url,
                "name": "infoblox-ddi",
            }
        ],
        messages=[
            {
                "role": "user",
                "content": "Explore my Infoblox network and give me a summary of all IP spaces.",
            }
        ],
    )

    # Print the response
    for block in response.content:
        if hasattr(block, "text"):
            print(block.text)
        elif hasattr(block, "type") and block.type == "tool_use":
            print(f"\n[Tool call: {block.name}]")
            print(json.dumps(block.input, indent=2))


if __name__ == "__main__":
    main()
