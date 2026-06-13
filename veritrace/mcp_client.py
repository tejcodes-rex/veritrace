"""A small synchronous client for the Veritrace MCP server.

Wraps the async Model Context Protocol SDK so the agent can call MCP tools with
ordinary blocking calls. Each call opens an SSE session, runs the tool and
returns the parsed JSON. This is the client half of the MCP integration: the
agent depends on it and never imports the Splunk SDK directly.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any


class McpClient:
    def __init__(self, url: str):
        self.url = url

    async def _call(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        from mcp import ClientSession
        from mcp.client.sse import sse_client

        async with sse_client(self.url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool, args)
                text = ""
                for block in result.content:
                    if getattr(block, "type", None) == "text":
                        text += block.text
                try:
                    return json.loads(text) if text else {}
                except json.JSONDecodeError:
                    return {"raw": text}

    def call_tool(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        return asyncio.run(self._call(tool, args))

    async def _list(self) -> list[str]:
        from mcp import ClientSession
        from mcp.client.sse import sse_client

        async with sse_client(self.url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                return [t.name for t in tools.tools]

    def list_tools(self) -> list[str]:
        return asyncio.run(self._list())
