"""
JSXray MCP Plugin
=================
Exposes JSXray scan results as an MCP (Model Context Protocol) server so
AI assistants (Claude Desktop, Cursor, etc.) can query scan data directly.

Transports
----------
  stdio  — default. Claude Desktop spawns the process and talks over stdin/stdout.
  sse    — HTTP server. Any MCP client connects to http://host:port/sse.

Tools exposed
-------------
  jsxray_summary        — full scan summary (target, mode, stats, elapsed)
  jsxray_js_endpoints   — all JS-extracted endpoints (optional limit)
  jsxray_params         — global params + per-file param map (optional file filter)
  jsxray_secrets        — credential/secret hints found in JS files
  jsxray_hidden_params  — hidden params discovered by x8/arjun (optional endpoint filter)

TOML config
-----------
    [plugins.mcp]
    enabled   = true
    transport = "stdio"     # "stdio" | "sse"
    host      = "127.0.0.1" # sse only
    port      = 9000        # sse only

Dependencies
------------
  pip install mcp                        # stdio transport
  pip install mcp uvicorn starlette      # sse transport
"""

import json
import threading
from plugins.base import BasePlugin


class Plugin(BasePlugin):
    name        = "mcp"
    description = "MCP server — exposes JSXray scan results to AI assistants"
    version     = "0.1.0"
    plugin_type = "mcp"

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.transport = self.config.get("transport", "stdio")
        self.host      = self.config.get("host", "127.0.0.1")
        self.port      = int(self.config.get("port", 9000))
        self._ctx      = None

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def run(self, ctx) -> None:
        """Store the completed ctx then start the MCP server."""
        self._ctx = ctx
        self.log(f"transport={self.transport}")
        try:
            import mcp.types as types
            from mcp.server import Server
        except ImportError:
            self.log(
                "'mcp' package not found.\n"
                "  Install: pip install mcp\n"
                "  SSE:     pip install mcp uvicorn starlette"
            )
            return ctx

        server = self._build_server(Server, types)

        if self.transport == "sse":
            self._serve_sse(server)
        else:
            self._serve_stdio(server)

        return ctx

    # ── Server builder ───────────────────────────────────────────────────────

    def _build_server(self, Server, types):
        """Register all tools and return the configured Server instance."""
        server = Server("jsxray")

        @server.list_tools()
        async def list_tools():
            return [
                types.Tool(
                    name="jsxray_summary",
                    description=(
                        "Return the full JSXray scan summary: target, mode, "
                        "elapsed time, tech stack, phase results, and all stats "
                        "(JS files, endpoints, params, secrets, hidden params)."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {},
                    },
                ),
                types.Tool(
                    name="jsxray_js_endpoints",
                    description=(
                        "List all endpoints extracted from JavaScript files. "
                        "These are API paths, fetch() URLs, XHR targets found "
                        "by static JS analysis."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of results to return (default: 200).",
                            }
                        },
                    },
                ),
                types.Tool(
                    name="jsxray_params",
                    description=(
                        "List all discovered URL/query parameters. Returns two "
                        "groups: 'global' (seen across all JS) and 'per_file' "
                        "(params found in each specific JS file). Use file_filter "
                        "to narrow by filename substring."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "file_filter": {
                                "type": "string",
                                "description": "Only return files whose URL contains this substring.",
                            }
                        },
                    },
                ),
                types.Tool(
                    name="jsxray_secrets",
                    description=(
                        "List credential and secret hints found inside JavaScript "
                        "files: API keys, tokens, passwords, private URLs. Each "
                        "result includes the source JS file URL."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {},
                    },
                ),
                types.Tool(
                    name="jsxray_hidden_params",
                    description=(
                        "List hidden/undocumented parameters discovered by active "
                        "fuzzing (x8, arjun). Keyed by endpoint URL. Use "
                        "endpoint_filter to narrow by URL substring."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "endpoint_filter": {
                                "type": "string",
                                "description": "Only return endpoints whose URL contains this substring.",
                            }
                        },
                    },
                ),
            ]

        @server.call_tool()
        async def call_tool(name: str, arguments: dict | None):
            args = arguments or {}
            ctx  = self._ctx

            if name == "jsxray_summary":
                data = ctx.to_summary() if ctx else {"error": "no scan context available"}
                return [types.TextContent(type="text", text=json.dumps(data, indent=2))]

            if name == "jsxray_js_endpoints":
                limit = int(args.get("limit", 200))
                data  = (ctx.js_endpoints or [])[:limit] if ctx else []
                return [types.TextContent(type="text", text=json.dumps(data, indent=2))]

            if name == "jsxray_params":
                ff = args.get("file_filter", "").lower()
                if ctx:
                    data = {
                        "global":   ctx.js_global_params,
                        "per_file": {
                            k: v
                            for k, v in ctx.js_param_map.items()
                            if ff in k.lower()
                        },
                    }
                else:
                    data = {}
                return [types.TextContent(type="text", text=json.dumps(data, indent=2))]

            if name == "jsxray_secrets":
                secrets = []
                if ctx:
                    for fd in ctx.js_file_data:
                        for s in fd.get("secrets", []):
                            secrets.append({"file": fd.get("url", ""), **s})
                return [types.TextContent(type="text", text=json.dumps(secrets, indent=2))]

            if name == "jsxray_hidden_params":
                ef = args.get("endpoint_filter", "").lower()
                if ctx:
                    data = {
                        k: v
                        for k, v in ctx.hidden_params.items()
                        if ef in k.lower()
                    }
                else:
                    data = {}
                return [types.TextContent(type="text", text=json.dumps(data, indent=2))]

            return [types.TextContent(type="text", text=f"Unknown tool: {name}")]

        return server

    # ── stdio transport ─────────────────────────────────────────────────────

    def _serve_stdio(self, server):
        """
        Blocking stdio transport.
        Used when Claude Desktop (or any MCP client) spawns jsxray.py
        as a subprocess and communicates over stdin/stdout.
        """
        import asyncio
        import mcp.server.stdio as mcp_stdio

        self.log("starting stdio server (blocking)")

        async def _run():
            async with mcp_stdio.stdio_server() as (read, write):
                await server.run(
                    read, write,
                    server.create_initialization_options(),
                    raise_exceptions=True,
                )

        asyncio.run(_run())

    # ── SSE transport ───────────────────────────────────────────────────────

    def _serve_sse(self, server):
        """
        Non-blocking SSE transport (daemon thread).
        Any MCP HTTP client connects to http://host:port/sse.
        The scan dashboard continues to run alongside it.
        """
        try:
            from mcp.server.sse import SseServerTransport
            from starlette.applications import Starlette
            from starlette.routing import Mount, Route
            import uvicorn
        except ImportError as e:
            self.log(f"SSE deps missing: {e} — run: pip install mcp uvicorn starlette")
            return

        sse = SseServerTransport("/messages")

        async def handle_sse(request):
            async with sse.connect_sse(
                request.scope, request.receive, request._send
            ) as (read, write):
                await server.run(
                    read, write,
                    server.create_initialization_options(),
                )

        app = Starlette(
            routes=[
                Route("/sse",      endpoint=handle_sse),
                Mount("/messages", app=sse.handle_post_message),
            ]
        )

        def _serve():
            uvicorn.run(
                app,
                host=self.host,
                port=self.port,
                log_level="warning",
            )

        thread = threading.Thread(target=_serve, daemon=True)
        thread.start()

        self.log(
            f"SSE server listening → http://{self.host}:{self.port}/sse\n"
            f"  Claude Desktop config:\n"
            f'    "jsxray": {{\n'
            f'      "type": "sse",\n'
            f'      "url":  "http://{self.host}:{self.port}/sse"\n'
            f'    }}'
        )
