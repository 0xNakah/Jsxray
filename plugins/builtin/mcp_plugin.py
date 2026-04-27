"""
JSXray MCP Plugin
=================
Exposes JSXray as a full MCP server so AI assistants (Perplexity, Claude, Cursor)
can both TRIGGER scans and QUERY results without touching the CLI.

Two operating modes
-------------------
  Plugin mode   — loaded by jsxray.py after a scan finishes (read-only, one ctx)
  Standalone    — python3 -m plugins.builtin.mcp_plugin
                  Persistent SSE server. AI can kick off scans on demand.

Transports
----------
  stdio  — Claude Desktop spawns the process, talks over stdin/stdout
  sse    — HTTP server at http://host:port/sse  (required for Perplexity)

Tools
-----
  jsxray_scan           — run a new scan (target, mode)  [standalone only]
  jsxray_scan_status    — poll whether a scan is running / done
  jsxray_summary        — full scan summary JSON
  jsxray_js_endpoints   — JS-extracted endpoints
  jsxray_params         — global + per-file params
  jsxray_secrets        — credential/secret hints
  jsxray_hidden_params  — hidden params from x8/arjun

TOML config (plugin mode)
-------------------------
    [plugins.mcp]
    enabled      = true
    transport    = "sse"        # "stdio" | "sse"
    host         = "127.0.0.1"
    port         = 9000
    allow_scan   = false        # true to expose jsxray_scan in plugin mode too

Standalone usage
----------------
    python3 -m plugins.builtin.mcp_plugin [--host 0.0.0.0] [--port 9000]

Dependencies
------------
    pip install mcp uvicorn starlette    # SSE transport
    pip install mcp                      # stdio only
"""

import json
import os
import subprocess
import sys
import threading
import time
from plugins.base import BasePlugin

# ── Scan registry ─────────────────────────────────────────────────────────────
#
# Keyed by target string. Each entry:
#   "status"   : "running" | "done" | "failed"
#   "ctx"      : Context object (when done)
#   "summary"  : dict from ctx.to_summary() (when done)
#   "started"  : unix timestamp
#   "elapsed"  : seconds (when done)
#
_scans: dict = {}
_scans_lock   = threading.Lock()


class Plugin(BasePlugin):
    name        = "mcp"
    description = "MCP server — AI can trigger JSXray scans and query results"
    version     = "0.2.0"
    plugin_type = "mcp"

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.transport  = self.config.get("transport", "sse")
        self.host       = self.config.get("host", "127.0.0.1")
        self.port       = int(self.config.get("port", 9000))
        self.allow_scan = self.config.get("allow_scan", False)

    # ── Plugin-mode lifecycle ───────────────────────────────────────────────

    def run(self, ctx):
        """
        Called after jsxray.py finishes all phases.
        Stores ctx in the registry then starts the MCP server.
        """
        _register_ctx(ctx.target, ctx)
        self.log(f"transport={self.transport}  allow_scan={self.allow_scan}")
        self._start(expose_scan_tool=self.allow_scan)
        return ctx

    # ── Server entry point ─────────────────────────────────────────────────

    def _start(self, expose_scan_tool: bool = True):
        try:
            import mcp.types as types
            from mcp.server import Server
        except ImportError:
            self.log(
                "'mcp' package not found.\n"
                "  pip install mcp uvicorn starlette"
            )
            return

        server = _build_server(Server, types, expose_scan_tool=expose_scan_tool)

        if self.transport == "sse":
            _serve_sse(server, self.host, self.port, blocking=False)
            self.log(
                f"SSE → http://{self.host}:{self.port}/sse\n"
                f"  Perplexity / Claude config:\n"
                f'    url: "http://{self.host}:{self.port}/sse"'
            )
        else:
            self.log("stdio transport (blocking)")
            _serve_stdio(server)


# ── Scan registry helpers ────────────────────────────────────────────────────

def _register_ctx(target: str, ctx):
    with _scans_lock:
        _scans[target] = {
            "status":  "done",
            "ctx":     ctx,
            "summary": ctx.to_summary(),
            "started": ctx.scan_start,
            "elapsed": ctx.elapsed(),
        }


def _latest_ctx():
    """Return the most recently completed ctx, or None."""
    with _scans_lock:
        done = [
            v for v in _scans.values()
            if v["status"] == "done" and v.get("ctx") is not None
        ]
    if not done:
        return None
    return max(done, key=lambda v: v["started"])["ctx"]


def _get_ctx(target: str | None):
    """Return ctx for a specific target, or fall back to latest."""
    if target:
        entry = _scans.get(target)
        if entry and entry["status"] == "done":
            return entry["ctx"]
        return None
    return _latest_ctx()


# ── MCP server builder ────────────────────────────────────────────────────────

def _build_server(Server, types, expose_scan_tool: bool = True):
    server = Server("jsxray")

    # ── list_tools ────────────────────────────────────────────────────────
    @server.list_tools()
    async def list_tools():
        tools = []

        if expose_scan_tool:
            tools += [
                types.Tool(
                    name="jsxray_scan",
                    description=(
                        "Trigger a new JSXray scan against a target domain. "
                        "The scan runs in the background. Poll jsxray_scan_status "
                        "to check progress, then use the read tools to query results."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "Target domain or URL, e.g. target.com",
                            },
                            "mode": {
                                "type": "string",
                                "enum": ["quick", "standard", "full"],
                                "description": "Scan depth. quick=no external tools, standard=passive+deep, full=+subdomains. Default: quick.",
                            },
                        },
                        "required": ["target"],
                    },
                ),
                types.Tool(
                    name="jsxray_scan_status",
                    description="Check the status of a running or completed scan.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "Target to check. Omit to list all scans.",
                            }
                        },
                    },
                ),
            ]

        tools += [
            types.Tool(
                name="jsxray_summary",
                description=(
                    "Return the full scan summary: target, mode, elapsed, "
                    "tech stack, and all stats (JS files, endpoints, params, secrets, hidden params)."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target to query. Omit to use the most recent scan.",
                        }
                    },
                },
            ),
            types.Tool(
                name="jsxray_js_endpoints",
                description="List all endpoints extracted from JavaScript files (fetch, XHR, API paths).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target to query. Omit for latest."},
                        "limit":  {"type": "integer", "description": "Max results (default 200)."},
                    },
                },
            ),
            types.Tool(
                name="jsxray_params",
                description=(
                    "List all discovered parameters. Returns 'global' (across all JS) "
                    "and 'per_file' (per JS file). Filter by file_filter substring."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target":      {"type": "string", "description": "Target to query. Omit for latest."},
                        "file_filter": {"type": "string", "description": "Filter by JS filename substring."},
                    },
                },
            ),
            types.Tool(
                name="jsxray_secrets",
                description="List credential/secret hints found in JS files (API keys, tokens, passwords).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target to query. Omit for latest."},
                    },
                },
            ),
            types.Tool(
                name="jsxray_hidden_params",
                description="List hidden params found by x8/arjun fuzzing. Filter by endpoint_filter substring.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target":          {"type": "string", "description": "Target to query. Omit for latest."},
                        "endpoint_filter": {"type": "string", "description": "Filter by endpoint URL substring."},
                    },
                },
            ),
        ]
        return tools

    # ── call_tool ────────────────────────────────────────────────────────
    @server.call_tool()
    async def call_tool(name: str, arguments: dict | None):
        a = arguments or {}

        # ── jsxray_scan ─────────────────────────────────────────────────
        if name == "jsxray_scan":
            target = a.get("target", "").strip()
            mode   = a.get("mode", "quick")

            if not target:
                return [types.TextContent(type="text", text=json.dumps({"error": "target is required"}))]

            with _scans_lock:
                existing = _scans.get(target, {})
                if existing.get("status") == "running":
                    return [types.TextContent(type="text", text=json.dumps({
                        "status":  "already_running",
                        "target":  target,
                        "message": "Scan already in progress. Poll jsxray_scan_status.",
                    }))]
                _scans[target] = {"status": "running", "started": time.time(), "ctx": None}

            def _run_scan():
                try:
                    jsxray_root = os.path.dirname(
                        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                    )
                    cmd = [
                        sys.executable,
                        os.path.join(jsxray_root, "jsxray.py"),
                        "-t", target,
                        "-m", mode,
                        "--no-dashboard",
                        "--silent",
                    ]
                    result = subprocess.run(
                        cmd,
                        cwd=jsxray_root,
                        capture_output=True,
                        text=True,
                    )
                    # Load the output JSON from the workspace
                    _load_scan_output(target, jsxray_root, result)
                except Exception as e:
                    with _scans_lock:
                        _scans[target]["status"] = "failed"
                        _scans[target]["error"]  = str(e)

            threading.Thread(target=_run_scan, daemon=True).start()

            return [types.TextContent(type="text", text=json.dumps({
                "status":  "started",
                "target":  target,
                "mode":    mode,
                "message": "Scan started. Poll jsxray_scan_status for updates, then query results.",
            }))]

        # ── jsxray_scan_status ──────────────────────────────────────────
        if name == "jsxray_scan_status":
            target = a.get("target")
            with _scans_lock:
                if target:
                    entry = _scans.get(target)
                    if not entry:
                        data = {"error": f"No scan found for '{target}'"}
                    else:
                        data = {
                            "target":  target,
                            "status":  entry["status"],
                            "elapsed": round(time.time() - entry["started"], 1),
                        }
                        if entry["status"] == "done":
                            data["summary"] = entry.get("summary", {})
                        if entry["status"] == "failed":
                            data["error"] = entry.get("error", "unknown error")
                else:
                    data = {
                        t: {"status": v["status"], "elapsed": round(time.time() - v["started"], 1)}
                        for t, v in _scans.items()
                    }
            return [types.TextContent(type="text", text=json.dumps(data, indent=2))]

        # ── read tools ─────────────────────────────────────────────────
        ctx = _get_ctx(a.get("target"))

        if name == "jsxray_summary":
            data = ctx.to_summary() if ctx else {"error": "no scan results available"}
            return [types.TextContent(type="text", text=json.dumps(data, indent=2))]

        if name == "jsxray_js_endpoints":
            limit = int(a.get("limit", 200))
            data  = (ctx.js_endpoints or [])[:limit] if ctx else []
            return [types.TextContent(type="text", text=json.dumps(data, indent=2))]

        if name == "jsxray_params":
            ff = a.get("file_filter", "").lower()
            data = {
                "global":   ctx.js_global_params,
                "per_file": {k: v for k, v in ctx.js_param_map.items() if ff in k.lower()},
            } if ctx else {}
            return [types.TextContent(type="text", text=json.dumps(data, indent=2))]

        if name == "jsxray_secrets":
            secrets = []
            if ctx:
                for fd in ctx.js_file_data:
                    for s in fd.get("secrets", []):
                        secrets.append({"file": fd.get("url", ""), **s})
            return [types.TextContent(type="text", text=json.dumps(secrets, indent=2))]

        if name == "jsxray_hidden_params":
            ef = a.get("endpoint_filter", "").lower()
            data = {
                k: v for k, v in ctx.hidden_params.items() if ef in k.lower()
            } if ctx else {}
            return [types.TextContent(type="text", text=json.dumps(data, indent=2))]

        return [types.TextContent(type="text", text=f"Unknown tool: {name}")]

    return server


def _load_scan_output(target: str, jsxray_root: str, proc_result):
    """
    After jsxray.py finishes, reconstruct a lightweight summary from the
    output JSON written to the workspace and store it in _scans.
    We import Context and replay from the saved summary.json if present.
    """
    import glob

    safe_target = (
        target.replace("https://", "")
               .replace("http://", "")
               .replace("/", "_")
    )
    pattern = os.path.join(jsxray_root, "recon", safe_target, "*", "summary.json")
    matches = sorted(glob.glob(pattern))

    if matches:
        latest = matches[-1]
        try:
            with open(latest) as f:
                summary = json.load(f)
            with _scans_lock:
                _scans[target]["status"]  = "done"
                _scans[target]["summary"] = summary
                _scans[target]["elapsed"] = summary.get("elapsed_s", 0)
            return
        except Exception:
            pass

    # Fallback: mark done with stderr as error note
    with _scans_lock:
        if proc_result.returncode != 0:
            _scans[target]["status"] = "failed"
            _scans[target]["error"]  = proc_result.stderr[-500:] if proc_result.stderr else "unknown"
        else:
            _scans[target]["status"]  = "done"
            _scans[target]["summary"] = {"note": "summary.json not found in workspace"}


# ── Transport helpers ────────────────────────────────────────────────────────────

def _serve_stdio(server):
    import asyncio
    import mcp.server.stdio as mcp_stdio

    async def _run():
        async with mcp_stdio.stdio_server() as (read, write):
            await server.run(
                read, write,
                server.create_initialization_options(),
                raise_exceptions=True,
            )
    asyncio.run(_run())


def _serve_sse(server, host: str, port: int, blocking: bool = True):
    try:
        from mcp.server.sse import SseServerTransport
        from starlette.applications import Starlette
        from starlette.routing import Mount, Route
        import uvicorn
    except ImportError as e:
        print(f"[mcp] SSE deps missing: {e} — pip install mcp uvicorn starlette")
        return

    sse = SseServerTransport("/messages")

    async def handle_sse(request):
        async with sse.connect_sse(
            request.scope, request.receive, request._send
        ) as (read, write):
            await server.run(read, write, server.create_initialization_options())

    app = Starlette(routes=[
        Route("/sse",      endpoint=handle_sse),
        Mount("/messages", app=sse.handle_post_message),
    ])

    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    srv    = uvicorn.Server(config)

    if blocking:
        import asyncio
        asyncio.run(srv.serve())
    else:
        thread = threading.Thread(target=srv.run, daemon=True)
        thread.start()


# ── Standalone entry point ──────────────────────────────────────────────────────
#
# python3 -m plugins.builtin.mcp_plugin
# python3 -m plugins.builtin.mcp_plugin --host 0.0.0.0 --port 9000

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="JSXray MCP standalone server")
    p.add_argument("--host",      default="127.0.0.1")
    p.add_argument("--port",      type=int, default=9000)
    p.add_argument("--transport", default="sse", choices=["sse", "stdio"])
    args = p.parse_args()

    try:
        import mcp.types as types
        from mcp.server import Server
    except ImportError:
        print("[mcp] Install: pip install mcp uvicorn starlette")
        sys.exit(1)

    server = _build_server(Server, types, expose_scan_tool=True)

    if args.transport == "stdio":
        print("[mcp] stdio transport (blocking)")
        _serve_stdio(server)
    else:
        print(f"[mcp] SSE server → http://{args.host}:{args.port}/sse")
        print(f"[mcp] Perplexity config: url = \"http://{args.host}:{args.port}/sse\"")
        print("[mcp] Waiting for connections... (Ctrl+C to stop)")
        _serve_sse(server, args.host, args.port, blocking=True)
