"""
JSXray MCP Plugin
=================
Exposes JSXray as a full MCP server so AI assistants (Perplexity, Claude, Cursor)
can both TRIGGER scans and QUERY results without touching the CLI.

Two operating modes
-------------------
  Plugin mode   — loaded by jsxray.py after a scan finishes (read-only, one ctx)
  Standalone    — python3 -m plugins.builtin.mcp_plugin
                  Persistent server. AI can kick off scans on demand.

Transports
----------
  stdio            — Claude Desktop spawns the process, talks over stdin/stdout
  streamable-http  — HTTP server at http://host:port/mcp  (Perplexity, Cursor, etc.)
                     Supersedes the legacy /sse transport (mcp >= 1.6)

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
    transport    = "streamable-http"   # "stdio" | "streamable-http"
    host         = "127.0.0.1"
    port         = 9000
    allow_scan   = false               # true to expose jsxray_scan in plugin mode too

Standalone usage
----------------
    python3 -m plugins.builtin.mcp_plugin [--host 0.0.0.0] [--port 9000] [--transport streamable-http]

Dependencies
------------
    pip install "mcp[cli]" uvicorn starlette    # streamable-http transport
    pip install mcp                              # stdio only
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
#   "status"  : "running" | "done" | "failed"
#   "ctx"     : Context object (when done, plugin mode only)
#   "summary" : dict from ctx.to_summary() or loaded from summary.json
#   "started" : unix timestamp
#   "elapsed" : seconds (when done)
#
_scans: dict = {}
_scans_lock  = threading.Lock()


class Plugin(BasePlugin):
    name        = "mcp"
    description = "MCP server — AI can trigger JSXray scans and query results"
    version     = "0.3.0"
    plugin_type = "mcp"

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.transport  = self.config.get("transport", "streamable-http")
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
            from mcp.server.fastmcp import FastMCP
        except ImportError:
            self.log(
                "'mcp' package not found.\n"
                '  pip install "mcp[cli]" uvicorn starlette'
            )
            return

        mcp_server = _build_fastmcp(expose_scan_tool=expose_scan_tool)

        if self.transport == "streamable-http":
            _serve_streamable_http(mcp_server, self.host, self.port, blocking=False)
            self.log(
                f"Streamable HTTP → http://{self.host}:{self.port}/mcp\n"
                f"  Perplexity / Cursor config:\n"
                f'    url: "http://{self.host}:{self.port}/mcp"'
            )
        else:
            self.log("stdio transport (blocking)")
            mcp_server.run(transport="stdio")


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
            return entry.get("ctx")
        return None
    return _latest_ctx()


def _get_summary(target: str | None) -> dict | None:
    """Return summary dict for a target even when ctx is None (standalone mode)."""
    if target:
        entry = _scans.get(target)
        if entry and entry["status"] == "done":
            return entry.get("summary")
        return None
    with _scans_lock:
        done = [v for v in _scans.values() if v["status"] == "done"]
    if not done:
        return None
    return max(done, key=lambda v: v["started"]).get("summary")


# ── FastMCP server builder ────────────────────────────────────────────────────

def _build_fastmcp(expose_scan_tool: bool = True):
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("jsxray")

    # ── jsxray_scan ────────────────────────────────────────────────────────
    if expose_scan_tool:
        @mcp.tool(
            description=(
                "Trigger a new JSXray scan against a target domain. "
                "The scan runs in the background. Poll jsxray_scan_status "
                "to check progress, then use the read tools to query results."
            )
        )
        def jsxray_scan(target: str, mode: str = "quick") -> dict:
            """
            Args:
                target: Target domain or URL, e.g. target.com
                mode:   Scan depth — quick | standard | full
            """
            target = target.strip()
            if not target:
                return {"error": "target is required"}

            with _scans_lock:
                existing = _scans.get(target, {})
                if existing.get("status") == "running":
                    return {
                        "status":  "already_running",
                        "target":  target,
                        "message": "Scan already in progress. Poll jsxray_scan_status.",
                    }
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
                    _load_scan_output(target, jsxray_root, result)
                except Exception as e:
                    with _scans_lock:
                        _scans[target]["status"] = "failed"
                        _scans[target]["error"]  = str(e)

            threading.Thread(target=_run_scan, daemon=True).start()

            return {
                "status":  "started",
                "target":  target,
                "mode":    mode,
                "message": "Scan started. Poll jsxray_scan_status for updates, then query results.",
            }

        @mcp.tool(description="Check the status of a running or completed scan.")
        def jsxray_scan_status(target: str = "") -> dict:
            """
            Args:
                target: Target to check. Omit to list all scans.
            """
            with _scans_lock:
                if target:
                    entry = _scans.get(target)
                    if not entry:
                        return {"error": f"No scan found for '{target}'"}
                    data = {
                        "target":  target,
                        "status":  entry["status"],
                        "elapsed": round(time.time() - entry["started"], 1),
                    }
                    if entry["status"] == "done":
                        data["summary"] = entry.get("summary", {})
                    if entry["status"] == "failed":
                        data["error"] = entry.get("error", "unknown error")
                    return data
                return {
                    t: {"status": v["status"], "elapsed": round(time.time() - v["started"], 1)}
                    for t, v in _scans.items()
                }

    # ── read tools ─────────────────────────────────────────────────────────

    @mcp.tool(
        description=(
            "Return the full scan summary: target, mode, elapsed, "
            "tech stack, and all stats (JS files, endpoints, params, secrets, hidden params)."
        )
    )
    def jsxray_summary(target: str = "") -> dict:
        ctx = _get_ctx(target or None)
        if ctx:
            return ctx.to_summary()
        summary = _get_summary(target or None)
        return summary if summary else {"error": "no scan results available"}

    @mcp.tool(description="List all endpoints extracted from JavaScript files (fetch, XHR, API paths).")
    def jsxray_js_endpoints(target: str = "", limit: int = 200) -> list:
        ctx = _get_ctx(target or None)
        if ctx:
            return (ctx.js_endpoints or [])[:limit]
        summary = _get_summary(target or None)
        if summary:
            return summary.get("js_endpoints", [])[:limit]
        return []

    @mcp.tool(
        description=(
            "List all discovered parameters. Returns 'global' (across all JS) "
            "and 'per_file' (per JS file). Filter by file_filter substring."
        )
    )
    def jsxray_params(target: str = "", file_filter: str = "") -> dict:
        ctx = _get_ctx(target or None)
        ff  = file_filter.lower()
        if ctx:
            return {
                "global":   ctx.js_global_params,
                "per_file": {k: v for k, v in ctx.js_param_map.items() if ff in k.lower()},
            }
        summary = _get_summary(target or None)
        if summary:
            return {
                "global":   summary.get("js_global_params", []),
                "per_file": {},
            }
        return {}

    @mcp.tool(description="List credential/secret hints found in JS files (API keys, tokens, passwords).")
    def jsxray_secrets(target: str = "") -> list:
        ctx = _get_ctx(target or None)
        if ctx:
            secrets = []
            for fd in ctx.js_file_data:
                for s in fd.get("secrets", []):
                    secrets.append({"file": fd.get("url", ""), **s})
            return secrets
        summary = _get_summary(target or None)
        if summary:
            return summary.get("secrets", [])
        return []

    @mcp.tool(description="List hidden params found by x8/arjun fuzzing. Filter by endpoint_filter substring.")
    def jsxray_hidden_params(target: str = "", endpoint_filter: str = "") -> dict:
        ctx = _get_ctx(target or None)
        ef  = endpoint_filter.lower()
        if ctx:
            return {k: v for k, v in ctx.hidden_params.items() if ef in k.lower()}
        summary = _get_summary(target or None)
        if summary:
            return {
                k: v for k, v in summary.get("hidden_params", {}).items()
                if ef in k.lower()
            }
        return {}

    return mcp


# ── Scan output loader ────────────────────────────────────────────────────────

def _load_scan_output(target: str, jsxray_root: str, proc_result):
    """
    After jsxray.py finishes, load summary.json from the workspace and
    store it in _scans. Works in standalone mode where ctx is never set.
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

    with _scans_lock:
        if proc_result.returncode != 0:
            _scans[target]["status"] = "failed"
            _scans[target]["error"]  = proc_result.stderr[-500:] if proc_result.stderr else "unknown"
        else:
            _scans[target]["status"]  = "done"
            _scans[target]["summary"] = {"note": "summary.json not found in workspace"}


# ── Transport helpers ─────────────────────────────────────────────────────────

def _serve_streamable_http(mcp_server, host: str, port: int, blocking: bool = True):
    """
    Mount the FastMCP app at /mcp using Starlette + uvicorn.
    FastMCP.streamable_http_app() returns a proper ASGI app — no manual
    SSE wiring needed, fully compatible with mcp >= 1.6 / 1.27.
    """
    try:
        from starlette.applications import Starlette
        from starlette.routing import Mount
        import uvicorn
    except ImportError as e:
        print(f"[mcp] Missing deps: {e}  →  pip install uvicorn starlette")
        return

    app = Starlette(routes=[
        Mount("/mcp", app=mcp_server.streamable_http_app()),
    ])

    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    srv    = uvicorn.Server(config)

    if blocking:
        import asyncio
        asyncio.run(srv.serve())
    else:
        thread = threading.Thread(target=srv.run, daemon=True)
        thread.start()


# ── Standalone entry point ────────────────────────────────────────────────────
#
#  python3 -m plugins.builtin.mcp_plugin
#  python3 -m plugins.builtin.mcp_plugin --host 0.0.0.0 --port 9000
#  python3 -m plugins.builtin.mcp_plugin --transport stdio

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="JSXray MCP standalone server")
    p.add_argument("--host",      default="127.0.0.1")
    p.add_argument("--port",      type=int, default=9000)
    p.add_argument("--transport", default="streamable-http",
                   choices=["streamable-http", "stdio"])
    args = p.parse_args()

    try:
        from mcp.server.fastmcp import FastMCP  # noqa: F401
    except ImportError:
        print('[mcp] Install: pip install "mcp[cli]" uvicorn starlette')
        sys.exit(1)

    mcp_server = _build_fastmcp(expose_scan_tool=True)

    if args.transport == "stdio":
        print("[mcp] stdio transport (blocking)")
        mcp_server.run(transport="stdio")
    else:
        url = f"http://{args.host}:{args.port}/mcp"
        print(f"[mcp] Streamable HTTP → {url}")
        print(f'[mcp] Perplexity / Cursor config: url = "{url}"')
        print("[mcp] Waiting for connections... (Ctrl+C to stop)")
        _serve_streamable_http(mcp_server, args.host, args.port, blocking=True)
