"""
JSXray MCP Plugin
=================
Exposes JSXray as a full MCP server so AI assistants (Perplexity, Claude, Cursor)
can both TRIGGER scans and QUERY results without touching the CLI.

Two operating modes
-------------------
  Plugin mode   — loaded by jsxray.py after a scan finishes (read-only, one ctx)
  Standalone    — python3 -m plugins.builtin.mcp_plugin

Transports
----------
  stdio            — Claude Desktop
  streamable-http  — HTTP at http://host:port/mcp  (Perplexity, Cursor — use via ngrok)

Tools
-----
  jsxray_scan / jsxray_scan_status / jsxray_summary
  jsxray_js_endpoints / jsxray_params / jsxray_secrets / jsxray_hidden_params

TOML
----
    [plugins.mcp]
    enabled   = true
    transport = "streamable-http"
    host      = "0.0.0.0"
    port      = 9000
    allow_scan = false

Dependencies
------------
    pip install "mcp[cli]" uvicorn starlette
"""

import json
import os
import subprocess
import sys
import threading
import time
from plugins.base import BasePlugin

_scans: dict = {}
_scans_lock  = threading.Lock()


class Plugin(BasePlugin):
    name        = "mcp"
    description = "MCP server — AI can trigger scans and query results"
    version     = "0.5.0"
    plugin_type = "mcp"

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.transport  = self.config.get("transport", "streamable-http")
        self.host       = self.config.get("host", "127.0.0.1")
        self.port       = int(self.config.get("port", 9000))
        self.allow_scan = self.config.get("allow_scan", False)

    def run(self, ctx):
        _register_ctx(ctx.target, ctx)
        self.log(f"transport={self.transport}  allow_scan={self.allow_scan}")
        self._start(expose_scan_tool=self.allow_scan)
        return ctx

    def _start(self, expose_scan_tool: bool = True):
        try:
            from mcp.server.fastmcp import FastMCP  # noqa: F401
        except ImportError:
            self.log('mcp not found — pip install "mcp[cli]" uvicorn starlette')
            return
        mcp_server = _build_fastmcp(expose_scan_tool=expose_scan_tool)
        if self.transport == "streamable-http":
            _serve(mcp_server, self.host, self.port, blocking=False)
            self.log(f"Streamable HTTP → http://{self.host}:{self.port}/mcp")
        else:
            mcp_server.run(transport="stdio")


# ── Registry ────────────────────────────────────────────────────────────────

def _register_ctx(target, ctx):
    with _scans_lock:
        _scans[target] = {
            "status": "done", "ctx": ctx,
            "summary": ctx.to_summary(),
            "started": ctx.scan_start, "elapsed": ctx.elapsed(),
        }

def _get_ctx(target):
    if target:
        e = _scans.get(target)
        return e.get("ctx") if e and e["status"] == "done" else None
    with _scans_lock:
        done = [v for v in _scans.values() if v["status"] == "done" and v.get("ctx")]
    return max(done, key=lambda v: v["started"])["ctx"] if done else None

def _get_summary(target):
    if target:
        e = _scans.get(target)
        return e.get("summary") if e and e["status"] == "done" else None
    with _scans_lock:
        done = [v for v in _scans.values() if v["status"] == "done"]
    return max(done, key=lambda v: v["started"]).get("summary") if done else None


# ── FastMCP tools ───────────────────────────────────────────────────────────

def _build_fastmcp(expose_scan_tool=True):
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("jsxray")

    if expose_scan_tool:
        @mcp.tool(description="Trigger a new JSXray scan. Poll jsxray_scan_status for progress.")
        def jsxray_scan(target: str, mode: str = "quick") -> dict:
            target = target.strip()
            if not target:
                return {"error": "target required"}
            with _scans_lock:
                if _scans.get(target, {}).get("status") == "running":
                    return {"status": "already_running", "target": target}
                _scans[target] = {"status": "running", "started": time.time(), "ctx": None}
            def _run():
                try:
                    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                    r = subprocess.run(
                        [sys.executable, os.path.join(root, "jsxray.py"),
                         "-t", target, "-m", mode, "--no-dashboard", "--silent"],
                        cwd=root, capture_output=True, text=True)
                    _load_scan_output(target, root, r)
                except Exception as e:
                    with _scans_lock:
                        _scans[target].update({"status": "failed", "error": str(e)})
            threading.Thread(target=_run, daemon=True).start()
            return {"status": "started", "target": target, "mode": mode}

        @mcp.tool(description="Check status of a running or completed scan.")
        def jsxray_scan_status(target: str = "") -> dict:
            with _scans_lock:
                scans = dict(_scans)
            if target:
                e = scans.get(target)
                if not e: return {"error": f"No scan for '{target}'"}
                d = {"target": target, "status": e["status"], "elapsed": round(time.time()-e["started"],1)}
                if e["status"] == "done":   d["summary"] = e.get("summary", {})
                if e["status"] == "failed": d["error"]   = e.get("error", "unknown")
                return d
            return {t: {"status": v["status"], "elapsed": round(time.time()-v["started"],1)}
                    for t, v in scans.items()}

    @mcp.tool(description="Full scan summary: target, mode, elapsed, tech stack, stats.")
    def jsxray_summary(target: str = "") -> dict:
        ctx = _get_ctx(target or None)
        if ctx: return ctx.to_summary()
        s = _get_summary(target or None)
        return s if s else {"error": "no results"}

    @mcp.tool(description="Endpoints from JS files (fetch, XHR, API paths).")
    def jsxray_js_endpoints(target: str = "", limit: int = 200) -> list:
        ctx = _get_ctx(target or None)
        if ctx: return (ctx.js_endpoints or [])[:limit]
        s = _get_summary(target or None)
        return s.get("js_endpoints", [])[:limit] if s else []

    @mcp.tool(description="Params: global (all JS) and per_file. Filter with file_filter.")
    def jsxray_params(target: str = "", file_filter: str = "") -> dict:
        ctx = _get_ctx(target or None)
        ff = file_filter.lower()
        if ctx:
            return {"global": ctx.js_global_params,
                    "per_file": {k: v for k, v in ctx.js_param_map.items() if ff in k.lower()}}
        s = _get_summary(target or None)
        return {"global": s.get("js_global_params", []), "per_file": {}} if s else {}

    @mcp.tool(description="Secrets/credentials found in JS (API keys, tokens, passwords).")
    def jsxray_secrets(target: str = "") -> list:
        ctx = _get_ctx(target or None)
        if ctx:
            return [{"file": fd.get("url",""), **s}
                    for fd in ctx.js_file_data for s in fd.get("secrets", [])]
        s = _get_summary(target or None)
        return s.get("secrets", []) if s else []

    @mcp.tool(description="Hidden params from source map parsing. Filter with endpoint_filter.")
    def jsxray_hidden_params(target: str = "", endpoint_filter: str = "") -> dict:
        ctx = _get_ctx(target or None)
        ef = endpoint_filter.lower()
        if ctx: return {k: v for k, v in ctx.hidden_params.items() if ef in k.lower()}
        s = _get_summary(target or None)
        return {k: v for k, v in s.get("hidden_params",{}).items() if ef in k.lower()} if s else {}

    return mcp


# ── Scan output loader ──────────────────────────────────────────────────────────

def _load_scan_output(target, jsxray_root, proc_result):
    import glob
    safe = target.replace("https://","").replace("http://","").replace("/","_")
    matches = sorted(glob.glob(os.path.join(jsxray_root,"recon",safe,"*","summary.json")))
    if matches:
        try:
            with open(matches[-1]) as f: summary = json.load(f)
            with _scans_lock:
                _scans[target].update({"status":"done","summary":summary,
                                       "elapsed":summary.get("elapsed_s",0)})
            return
        except Exception:
            pass
    with _scans_lock:
        if proc_result.returncode != 0:
            _scans[target].update({"status":"failed",
                                   "error":proc_result.stderr[-500:] or "unknown"})
        else:
            _scans[target].update({"status":"done",
                                   "summary":{"note":"summary.json not found"}})


# ── Transport ─────────────────────────────────────────────────────────────────

class _HostBypassMiddleware:
    """
    ASGI middleware that rewrites the Host header to 127.0.0.1:<port>
    before passing the request to FastMCP.

    FastMCP validates the Host header and returns 421 when it doesn’t match
    the bound address (which always happens behind ngrok/Cloudflare/reverse-proxies).
    This middleware normalises the host so FastMCP always sees a local address.
    """
    def __init__(self, app, host: str, port: int):
        self.app  = app
        self.host = f"{host}:{port}".encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            # Replace host header with the actual bound address
            headers = [
                (b"host", self.host) if k == b"host" else (k, v)
                for k, v in scope.get("headers", [])
            ]
            scope = {**scope, "headers": headers}
        await self.app(scope, receive, send)


def _serve(mcp_server, host: str, port: int, blocking: bool = True):
    try:
        import uvicorn
    except ImportError:
        print("[mcp] pip install uvicorn")
        return

    inner_app = mcp_server.streamable_http_app()
    # Wrap with host-bypass middleware so ngrok/Cloudflare host headers
    # don't trigger FastMCP's 421 Misdirected Request rejection.
    app = _HostBypassMiddleware(inner_app, "127.0.0.1", port)

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="warning",
        # Disable uvicorn's own h11 host validation
        server_header=False,
        date_header=False,
    )
    srv = uvicorn.Server(config)

    if blocking:
        import asyncio
        asyncio.run(srv.serve())
    else:
        threading.Thread(target=srv.run, daemon=True).start()


# ── Standalone ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--host",      default="127.0.0.1")
    p.add_argument("--port",      type=int, default=9000)
    p.add_argument("--transport", default="streamable-http", choices=["streamable-http","stdio"])
    args = p.parse_args()

    try:
        from mcp.server.fastmcp import FastMCP  # noqa: F401
    except ImportError:
        print('[mcp] pip install "mcp[cli]" uvicorn starlette'); sys.exit(1)

    mcp_server = _build_fastmcp(expose_scan_tool=True)

    if args.transport == "stdio":
        print("[mcp] stdio (blocking)")
        mcp_server.run(transport="stdio")
    else:
        print(f"[mcp] Streamable HTTP → http://{args.host}:{args.port}/mcp")
        print("[mcp] Ctrl+C to stop")
        _serve(mcp_server, args.host, args.port, blocking=True)
