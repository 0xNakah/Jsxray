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
                     Uses FastMCP served directly via uvicorn (mcp >= 1.6)

Tools
-----
  jsxray_scan           — run a new scan (target, mode)  [standalone only]
  jsxray_scan_status    — poll whether a scan is running / done
  jsxray_summary        — full scan summary JSON
  jsxray_js_endpoints   — JS-extracted endpoints
  jsxray_params         — global + per-file params
  jsxray_secrets        — credential/secret hints
  jsxray_hidden_params  — hidden params (source maps only, no active probing)

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
    pip install "mcp[cli]" uvicorn    # streamable-http transport
    pip install mcp                   # stdio only
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
    description = "MCP server — AI can trigger JSXray scans and query results"
    version     = "0.4.0"
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
            self.log('mcp not found — pip install "mcp[cli]" uvicorn')
            return

        mcp_server = _build_fastmcp(expose_scan_tool=expose_scan_tool)

        if self.transport == "streamable-http":
            _serve(mcp_server, self.host, self.port, blocking=False)
            self.log(
                f"Streamable HTTP → http://{self.host}:{self.port}/mcp\n"
                f'  Perplexity / Cursor url = "http://{self.host}:{self.port}/mcp"'
            )
        else:
            self.log("stdio transport (blocking)")
            mcp_server.run(transport="stdio")


# ── Registry helpers ────────────────────────────────────────────────────────────

def _register_ctx(target: str, ctx):
    with _scans_lock:
        _scans[target] = {
            "status":  "done",
            "ctx":     ctx,
            "summary": ctx.to_summary(),
            "started": ctx.scan_start,
            "elapsed": ctx.elapsed(),
        }


def _get_ctx(target: str | None):
    if target:
        entry = _scans.get(target)
        return entry.get("ctx") if entry and entry["status"] == "done" else None
    with _scans_lock:
        done = [v for v in _scans.values() if v["status"] == "done" and v.get("ctx")]
    return max(done, key=lambda v: v["started"])["ctx"] if done else None


def _get_summary(target: str | None):
    if target:
        entry = _scans.get(target)
        return entry.get("summary") if entry and entry["status"] == "done" else None
    with _scans_lock:
        done = [v for v in _scans.values() if v["status"] == "done"]
    return max(done, key=lambda v: v["started"]).get("summary") if done else None


# ── FastMCP builder ──────────────────────────────────────────────────────────────

def _build_fastmcp(expose_scan_tool: bool = True):
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("jsxray")

    if expose_scan_tool:

        @mcp.tool(description=(
            "Trigger a new JSXray scan against a target domain. "
            "Runs in the background — poll jsxray_scan_status for progress."
        ))
        def jsxray_scan(target: str, mode: str = "quick") -> dict:
            target = target.strip()
            if not target:
                return {"error": "target is required"}
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
                        cwd=root, capture_output=True, text=True,
                    )
                    _load_scan_output(target, root, r)
                except Exception as e:
                    with _scans_lock:
                        _scans[target].update({"status": "failed", "error": str(e)})

            threading.Thread(target=_run, daemon=True).start()
            return {"status": "started", "target": target, "mode": mode,
                    "message": "Poll jsxray_scan_status for updates."}

        @mcp.tool(description="Check status of a running or completed scan.")
        def jsxray_scan_status(target: str = "") -> dict:
            with _scans_lock:
                scans = dict(_scans)
            if target:
                entry = scans.get(target)
                if not entry:
                    return {"error": f"No scan found for '{target}'"}
                data = {"target": target, "status": entry["status"],
                        "elapsed": round(time.time() - entry["started"], 1)}
                if entry["status"] == "done":    data["summary"] = entry.get("summary", {})
                if entry["status"] == "failed":  data["error"]   = entry.get("error", "unknown")
                return data
            return {t: {"status": v["status"], "elapsed": round(time.time() - v["started"], 1)}
                    for t, v in scans.items()}

    @mcp.tool(description="Full scan summary: target, mode, elapsed, tech stack, all stats.")
    def jsxray_summary(target: str = "") -> dict:
        ctx = _get_ctx(target or None)
        if ctx: return ctx.to_summary()
        s = _get_summary(target or None)
        return s if s else {"error": "no scan results available"}

    @mcp.tool(description="Endpoints extracted from JavaScript files (fetch, XHR, API paths).")
    def jsxray_js_endpoints(target: str = "", limit: int = 200) -> list:
        ctx = _get_ctx(target or None)
        if ctx: return (ctx.js_endpoints or [])[:limit]
        s = _get_summary(target or None)
        return s.get("js_endpoints", [])[:limit] if s else []

    @mcp.tool(description="Discovered parameters: 'global' (all JS) and 'per_file'. Filter with file_filter.")
    def jsxray_params(target: str = "", file_filter: str = "") -> dict:
        ctx = _get_ctx(target or None)
        ff = file_filter.lower()
        if ctx:
            return {"global": ctx.js_global_params,
                    "per_file": {k: v for k, v in ctx.js_param_map.items() if ff in k.lower()}}
        s = _get_summary(target or None)
        return {"global": s.get("js_global_params", []), "per_file": {}} if s else {}

    @mcp.tool(description="Credential/secret hints found in JS files (API keys, tokens, passwords).")
    def jsxray_secrets(target: str = "") -> list:
        ctx = _get_ctx(target or None)
        if ctx:
            return [{"file": fd.get("url", ""), **s}
                    for fd in ctx.js_file_data for s in fd.get("secrets", [])]
        s = _get_summary(target or None)
        return s.get("secrets", []) if s else []

    @mcp.tool(description="Hidden params from source map parsing. Filter with endpoint_filter.")
    def jsxray_hidden_params(target: str = "", endpoint_filter: str = "") -> dict:
        ctx = _get_ctx(target or None)
        ef = endpoint_filter.lower()
        if ctx:
            return {k: v for k, v in ctx.hidden_params.items() if ef in k.lower()}
        s = _get_summary(target or None)
        return {k: v for k, v in s.get("hidden_params", {}).items() if ef in k.lower()} if s else {}

    return mcp


# ── Scan output loader ────────────────────────────────────────────────────────────

def _load_scan_output(target: str, jsxray_root: str, proc_result):
    import glob
    safe = target.replace("https://", "").replace("http://", "").replace("/", "_")
    matches = sorted(glob.glob(os.path.join(jsxray_root, "recon", safe, "*", "summary.json")))
    if matches:
        try:
            with open(matches[-1]) as f:
                summary = json.load(f)
            with _scans_lock:
                _scans[target].update({"status": "done", "summary": summary,
                                       "elapsed": summary.get("elapsed_s", 0)})
            return
        except Exception:
            pass
    with _scans_lock:
        if proc_result.returncode != 0:
            _scans[target].update({"status": "failed",
                                   "error": proc_result.stderr[-500:] or "unknown"})
        else:
            _scans[target].update({"status": "done",
                                   "summary": {"note": "summary.json not found"}})


# ── Transport ───────────────────────────────────────────────────────────────────

def _serve(mcp_server, host: str, port: int, blocking: bool = True):
    """
    Serve FastMCP directly via uvicorn at /mcp.
    Bypasses Starlette Mount entirely to avoid 307 redirect loops.
    FastMCP.streamable_http_app() is a self-contained ASGI app that
    already handles all routing internally.
    """
    try:
        import uvicorn
    except ImportError:
        print("[mcp] pip install uvicorn")
        return

    asgi_app = mcp_server.streamable_http_app()
    config   = uvicorn.Config(asgi_app, host=host, port=port, log_level="warning")
    srv      = uvicorn.Server(config)

    if blocking:
        import asyncio
        asyncio.run(srv.serve())
    else:
        threading.Thread(target=srv.run, daemon=True).start()


# ── Standalone entry point ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="JSXray MCP standalone server")
    p.add_argument("--host",      default="127.0.0.1")
    p.add_argument("--port",      type=int, default=9000)
    p.add_argument("--transport", default="streamable-http", choices=["streamable-http", "stdio"])
    args = p.parse_args()

    try:
        from mcp.server.fastmcp import FastMCP  # noqa: F401
    except ImportError:
        print('[mcp] pip install "mcp[cli]" uvicorn')
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
        _serve(mcp_server, args.host, args.port, blocking=True)
