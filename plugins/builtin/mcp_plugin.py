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

import glob
import json
import os
import subprocess
import sys
import threading
import time
from plugins.base import BasePlugin

_scans: dict = {}
_scans_lock  = threading.Lock()

_ROOT      = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_RECON_DIR = os.path.join(_ROOT, "recon")


# ── Disk helpers ──────────────────────────────────────────────────────────────

def _target_to_safe(target: str) -> str:
    return (
        target
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .rstrip("_")
    )


def _latest_workspace(target: str) -> str | None:
    safe = _target_to_safe(target)
    for candidate in (safe, safe.replace("www.", "", 1)):
        matches = sorted(glob.glob(os.path.join(_RECON_DIR, candidate, "*", "summary.json")))
        if matches:
            return os.path.dirname(matches[-1])
    return None


def _any_latest_workspace() -> str | None:
    all_summaries = sorted(
        glob.glob(os.path.join(_RECON_DIR, "*", "*", "summary.json")),
        key=os.path.getmtime,
    )
    return os.path.dirname(all_summaries[-1]) if all_summaries else None


def _load_json(path: str):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _load_lines(path: str) -> list:
    try:
        with open(path) as f:
            return [l.rstrip() for l in f if l.strip() and not l.startswith("#")]
    except Exception:
        return []


def _load_endpoints(path: str) -> list:
    """Load endpoints whether stored as a plain list or {total, endpoints} dict."""
    data = _load_json(path)
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("endpoints", [])
    return []


def _read_workspace(ws: str) -> dict:
    return {
        "summary":         _load_json(os.path.join(ws, "summary.json")) or {},
        "secrets":         _load_json(os.path.join(ws, "secrets.json")) or [],
        "js_secrets_hints":_load_json(os.path.join(ws, "js_secrets_hints.json")) or [],
        "js_endpoints":    _load_endpoints(os.path.join(ws, "js_endpoints.json")),
        "crawl_endpoints": _load_endpoints(os.path.join(ws, "crawl_endpoints.json")),
        "js_params":       _load_json(os.path.join(ws, "js_params.json")) or {},
        "js_global_params":_load_lines(os.path.join(ws, "js_params_flat.txt")),
        "hidden_params":   _load_json(os.path.join(ws, "source_maps.json")) or {},
        "nuclei_targets":  _load_lines(os.path.join(ws, "nuclei_targets.txt")),
        "robots":          _load_json(os.path.join(ws, "robots_paths.json")) or [],
    }


# ── In-memory registry ────────────────────────────────────────────────────────

class Plugin(BasePlugin):
    name        = "mcp"
    description = "MCP server — AI can trigger scans and query results"
    version     = "0.7.0"
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


def _register_ctx(target, ctx):
    with _scans_lock:
        _scans[target] = {
            "status":  "done",
            "ctx":     ctx,
            "summary": ctx.to_summary(),
            "started": ctx.scan_start,
            "elapsed": ctx.elapsed(),
        }


def _get_ctx(target):
    if target:
        e = _scans.get(target)
        return e.get("ctx") if e and e["status"] == "done" else None
    with _scans_lock:
        done = [v for v in _scans.values() if v["status"] == "done" and v.get("ctx")]
    return max(done, key=lambda v: v["started"])["ctx"] if done else None


def _get_data(target: str) -> dict | None:
    """
    Priority: in-memory ctx → disk.
    Returns a unified dict with keys:
      summary, secrets, js_endpoints, crawl_endpoints,
      js_global_params, js_params, hidden_params, js_secrets_hints,
      nuclei_targets, robots.
    """
    ctx = _get_ctx(target or None)
    if ctx:
        secrets = [
            {"file": fd.get("url", ""), **s}
            for fd in ctx.js_file_data
            for s in fd.get("secrets", [])
        ]
        return {
            "summary":          ctx.to_summary(),
            "secrets":          secrets,
            "js_secrets_hints": [],
            "js_endpoints":     ctx.js_endpoints or [],
            "crawl_endpoints":  [],
            "js_global_params": ctx.js_global_params or [],
            "js_params":        ctx.js_param_map or {},
            "hidden_params":    ctx.hidden_params or {},
            "nuclei_targets":   [],
            "robots":           [],
        }

    ws = _latest_workspace(target) if target else _any_latest_workspace()
    return _read_workspace(ws) if ws else None


# ── FastMCP tools ─────────────────────────────────────────────────────────────

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
                    r = subprocess.run(
                        [sys.executable, os.path.join(_ROOT, "jsxray.py"),
                         "-t", target, "-m", mode, "--no-dashboard", "--silent"],
                        cwd=_ROOT, capture_output=True, text=True)
                    _load_scan_output(target, r)
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
                if not e:
                    ws = _latest_workspace(target)
                    if ws:
                        summary = _load_json(os.path.join(ws, "summary.json")) or {}
                        return {"target": target, "status": "done", "source": "disk",
                                "elapsed": summary.get("elapsed_s", "?"), "summary": summary}
                    return {"error": f"No scan found for '{target}'"}
                d = {"target": target, "status": e["status"],
                     "elapsed": round(time.time() - e["started"], 1)}
                if e["status"] == "done":   d["summary"] = e.get("summary", {})
                if e["status"] == "failed": d["error"]   = e.get("error", "unknown")
                return d
            result = {t: {"status": v["status"],
                          "elapsed": round(time.time() - v["started"], 1)}
                     for t, v in scans.items()}
            for summary_path in sorted(
                    glob.glob(os.path.join(_RECON_DIR, "*", "*", "summary.json")),
                    key=os.path.getmtime):
                data = _load_json(summary_path) or {}
                t = data.get("target", "")
                if t and t not in result:
                    result[t] = {"status": "done", "source": "disk",
                                 "elapsed": data.get("elapsed_s", "?")}
            return result

    @mcp.tool(description="Full scan summary: target, mode, elapsed, tech stack, stats.")
    def jsxray_summary(target: str = "") -> dict:
        d = _get_data(target or None)
        return d["summary"] if d else {"error": "no results"}

    @mcp.tool(description="All endpoints extracted from JS files and crawl.")
    def jsxray_js_endpoints(target: str = "", limit: int = 200) -> list:
        d = _get_data(target or None)
        if not d:
            return []
        eps = list(dict.fromkeys(d["js_endpoints"] + d["crawl_endpoints"]))
        return eps[:limit]

    @mcp.tool(description="All params extracted from JS. Filter by file with file_filter.")
    def jsxray_params(target: str = "", file_filter: str = "") -> dict:
        d = _get_data(target or None)
        if not d:
            return {}
        ff = file_filter.lower()
        per_file = (
            {k: v for k, v in d["js_params"].items() if ff in k.lower()}
            if ff else d["js_params"]
        )
        return {
            "global":   d["js_global_params"],
            "per_file": per_file,
        }

    @mcp.tool(description="Secrets and credentials found in JS files.")
    def jsxray_secrets(target: str = "") -> list:
        d = _get_data(target or None)
        if not d:
            return []
        return d["secrets"] + d.get("js_secrets_hints", [])

    @mcp.tool(description="Hidden params from source map parsing. Filter with endpoint_filter.")
    def jsxray_hidden_params(target: str = "", endpoint_filter: str = "") -> dict:
        d = _get_data(target or None)
        if not d:
            return {}
        hp = d["hidden_params"]
        ef = endpoint_filter.lower()
        return {k: v for k, v in hp.items() if ef in k.lower()} if ef else hp

    return mcp


# ── Scan output loader ────────────────────────────────────────────────────────

def _load_scan_output(target, proc_result):
    ws = _latest_workspace(target)
    if ws:
        summary = _load_json(os.path.join(ws, "summary.json")) or {}
        with _scans_lock:
            _scans[target].update({"status": "done", "summary": summary,
                                   "elapsed": summary.get("elapsed_s", 0)})
        return
    with _scans_lock:
        if proc_result.returncode != 0:
            _scans[target].update({"status": "failed",
                                   "error": proc_result.stderr[-500:] or "unknown"})
        else:
            _scans[target].update({"status": "done",
                                   "summary": {"note": "summary.json not found"}})


# ── Transport ─────────────────────────────────────────────────────────────────

class _HostBypassMiddleware:
    """
    Rewrites the Host header to 127.0.0.1:<port> before passing to FastMCP.
    FastMCP validates the Host and returns 421 when behind ngrok/reverse-proxy.
    """
    def __init__(self, app, host: str, port: int):
        self.app  = app
        self.host = f"{host}:{port}".encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
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
    app = _HostBypassMiddleware(inner_app, "127.0.0.1", port)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning",
                            server_header=False, date_header=False)
    srv = uvicorn.Server(config)
    if blocking:
        import asyncio
        asyncio.run(srv.serve())
    else:
        threading.Thread(target=srv.run, daemon=True).start()


# ── Standalone ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--host",      default="127.0.0.1")
    p.add_argument("--port",      type=int, default=9000)
    p.add_argument("--transport", default="streamable-http",
                   choices=["streamable-http", "stdio"])
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
