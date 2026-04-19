"""
ast_extract.py — AST v5 Parameter Extraction Engine
=====================================================

Architecture (5 tiers):
  Tier 1 — Structural AST: net calls (fetch/axios/got/ky/http), URLSearchParams
            calls, FormData.append, JSON.stringify, qs.stringify
  Tier 2 — Alias tracking: const p = req.query / new URLSearchParams() /
            payload alias → follow all subsequent reads
  Tier 3 — Scoped property reads: params.foo, query.foo, req.body.foo,
            body['api_key'], destructure from query objects
  Tier 4 — Template literal partial extraction: static QS keys from
            fetch(`/api?foo=${x}&bar=${y}`)
  Tier 5 — Fallback (transparent): Node.js unavailable → empty list;
            caller (js_extract.py) sees [] and the tool keeps running

Output per param:
  { "value": "user_id", "confidence": "HIGH"|"MED", "source": "<tier_tag>" }

Node.js runtime requirement:
  acorn + acorn-walk must be resolvable via `node` in PATH.
  Install once:  npm install -g acorn acorn-walk
  The Python wrapper auto-locates the bundled JS runner alongside this file.

Fallback behaviour:
  If Node.js is absent or the subprocess fails for any reason,
  extract_params_detailed() returns [] — the tool continues normally.
"""

import json
import os
import subprocess

_DIR     = os.path.dirname(os.path.abspath(__file__))
_JS_FILE = os.path.join(_DIR, "ast_extract_runner.js")


def _node_available() -> bool:
    try:
        subprocess.run(
            ["node", "--version"],
            check=True,
            capture_output=True,
            timeout=5,
        )
        return True
    except Exception:
        return False


_NODE_OK = _node_available()


def extract_params_detailed(text: str, log_fn=None) -> list[dict]:
    """
    Run the AST v5 engine on raw JS source or sourcemap content.

    Returns a list of dicts, each with:
        {
            "value":      str,            # parameter name
            "confidence": "HIGH" | "MED", # HIGH = structural AST hit
            "source":     str,            # tier tag, e.g. "req_member_read"
        }

    Falls back to [] on any error so js_extract.py never crashes.
    log_fn: optional callable(str) for debug output.
    """
    if not _NODE_OK:
        if log_fn:
            log_fn("[ast_extract] Node.js not available — AST extraction skipped")
        return []

    if not text or not text.strip():
        return []

    if not os.path.isfile(_JS_FILE):
        if log_fn:
            log_fn(f"[ast_extract] Runner not found: {_JS_FILE}")
        return []

    # Scale timeout to input size: 10s minimum, 60s max, ~1s per 50KB
    timeout = max(10, min(60, len(text) // 50_000))

    try:
        result = subprocess.run(
            ["node", _JS_FILE],
            input=text,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        return data.get("params", [])
    except Exception:
        return []


def extract_params(text: str, log_fn=None) -> list[str]:
    """
    Convenience wrapper — returns a flat sorted list of unique param names.
    Confidence/source metadata is discarded; use extract_params_detailed()
    when you need per-param confidence scores.
    """
    detailed = extract_params_detailed(text, log_fn=log_fn)
    return sorted({p["value"] for p in detailed})
