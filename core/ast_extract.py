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
  If Node.js is absent or the subprocess fails for any reason, extract_params()
  returns [] — the tool continues normally, producing no params for that file
  rather than crashing.
"""

import json
import os
import subprocess

_DIR = os.path.dirname(os.path.abspath(__file__))
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


def extract_params(text: str) -> list[str]:
    """
    Run the AST v5 engine on raw JS source or sourcemap content.

    Returns a sorted list of unique parameter names.
    Falls back to [] on any error so js_extract.py never crashes.
    """
    detailed = extract_params_detailed(text)
    return sorted({p["value"] for p in detailed})


def extract_params_detailed(text: str) -> list[dict]:
    """
    Return full per-param dicts:
        [{"value": "user_id", "confidence": "HIGH", "source": "req_member_read"}, ...]
    """
    if not _NODE_OK or not text or not text.strip():
        return []

    if not os.path.isfile(_JS_FILE):
        return []

    try:
        result = subprocess.run(
            ["node", _JS_FILE],
            input=text,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        return data.get("params", [])
    except Exception:
        return []
