"""
core/reader.py — Load and display results from an existing JSXray scan directory.

Usage (CLI):
    python3 jsxray.py --read recon/gov.uk/20260427_224504

Or call directly:
    from core.reader import read_scan
    read_scan("/path/to/scan/dir")
"""

import json
import os
import shutil
from pathlib import Path


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_json(path: Path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None

def _load_text(path: Path):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return None

def _trunc(s, width=100):
    s = str(s)
    return s if len(s) <= width else s[:width - 1] + "\u2026"

def _sep(char="─", width=None):
    w = width or shutil.get_terminal_size((100, 24)).columns
    print(char * min(w, 100))


# ── Section printers ─────────────────────────────────────────────────────────

def _print_summary(workspace: Path):
    data = _load_json(workspace / "summary.json")
    _sep("=")
    print("  JSXray — Scan Results (read mode)")
    _sep("=")
    if not data:
        print("  [!] summary.json not found or unreadable")
        _sep()
        return
    print(f"  Target   : {data.get('target', 'unknown')}")
    print(f"  Mode     : {data.get('mode', 'unknown')}")
    print(f"  Elapsed  : {data.get('elapsed_s', '?')}s")
    print(f"  Workspace: {workspace}")
    s = data.get("stats", {})
    if s:
        _sep()
        print(f"  robots.txt : {s.get('robots_paths', 0)} paths  "
              f"({s.get('robots_live', 0)} live, {s.get('robots_403', 0)} 403, "
              f"{s.get('robots_redirect', 0)} redirect)")
        print(f"  URL pool   : {s.get('url_pool', 0)} URLs")
        print(f"  JS files   : {s.get('js_files', 0)} files  "
              f"({s.get('source_maps', 0)} source maps)")
        print(f"  Endpoints  : {s.get('js_endpoints', 0)} extracted")
        print(f"  Params     : {s.get('js_global_params', 0)} extracted  "
              f"(+{s.get('hidden_params', 0)} hidden)")
        if s.get('secret_hints'):
            print(f"  Secrets    : {s['secret_hints']} hints found")
    tech = data.get("tech_stack")
    if tech:
        _sep()
        print(f"  Tech stack : {', '.join(tech)}")
    _sep()


def _print_secrets(workspace: Path):
    secrets = _load_json(workspace / "secrets.json") or []
    hints   = _load_json(workspace / "js_secrets_hints.json") or []

    print("\n🔑  SECRETS")
    _sep()
    if not secrets and not hints:
        print("  (none found)")
        return

    # Deduplicate hints vs confirmed secrets
    secret_keys = {(s.get("type"), s.get("match")) for s in secrets}
    extra_hints = [h for h in hints if (h.get("type"), h.get("match")) not in secret_keys]

    all_findings = secrets + extra_hints
    for i, s in enumerate(all_findings, 1):
        print(f"  [{i}] type  : {s.get('type', '?').upper()}")
        print(f"      file  : {_trunc(s.get('url', '?'), 90)}")
        print(f"      match : {_trunc(s.get('match', '?'), 90)}")
        print()


def _print_endpoints(workspace: Path):
    # js_endpoints.json is now a plain list
    raw    = _load_json(workspace / "js_endpoints.json") or []
    js_eps = raw if isinstance(raw, list) else raw.get("endpoints", [])

    crawl_raw = _load_json(workspace / "crawl_endpoints.json") or []
    crawl_eps = crawl_raw if isinstance(crawl_raw, list) else crawl_raw.get("endpoints", [])

    all_eps = list(dict.fromkeys(js_eps + crawl_eps))

    print("\n🌐  ENDPOINTS")
    _sep()
    if not all_eps:
        print("  (none found)")
        return

    print(f"  {len(all_eps)} total  ({len(js_eps)} from JS  /  {len(crawl_eps)} from crawl)\n")
    for ep in all_eps:
        print(f"  {_trunc(ep, 95)}")


def _print_params(workspace: Path):
    flat = _load_text(workspace / "js_params_flat.txt")

    print("\n🎯  PARAMETERS")
    _sep()
    if not flat:
        print("  (none found)")
        return

    params = flat.splitlines()
    print(f"  {len(params)} params total\n")
    for p in params:
        print(f"    {p}")


def _print_nuclei(workspace: Path):
    data = _load_text(workspace / "nuclei_targets.txt")
    print("\n⚡  NUCLEI TARGETS")
    _sep()
    if not data:
        print("  (none)")
        return
    lines = [l for l in data.splitlines() if l and not l.startswith("#")]
    print(f"  {len(lines)} targets — run with:")
    print(f"  nuclei -l {workspace}/nuclei_targets.txt -t ~/nuclei-templates/ -severity medium,high,critical\n")
    for l in lines[:10]:
        print(f"  {_trunc(l, 95)}")
    if len(lines) > 10:
        print(f"  … and {len(lines) - 10} more")


def _print_robots(workspace: Path):
    robots = _load_json(workspace / "robots_paths.json") or []
    print("\n🤖  ROBOTS.TXT PATHS")
    _sep()
    if not robots:
        print("  (none)")
        return
    for entry in robots:
        print(f"  [{entry.get('status', '?')}]  {_trunc(entry.get('url', '?'), 90)}")


# ── Main entry ────────────────────────────────────────────────────────────────

def read_scan(path: str):
    """
    Load all results from a JSXray scan directory and print a rich summary.

    Args:
        path: Absolute or relative path to the scan workspace directory
              e.g.  recon/gov.uk/20260427_224504
    """
    workspace = Path(path).expanduser().resolve()
    if not workspace.exists():
        print(f"[jsxray --read] Directory not found: {workspace}")
        return

    _print_summary(workspace)
    _print_secrets(workspace)
    _print_endpoints(workspace)
    _print_params(workspace)
    _print_nuclei(workspace)
    _print_robots(workspace)

    _sep("=")
    print(f"\n[jsxray] Read from → {workspace}/\n")
