"""
js_extract.py — JS Parameter & Endpoint Extraction

For each discovered JS file:
  - Fetch the file (or decompress source map)
  - Extract URL endpoints (LinkFinder-style regex + custom patterns)
  - Extract GET/POST parameter names
  - Flag high-value params (redirect, query, search, url, callback, etc.)
  - Aggregate into ctx.js_param_map and ctx.js_global_params
"""

import re, requests, json
from urllib.parse import urljoin, urlparse, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.context import Context

HEADERS = {
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept":          "*/*",
}

# ── High-value param names ────────────────────────────────────────────────────

HIGH_VALUE_PARAMS = {
    # Redirect / SSRF
    "redirect","redirect_uri","redirect_url","redirecturl","redirecturi",
    "return","returnurl","returnuri","return_url","return_uri",
    "next","continue","forward","goto","dest","destination",
    "target","ref","referer","referrer","back","location","url","uri",
    # XSS sinks
    "q","query","search","keyword","keywords","term","terms","text",
    "input","msg","message","content","comment","description","title",
    "subject","body","note","name","value","data","payload",
    # Template / injection
    "template","view","page","layout","format","theme","style",
    "lang","language","locale","currency","country","region",
    # Debug
    "debug","test","preview","mode","dev","verbose","trace",
    # Auth
    "token","state","code","nonce","scope","response_type",
    # Upload / path
    "file","filename","path","dir","folder","upload","attachment",
    # Callback
    "callback","cb","jsonp","handler","fn",
}

# ── Regex patterns ─────────────────────────────────────────────────────────────

# Endpoint patterns — various JS assignment/string styles
ENDPOINT_PATTERNS = [
    # Fetch / XHR / axios
    re.compile(r'''(?:fetch|axios(?:\.\w+)?|http\.(?:get|post|put|delete|patch))\s*\(\s*['"`]([^'"`\s]{3,}(?:/[^'"`\s]*)?)['"`]'''),
    # string with /api/, /v1/, etc.
    re.compile(r'''['"`](/(?:api|v\d+|rest|graphql|ajax|service|data|endpoint|query)[^'"`\s]{0,100})['"`]'''),
    # Relative paths with params
    re.compile(r'''['"`](/[a-zA-Z0-9_\-./]{3,80}\?[a-zA-Z0-9_\-=&%+.]{2,100})['"`]'''),
    # Full URL strings in JS
    re.compile(r'''['"`](https?://[^'"`\s]{10,200})['"`]'''),
    # Router-style paths
    re.compile(r'''(?:path|route|url|href|src|action)\s*[:=]\s*['"`](/[^'"`\s]{2,80})['"`]'''),
]

# Parameter name extraction
PARAM_PATTERNS = [
    # URLSearchParams
    re.compile(r'''(?:searchParams|URLSearchParams|params)\s*\.(?:get|append|set|has)\s*\(\s*['"`]([a-zA-Z0-9_\-]{1,40})['"`]'''),
    # query string assignments: ?param=  &param=
    re.compile(r'''[?&]([a-zA-Z0-9_\-]{1,40})='''),
    # Object key access for query: params.foo, query.foo, qs.foo
    re.compile(r'''(?:params|query|qs|req\.query|args|opts)\s*[.\[]\s*['"`]?([a-zA-Z0-9_\-]{1,40})['"`]?'''),
    # Request body keys
    re.compile(r'''(?:body|payload|data|form)\s*[.\[]\s*['"`]([a-zA-Z0-9_\-]{1,40})['"`]'''),
    # Direct assignment: const q = params.q
    re.compile(r'''const\s+([a-zA-Z0-9_]{1,30})\s*=\s*(?:params|query|searchParams)'''),
    # GraphQL variable names
    re.compile(r'''\$([a-zA-Z0-9_]{1,30})\s*:\s*(?:String|Int|Boolean|ID|Float)'''),
]

# API key / secret hints (flag but don't extract value)
SECRET_PATTERNS = [
    re.compile(r'''(?:api[_\-]?key|apikey|secret|token|auth[_\-]?key|access[_\-]?key)\s*[:=]\s*['"`]([A-Za-z0-9\-_./+]{10,80})['"`]''', re.IGNORECASE),
]

# ── Fetch helpers ─────────────────────────────────────────────────────────────

def fetch_js(url, timeout, ua):
    """Fetch a JS file and return its text content."""
    try:
        r = requests.get(url, timeout=timeout,
                         headers={**HEADERS, "User-Agent": ua},
                         allow_redirects=True)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return ""

def fetch_source_map(map_url, timeout, ua):
    """Fetch a .map file and reconstruct original source text."""
    try:
        r = requests.get(map_url, timeout=timeout,
                         headers={**HEADERS, "User-Agent": ua},
                         allow_redirects=True)
        if r.status_code == 200:
            data = r.json()
            sources_content = data.get("sourcesContent", [])
            # Combine all source files into one big text blob for regex
            combined = "\n\n".join(
                s for s in sources_content if s and isinstance(s, str)
            )
            return combined if combined else r.text
    except Exception:
        pass
    return ""

# ── Extraction ────────────────────────────────────────────────────────────────

def extract_endpoints(text, base_url):
    endpoints = set()
    for pattern in ENDPOINT_PATTERNS:
        for m in pattern.finditer(text):
            ep = m.group(1).strip()
            # Normalise
            if ep.startswith("http"):
                endpoints.add(ep)
            elif ep.startswith("/"):
                full = urljoin(base_url, ep)
                endpoints.add(full)
    return list(endpoints)

def extract_params(text):
    params = set()
    for pattern in PARAM_PATTERNS:
        for m in pattern.finditer(text):
            name = m.group(1).strip()
            # sanity filter
            if 2 <= len(name) <= 40 and re.match(r'^[a-zA-Z][a-zA-Z0-9_\-]*$', name):
                params.add(name.lower())
    return list(params)

def extract_secrets(text, js_url):
    secrets = []
    for pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            value = m.group(1)
            # skip obviously fake/templated values
            if not re.match(r'^[xX\*<>{}|]+$', value):
                secrets.append({"url": js_url, "match": m.group(0)[:120]})
    return secrets

def process_js_file(js_url, map_url, base_url, timeout, ua):
    """Process one JS file (and its source map if available)."""
    result = {
        "url":       js_url,
        "map_url":   map_url,
        "endpoints": [],
        "params":    [],
        "secrets":   [],
        "source":    "js",
    }

    # Prefer source map if available (richer content)
    if map_url:
        text = fetch_source_map(map_url, timeout, ua)
        result["source"] = "sourcemap"
        if not text:
            text = fetch_js(js_url, timeout, ua)
            result["source"] = "js_fallback"
    else:
        text = fetch_js(js_url, timeout, ua)

    if not text:
        return result

    result["endpoints"] = extract_endpoints(text, base_url)
    result["params"]    = extract_params(text)
    result["secrets"]   = extract_secrets(text, js_url)
    return result

# ── Phase runner ──────────────────────────────────────────────────────────────

def run(ctx: Context, phase_num=5, total=9) -> Context:
    base_url = getattr(ctx, "canonical_url", None) or ctx.target_url

    if not ctx.js_files:
        ctx.log("[js_extract] No JS files to process — skipping")
        ctx.phases_run.append("js_extract")
        ctx.log_phase_done(phase_num, total, "js_extract", "0 JS files")
        return ctx

    ctx.log(f"[js_extract] Processing {len(ctx.js_files)} JS files "
            f"({len(ctx.source_maps)} with source maps)...")

    all_results   = []
    global_params = set()
    global_ep     = set()
    param_map     = {}   # endpoint → set of params
    all_secrets   = []

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {
            ex.submit(
                process_js_file,
                js_url,
                ctx.source_maps.get(js_url),
                base_url,
                ctx.timeout,
                ctx.user_agent,
            ): js_url
            for js_url in ctx.js_files
        }
        done = 0
        for f in as_completed(futures):
            r    = f.result()
            done += 1
            all_results.append(r)

            global_params.update(r["params"])
            global_ep.update(r["endpoints"])
            all_secrets.extend(r["secrets"])

            # Build param map keyed by endpoint
            for ep in r["endpoints"]:
                if ep not in param_map:
                    param_map[ep] = set()
                param_map[ep].update(r["params"])

            if not ctx.silent and (r["params"] or r["endpoints"]):
                ctx.log(
                    f"[js_extract]   {r['source']:12}  "
                    f"{len(r['params']):3} params  "
                    f"{len(r['endpoints']):3} endpoints  "
                    f"{'★ ' + str(len(r['secrets'])) + ' secrets' if r['secrets'] else ''}"
                    f"  {r['url']}"
                )

    # Finalise
    ctx.js_global_params = sorted(global_params)
    ctx.js_endpoints     = sorted(global_ep)
    ctx.js_param_map     = {ep: sorted(params) for ep, params in param_map.items()}
    ctx.js_file_data     = all_results

    # High-value param summary
    high_value = [p for p in ctx.js_global_params if p in HIGH_VALUE_PARAMS]

    # Persist
    ctx.write_json("js_params.json", {
        "total_params":    len(ctx.js_global_params),
        "high_value":      high_value,
        "all_params":      ctx.js_global_params,
        "by_endpoint":     ctx.js_param_map,
    })
    ctx.write_json("js_endpoints.json", {
        "total":     len(ctx.js_endpoints),
        "endpoints": ctx.js_endpoints,
    })
    ctx.write_text("js_params_flat.txt",
                   "\n".join(ctx.js_global_params))
    ctx.write_text("js_endpoints_flat.txt",
                   "\n".join(ctx.js_endpoints))

    if all_secrets:
        ctx.write_json("js_secrets_hints.json", all_secrets)
        ctx.log(f"[js_extract] ⚠  {len(all_secrets)} potential secrets/keys found → js_secrets_hints.json")

    # Print high-value params for quick review
    if high_value and not ctx.silent:
        ctx.log(f"[js_extract] ★ High-value params: {', '.join(high_value[:20])}")

    ctx.phases_run.append("js_extract")
    ctx.log_phase_done(phase_num, total, "js_extract",
        f"{len(ctx.js_files)} JS files | "
        f"{len(ctx.js_global_params)} params | "
        f"{len(high_value)} high-value | "
        f"{len(ctx.js_endpoints)} endpoints | "
        f"{len(all_secrets)} secret hints")
    return ctx
