"""
endpoint_crawl.py — Phase 6: Crawl Discovered Endpoints

After js_extract has populated ctx.js_endpoints, this phase fetches each
in-scope URL and re-runs param + endpoint extraction on the response body.

Strategy
────────
1.  Filter js_endpoints to crawlable URLs:
      - In-scope (same domain / subdomain)
      - Not a static asset (.png .jpg .svg .css .woff .ico .mp4 …)
      - Not already visited (seen set seeded with ctx.js_files)

2.  Fetch each URL concurrently (max_workers=15, shorter timeout).
    Follow redirects.  Accept HTML, JSON, JS, plain-text.

3.  Per response type:
      HTML  → BeautifulSoup (if available) or regex fallback
              • <input name>, <select name>, <textarea name>   → params (via AST on inline scripts)
              • <a href="?foo=bar">                            → params (query keys)
              • <form action="/path">                          → endpoints
              • <script src="/js/app.js">                      → new JS URLs → extra_js pass
              • inline <script> text                           → extract_endpoints + extract_params
      JSON  → walk all string values that look like paths/URLs → endpoints
              walk all text content through extract_params      → params
      JS    → extract_endpoints + extract_params (same as js_extract)

4.  All newly found endpoints are filtered through _is_in_scope_endpoint.
    All param extraction uses ast_extract.extract_params.

5.  Extra JS pass (FIX):
      Any <script src> URLs discovered in HTML responses are run through
      process_js_file (same pipeline as js_extract phase) so their params,
      endpoints, lazy chunks and secrets are fully extracted and merged.

6.  Merge results into ctx:
      ctx.js_endpoints    += new endpoints  (deduped)
      ctx.js_global_params+= new params     (deduped)
      ctx.js_files        += new JS URLs    (deduped)

7.  Write outputs:
      crawl_endpoints.json   { total, by_url: {url: [endpoints]} }
      crawl_params.json      { total, by_url: {url: [params]} }
      crawl_endpoints_flat.txt
      crawl_params_flat.txt
"""

import re
import json
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.ast_extract import extract_params
from core.js_extract import (
    extract_endpoints,
    _is_in_scope_endpoint,
    _host_in_scope,
    process_js_file,
    HEADERS,
)

# ── Static asset extensions to skip ─────────────────────────────────────────────
SKIP_EXT = re.compile(
    r"\.(?:png|jpg|jpeg|gif|webp|svg|ico|bmp|tiff|"
    r"css|woff|woff2|ttf|eot|otf|"
    r"mp4|mp3|webm|ogg|wav|avi|mov|"
    r"pdf|zip|gz|tar|rar|7z|dmg|exe|"
    r"map|txt|xml|rss|atom)(?:[?#]|$)",
    re.IGNORECASE,
)

# ── HTML extraction helpers ───────────────────────────────────────────────────────────────
_ANCHOR_HREF   = re.compile(r"""<a[^>]+href\s*=\s*['"]([^'"]{2,200})['"]""", re.IGNORECASE)
_FORM_ACTION   = re.compile(r"""<form[^>]+action\s*=\s*['"]([^'"]{2,200})['"]""", re.IGNORECASE)
_SCRIPT_SRC    = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]{4,200})['"]""", re.IGNORECASE)
_INLINE_SCRIPT = re.compile(r"""<script(?:[^>](?!src))*>(.*?)</script>""", re.IGNORECASE | re.DOTALL)
_QUERY_KEY     = re.compile(r"[?&]([a-zA-Z0-9_\-]{1,40})=")

# ── JSON walk ──────────────────────────────────────────────────────────────────────────
_URL_VALUE = re.compile(r"^https?://|^/[a-zA-Z0-9_\-/]")

def _walk_json(obj, endpoints, base_url, domain, depth=0):
    """Collect in-scope endpoint URLs from a JSON object tree."""
    if depth > 10:
        return
    if isinstance(obj, dict):
        for v in obj.values():
            _walk_json(v, endpoints, base_url, domain, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _walk_json(item, endpoints, base_url, domain, depth + 1)
    elif isinstance(obj, str) and len(obj) < 300:
        if _URL_VALUE.match(obj) and "${" not in obj:
            resolved = obj if obj.startswith("http") else urljoin(base_url, obj)
            if _is_in_scope_endpoint(resolved, domain):
                endpoints.add(resolved)


def _extract_html(text, page_url, domain):
    params    = set()
    endpoints = set()
    extra_js  = set()

    # Query keys from anchor hrefs
    for m in _ANCHOR_HREF.finditer(text):
        href = m.group(1).strip()
        if href.startswith(("javascript:", "mailto:", "#")):
            continue
        for k in _QUERY_KEY.findall(href):
            params.add(k.strip().lower())
        resolved = href if href.startswith("http") else urljoin(page_url, href)
        if _is_in_scope_endpoint(resolved, domain):
            endpoints.add(resolved)

    # Form actions
    for m in _FORM_ACTION.finditer(text):
        action = m.group(1).strip()
        if action.startswith(("javascript:", "#")):
            continue
        resolved = action if action.startswith("http") else urljoin(page_url, action)
        if _is_in_scope_endpoint(resolved, domain):
            endpoints.add(resolved)

    # External script srcs → candidate JS files for extra pass
    for m in _SCRIPT_SRC.finditer(text):
        src = m.group(1).strip()
        if "${" in src:
            continue
        resolved = src if src.startswith("http") else urljoin(page_url, src)
        if _is_in_scope_endpoint(resolved, domain):
            extra_js.add(resolved)

    # Inline scripts → AST param extraction + endpoint patterns
    for m in _INLINE_SCRIPT.finditer(text):
        block = m.group(1)
        if not block or len(block) < 10:
            continue
        params.update(extract_params(block))
        for ep in extract_endpoints(block, page_url, domain):
            endpoints.add(ep)

    return params, endpoints, extra_js


def _crawl_one(url, base_url, domain, timeout, ua):
    result = {
        "url":       url,
        "status":    None,
        "ctype":     None,
        "params":    [],
        "endpoints": [],
        "extra_js":  [],
        "error":     None,
    }

    try:
        r = requests.get(
            url,
            timeout=timeout,
            headers={**HEADERS, "User-Agent": ua},
            allow_redirects=True,
        )
        result["status"] = r.status_code
        ctype = r.headers.get("Content-Type", "").lower()
        result["ctype"] = ctype

        if r.status_code not in (200, 201, 206):
            return result

        text = r.text

        if "json" in ctype:
            try:
                obj = r.json()
                endpoints = set()
                _walk_json(obj, endpoints, base_url, domain)
                # Extract params from the raw JSON text via AST
                params = set(extract_params(text))
                result["params"]    = sorted(params)
                result["endpoints"] = sorted(endpoints)
            except Exception:
                pass

        elif "javascript" in ctype or url.rstrip("/").endswith(".js"):
            result["params"]    = extract_params(text)
            result["endpoints"] = extract_endpoints(text, base_url, domain)

        else:
            # HTML or unknown — treat as HTML
            params, endpoints, extra_js = _extract_html(text, url, domain)
            result["params"]    = sorted(params)
            result["endpoints"] = sorted(endpoints)
            result["extra_js"]  = sorted(extra_js)

    except requests.exceptions.Timeout:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)[:120]

    return result


def _is_crawlable(url, domain):
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        if not _host_in_scope(p.netloc, domain):
            return False
        path = p.path.lower()
        if SKIP_EXT.search(path):
            return False
        return True
    except Exception:
        return False


# ── Phase runner ─────────────────────────────────────────────────────────────

def run(ctx, phase_num=6, total=9):
    base_url = getattr(ctx, "canonical_url", None) or ctx.target_url
    domain   = urlparse(base_url).netloc.lstrip("www.")

    seen = set(getattr(ctx, "js_files", []))
    candidates = [
        url for url in getattr(ctx, "js_endpoints", [])
        if url not in seen and _is_crawlable(url, domain)
    ]

    if not candidates:
        ctx.log("[endpoint_crawl] No crawlable endpoints — skipping")
        ctx.phases_run.append("endpoint_crawl")
        ctx.log_phase_done(phase_num, total, "endpoint_crawl", "0 URLs crawled")
        return ctx

    ctx.log(f"[endpoint_crawl] Crawling {len(candidates)} endpoints...")

    crawl_timeout = min(ctx.timeout, 10)
    all_results   = []

    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = {
            ex.submit(_crawl_one, url, base_url, domain, crawl_timeout, ctx.user_agent): url
            for url in candidates
        }
        for fut in as_completed(futures):
            r = fut.result()
            all_results.append(r)
            seen.add(r["url"])

            if not ctx.silent and (r["params"] or r["endpoints"]):
                status  = r["status"] or "ERR"
                ep_lbl  = f"  {len(r['endpoints'])} ep" if r["endpoints"] else ""
                par_lbl = f"  {len(r['params'])} params" if r["params"] else ""
                ctx.log(
                    f"[endpoint_crawl]   [{status}]{ep_lbl}{par_lbl}"
                    f"  {r['url']}"
                )

    # ── Collect results ──────────────────────────────────────────────────────────────
    new_params    = set()
    new_endpoints = set()
    extra_js      = set()
    by_url_ep     = {}
    by_url_par    = {}

    for r in all_results:
        url = r["url"]
        if r["params"]:
            new_params.update(r["params"])
            by_url_par[url] = r["params"]
        if r["endpoints"]:
            new_endpoints.update(r["endpoints"])
            by_url_ep[url] = r["endpoints"]
        if r["extra_js"]:
            extra_js.update(r["extra_js"])

    # ── Process extra JS files through full js_extract pipeline ─────────────────
    existing_js   = set(getattr(ctx, "js_files", []))
    new_js_files  = sorted(extra_js - existing_js - seen)
    extra_js_params_count = 0

    if new_js_files:
        ctx.log(f"[endpoint_crawl] Processing {len(new_js_files)} newly discovered JS files...")

        js_file_data = getattr(ctx, "js_file_data", [])

        with ThreadPoolExecutor(max_workers=15) as ex:
            futures = {
                ex.submit(
                    process_js_file,
                    js_url,
                    None,
                    base_url,
                    domain,
                    crawl_timeout,
                    ctx.user_agent,
                ): js_url
                for js_url in new_js_files
            }
            for fut in as_completed(futures):
                r = fut.result()
                js_file_data.append(r)
                new_params.update(r["params"])
                new_endpoints.update(r["endpoints"])
                extra_js_params_count += len(r["params"])

                if r.get("secrets"):
                    ctx.log(f"[endpoint_crawl]   \u2605 {len(r['secrets'])} secrets in {r['url']}")

                if not ctx.silent and (r["params"] or r["endpoints"]):
                    ctx.log(
                        f"[endpoint_crawl]   [extra-js]  "
                        f"{len(r['params']):3} params  "
                        f"{len(r['endpoints']):3} endpoints  "
                        f"{r['url']}"
                    )

        ctx.js_file_data = js_file_data
        ctx.js_files     = sorted(existing_js | set(new_js_files))

    # ── Merge into ctx ───────────────────────────────────────────────────────────────
    existing_eps    = set(getattr(ctx, "js_endpoints", []))
    existing_params = set(getattr(ctx, "js_global_params", []))

    added_eps    = new_endpoints - existing_eps
    added_params = new_params    - existing_params

    ctx.js_endpoints     = sorted(existing_eps    | new_endpoints)
    ctx.js_global_params = sorted(existing_params | new_params)
    ctx.js_files_extra   = new_js_files

    # ── Write outputs ────────────────────────────────────────────────────────────────
    ctx.write_json("crawl_endpoints.json", {
        "total_new":  len(added_eps),
        "total_seen": len(new_endpoints),
        "by_url":     by_url_ep,
    })
    ctx.write_json("crawl_params.json", {
        "total_new":  len(added_params),
        "total_seen": len(new_params),
        "by_url":     by_url_par,
    })
    if added_eps:
        ctx.write_text("crawl_endpoints_flat.txt", "\n".join(sorted(added_eps)))
    if added_params:
        ctx.write_text("crawl_params_flat.txt", "\n".join(sorted(added_params)))
    if new_js_files:
        ctx.write_text("crawl_extra_js.txt", "\n".join(new_js_files))

    ctx.phases_run.append("endpoint_crawl")
    ctx.log_phase_done(
        phase_num, total, "endpoint_crawl",
        f"{len(candidates)} URLs crawled | "
        f"+{len(added_eps)} endpoints | "
        f"+{len(added_params)} params | "
        f"{len(new_js_files)} extra JS files processed "
        f"(+{extra_js_params_count} params from JS)",
    )
    return ctx
