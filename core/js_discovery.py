"""
js_discovery.py — JS File Discovery

Strategy (quick / no-tools):
  1. Fetch canonical root page → extract <script src=...>
  2. Fetch each live robots.txt page → extract <script src=...>
  3. Fetch sitemap-seeded pages (prioritised, up to N) → extract <script src=...>
  4. Wayback CDX passive JS URL lookup (no target contact)
  5. Pull .js URLs already in ctx.url_pool (built by urls phase)
  6. For each JS URL: check for .map source map

Feature #2 — Inline <script> extraction:
  Each fetched seed page is also scanned for <script> blocks that have NO
  src= attribute (inline JS). The combined text of all inline blocks is run
  through extract_endpoints() and extract_params() immediately, so API calls
  and parameter names embedded directly in HTML are captured even when no
  external .js file exists.

  Results land in:
    ctx.inline_script_endpoints  — list[str]  (in-scope resolved URLs)
    ctx.inline_script_params     — list[str]  (deduplicated param names)
  and are merged into ctx.js_endpoints / ctx.js_global_params by js_extract.

Standard/full modes add:
  - Chunk pattern enumeration (common Next.js / webpack chunk paths)
  - Cross-origin JS host crawl
"""

import re, requests, shutil, subprocess
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.context import Context
from core.urls import is_blocked
from core.js_extract import extract_endpoints
from core.ast_extract import extract_params

SCRIPT_SRC    = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
SCRIPT_INLINE = re.compile(r'<script(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)</script>', re.IGNORECASE)
MAP_COMMENT   = re.compile(r'(?://[#@]\s*sourceMappingURL=([^\s]+\.map))', re.IGNORECASE)

HEADERS = {
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept":          "text/html,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

CHUNK_PATTERNS_NEXTJS = [
    "/_next/static/chunks/main.js",
    "/_next/static/chunks/pages/_app.js",
    "/_next/static/chunks/pages/index.js",
    "/_next/static/chunks/webpack.js",
    "/_next/static/chunks/framework.js",
    "/_next/static/chunks/polyfills.js",
]
CHUNK_PATTERNS_WEBPACK = [
    "/static/js/main.js",
    "/static/js/bundle.js",
    "/static/js/vendors~main.chunk.js",
    "/js/app.js",
    "/js/main.js",
    "/js/bundle.js",
    "/assets/js/app.js",
    "/assets/js/main.js",
]

JS_EXT_RE = re.compile(r'\.js(\?[^#]*)?$', re.IGNORECASE)

# Content-Types that indicate a real source map (not an HTML 404 page)
_MAP_VALID_CT = ("application/json", "text/plain", "application/octet-stream",
                 "application/javascript", "text/javascript")

# Minimum inline block size worth processing.
_INLINE_MIN_CHARS = 20


def _resolve(ref, base_url):
    if ref.startswith("//"): return "https:" + ref
    if ref.startswith("http"): return ref
    return urljoin(base_url, ref)


def _host_in_scope(host: str, domain: str) -> bool:
    host = (host or "").lower().lstrip("www.")
    base = (domain or "").lower().lstrip("www.")
    return bool(host) and bool(base) and (host == base or host.endswith("." + base))


def _prioritize_pages(urls):
    """Put parameterized and high-value pages first before applying caps."""
    high, normal = [], []
    keywords = ("search", "query", "redirect", "callback", "return", "api", "ajax", "graphql")
    for url in urls:
        lu = url.lower()
        if "?" in url or any(k in lu for k in keywords):
            high.append(url)
        else:
            normal.append(url)
    return list(dict.fromkeys(high + normal))


def fetch_page_js_refs(url, timeout, ua, domain):
    """Fetch a page and return (script_src_refs, inline_blocks, was_blocked)."""
    try:
        r = requests.get(url, timeout=timeout,
                         headers={**HEADERS, "User-Agent": ua},
                         allow_redirects=True)
        if r.status_code != 200:
            return [], [], False
        if is_blocked(r.text, r.status_code):
            return [], [], True

        refs    = SCRIPT_SRC.findall(r.text)
        inlines = [
            blk for blk in SCRIPT_INLINE.findall(r.text)
            if blk.strip() and len(blk.strip()) >= _INLINE_MIN_CHARS
        ]
        return refs, inlines, False
    except Exception:
        return [], [], False


def check_source_map(js_url, timeout, ua):
    """Return the source map URL for js_url, or None if no valid map exists."""
    try:
        r = requests.get(js_url, timeout=timeout,
                         headers={**HEADERS, "User-Agent": ua},
                         allow_redirects=True)
        if r.status_code != 200:
            return None

        # 1. Response header
        sm = r.headers.get("SourceMap", "") or r.headers.get("X-SourceMap", "")
        if sm:
            return urljoin(js_url, sm)

        # 2. Inline sourceMappingURL comment
        tail = r.text[-800:] if len(r.text) > 800 else r.text
        m = MAP_COMMENT.search(tail)
        if m:
            return urljoin(js_url, m.group(1))

        # 3. Probe <js>.map — GET and validate Content-Type
        map_url = js_url.split("?")[0] + ".map"
        rm = requests.get(map_url, timeout=timeout,
                          headers={"User-Agent": ua}, allow_redirects=True)
        if rm.status_code == 200:
            ct = rm.headers.get("Content-Type", "").lower()
            if any(ct.startswith(valid) for valid in _MAP_VALID_CT):
                return map_url
    except Exception:
        pass
    return None


def seed_js_from_wayback(domain, timeout, ctx):
    ctx.log("[js_discovery] Passive JS seed via Wayback CDX...")
    try:
        r = requests.get("https://web.archive.org/cdx/search/cdx", params={
            "url":      f"{domain}/*.js",
            "output":   "text",
            "fl":       "original",
            "collapse": "urlkey",
            "limit":    "500",
            "filter":   "statuscode:200",
        }, timeout=timeout)
        if r.status_code == 200 and r.text.strip():
            js_urls = [u.strip() for u in r.text.strip().split("\n")
                       if u.strip().startswith("http") and ".js" in u]
            ctx.log(f"[js_discovery]   Wayback CDX → {len(js_urls)} JS URLs")
            return js_urls
    except Exception as e:
        ctx.log(f"[js_discovery]   Wayback CDX error: {e}")
    return []


def try_chunk_patterns(base_url, tech_stack, timeout, ua):
    patterns = []
    tech_lower = [t.lower() for t in tech_stack]
    if "next.js" in tech_lower:
        patterns = CHUNK_PATTERNS_NEXTJS
    elif any(x in tech_lower for x in ["react", "webpack", "vue.js"]):
        patterns = CHUNK_PATTERNS_WEBPACK
    else:
        patterns = CHUNK_PATTERNS_NEXTJS + CHUNK_PATTERNS_WEBPACK

    found = []
    for path in patterns:
        url = base_url.rstrip("/") + path
        try:
            r = requests.head(url, timeout=timeout,
                              headers={"User-Agent": ua}, allow_redirects=True)
            if r.status_code == 200:
                found.append(url)
        except Exception:
            pass
    return found


def _is_js_url(url):
    try:
        path = urlparse(url).path
        return bool(JS_EXT_RE.search(path))
    except Exception:
        return False


def run(ctx: Context, phase_num=4, total=9) -> Context:
    base_url   = getattr(ctx, "canonical_url", None) or ctx.target_url
    domain     = urlparse(base_url).netloc.lstrip("www.")
    mode       = getattr(ctx, "mode", "standard")
    tech_stack = getattr(ctx, "tech_stack", [])

    ctx.log(f"[js_discovery] Base: {base_url}  mode={mode}")

    seed_pages = [base_url]

    for r in ctx.robots_live:
        if r.get("status") in (200, 401, 403):
            seed_pages.append(r.get("resolved_url") or r["url"])

    seed_pages += ctx.sitemap_urls[:100]

    prioritized_pool = _prioritize_pages(ctx.url_pool)
    for u in prioritized_pool[:150]:
        seed_pages.append(u)

    seed_pages = _prioritize_pages(seed_pages)
    ctx.log(f"[js_discovery] Scanning {len(seed_pages)} seed pages for JS refs...")

    js_refs         = set()
    all_inline_eps  = set()
    all_inline_pars = set()
    blocked         = 0
    pages_done      = 0
    inline_blocks_total = 0

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {
            ex.submit(fetch_page_js_refs, url, ctx.timeout, ctx.user_agent, domain): url
            for url in seed_pages
        }
        for f in as_completed(futures):
            page_url = futures[f]
            refs, inlines, was_blocked = f.result()
            pages_done += 1
            if was_blocked:
                blocked += 1

            for ref in refs:
                js_refs.add(_resolve(ref, page_url))

            if inlines:
                inline_blocks_total += len(inlines)
                combined = "\n".join(inlines)
                for ep in extract_endpoints(combined, page_url, domain):
                    all_inline_eps.add(ep)
                for p in extract_params(combined):
                    all_inline_pars.add(p)

    ctx.log(
        f"[js_discovery]   {pages_done} pages → {len(js_refs)} JS refs"
        + (f" ({blocked} blocked)" if blocked else "")
    )
    ctx.log(
        f"[js_discovery]   Inline <script> blocks: {inline_blocks_total} across pages"
        f" → {len(all_inline_eps)} endpoints, {len(all_inline_pars)} params"
    )

    ctx.inline_script_endpoints = sorted(all_inline_eps)
    ctx.inline_script_params    = sorted(all_inline_pars)

    # Pool-resident JS URLs
    pool_js = [u for u in ctx.url_pool if _is_js_url(u)]
    ctx.log(f"[js_discovery]   JS from url_pool: {len(pool_js)}")
    js_refs.update(pool_js)

    # Filter to in-scope only
    js_refs = {u for u in js_refs if _host_in_scope(urlparse(u).netloc, domain)}

    # Wayback CDX passive seed (all modes)
    wayback_js = seed_js_from_wayback(domain, ctx.timeout, ctx)
    js_refs.update(wayback_js)

    # Standard / full: chunk pattern probe + cross-origin JS host crawl
    if mode in ("standard", "full"):
        chunk_found = try_chunk_patterns(base_url, tech_stack, ctx.timeout, ctx.user_agent)
        if chunk_found:
            ctx.log(f"[js_discovery]   Chunk patterns hit: {len(chunk_found)}")
            js_refs.update(chunk_found)

        # Cross-origin JS host crawl
        cross_origin_hosts = set()
        for u in list(js_refs):
            host = urlparse(u).netloc
            if host and not _host_in_scope(host, domain):
                cross_origin_hosts.add(host)

        if cross_origin_hosts and mode == "full":
            ctx.log(f"[js_discovery]   Cross-origin JS hosts: {', '.join(list(cross_origin_hosts)[:5])}")
            extra_refs = set()
            for host in list(cross_origin_hosts)[:3]:
                co_url = f"https://{host}/"
                refs, _, _ = fetch_page_js_refs(co_url, ctx.timeout, ctx.user_agent, host)
                for ref in refs:
                    extra_refs.add(_resolve(ref, co_url))
            ctx.log(f"[js_discovery]   Cross-origin extra JS: {len(extra_refs)}")
            js_refs.update(extra_refs)

    ctx.log(f"[js_discovery]   Total unique JS refs: {len(js_refs)}")

    # Source map discovery (threaded)
    source_maps = {}
    js_list     = sorted(js_refs)

    ctx.log(f"[js_discovery] Checking source maps for {len(js_list)} JS files...")
    with ThreadPoolExecutor(max_workers=20) as ex:
        sm_futures = {
            ex.submit(check_source_map, js_url, ctx.timeout, ctx.user_agent): js_url
            for js_url in js_list
        }
        for f in as_completed(sm_futures):
            js_url = sm_futures[f]
            sm_url = f.result()
            if sm_url:
                source_maps[js_url] = sm_url

    ctx.log(f"[js_discovery]   Source maps found: {len(source_maps)}")

    ctx.js_files    = js_list
    ctx.source_maps = source_maps

    ctx.write_text("js_files.txt",    "\n".join(js_list))
    ctx.write_json("source_maps.json", source_maps)
    if ctx.inline_script_endpoints:
        ctx.write_text("inline_endpoints.txt", "\n".join(ctx.inline_script_endpoints))
    if ctx.inline_script_params:
        ctx.write_text("inline_params.txt", "\n".join(ctx.inline_script_params))

    ctx.phases_run.append("js_discovery")
    ctx.log_phase_done(
        phase_num, total, "js_discovery",
        f"{len(js_list)} JS files | "
        f"{len(source_maps)} source maps | "
        f"{len(all_inline_eps)} inline endpoints | "
        f"{len(all_inline_pars)} inline params",
    )
    return ctx
