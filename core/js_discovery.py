"""
js_discovery.py — JS File Discovery

Strategy (quick / no-tools):
  1. Fetch canonical root page → extract <script src=...>
  2. Fetch each live robots.txt page → extract <script src=...>
  3. Fetch sitemap-seeded pages (up to N) → extract <script src=...>
  4. Wayback CDX passive JS URL lookup (no target contact)
  5. Pull .js URLs already in ctx.url_pool (built by urls phase)
  6. For each JS URL: check for .map source map

Standard/full modes add:
  - Chunk pattern enumeration (common Next.js / webpack chunk paths)
  - Cross-origin JS host crawl
"""

import re, requests, shutil, subprocess
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.context import Context
from core.urls import is_blocked

SCRIPT_SRC  = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
MAP_COMMENT = re.compile(r'(?://[#@]\s*sourceMappingURL=([^\s]+\.map))', re.IGNORECASE)

HEADERS = {
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept":          "text/html,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# Common Next.js / webpack / Vite chunk paths to try if we detect the framework
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

# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve(ref, base_url):
    if ref.startswith("//"): return "https:" + ref
    if ref.startswith("http"): return ref
    return urljoin(base_url, ref)

def fetch_page_js_refs(url, timeout, ua):
    """GET a page and return all JS src references found. Returns (refs[], blocked)."""
    try:
        r = requests.get(url, timeout=timeout,
                         headers={**HEADERS, "User-Agent": ua},
                         allow_redirects=True)
        if r.status_code != 200:
            return [], False
        if is_blocked(r.text, r.status_code):
            return [], True
        refs = SCRIPT_SRC.findall(r.text)
        return refs, False
    except Exception:
        return [], False

def check_source_map(js_url, timeout, ua):
    """Check if a JS file has a source map. Returns map URL or None."""
    try:
        r = requests.get(js_url, timeout=timeout,
                         headers={**HEADERS, "User-Agent": ua},
                         allow_redirects=True)
        if r.status_code != 200:
            return None
        sm = r.headers.get("SourceMap", "") or r.headers.get("X-SourceMap", "")
        if sm:
            return urljoin(js_url, sm)
        tail = r.text[-800:] if len(r.text) > 800 else r.text
        m = MAP_COMMENT.search(tail)
        if m:
            return urljoin(js_url, m.group(1))
        map_url = js_url.split("?")[0] + ".map"
        rm = requests.head(map_url, timeout=timeout,
                           headers={"User-Agent": ua}, allow_redirects=True)
        if rm.status_code == 200:
            return map_url
    except Exception:
        pass
    return None

def seed_js_from_wayback(domain, timeout, ctx):
    """Passive JS discovery via Wayback CDX — never touches target server."""
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
    """Try known chunk paths based on detected tech stack."""
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
    """Return True if URL path ends in .js (ignoring query string)."""
    try:
        path = urlparse(url).path
        return bool(JS_EXT_RE.search(path))
    except Exception:
        return False

# ── Phase runner ──────────────────────────────────────────────────────────────

def run(ctx: Context, phase_num=4, total=9) -> Context:
    base_url   = getattr(ctx, "canonical_url", None) or ctx.target_url
    domain     = urlparse(base_url).netloc.lstrip("www.")
    mode       = getattr(ctx, "mode", "standard")
    tech_stack = getattr(ctx, "tech_stack", [])

    ctx.log(f"[js_discovery] Base: {base_url}  mode={mode}")

    # ── Step 1: Seed pages to crawl for <script src=...> ─────────────────────
    seed_pages = [base_url]

    for r in ctx.robots_live:
        if r.get("status") == 200:
            seed_pages.append(r.get("resolved_url") or r["url"])

    seed_pages += ctx.sitemap_urls[:30]

    for u in ctx.url_pool[:50]:
        if "?" in u:
            seed_pages.append(u)

    seed_pages = list(dict.fromkeys(seed_pages))
    ctx.log(f"[js_discovery] Scanning {len(seed_pages)} seed pages for JS refs...")

    # ── Step 2: Parallel page fetch → JS ref extraction ──────────────────────
    js_refs  = set()
    blocked  = 0
    pages_done = 0

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {
            ex.submit(fetch_page_js_refs, url, ctx.timeout, ctx.user_agent): url
            for url in seed_pages
        }
        for f in as_completed(futures):
            refs, was_blocked = f.result()
            pages_done += 1
            if was_blocked:
                blocked += 1
            for ref in refs:
                js_refs.add(_resolve(ref, futures[f]))

    ctx.log(f"[js_discovery]   {pages_done} pages → {len(js_refs)} JS refs"
            + (f" ({blocked} blocked)" if blocked else ""))

    # ── Step 3: Wayback CDX passive JS seed ───────────────────────────────────
    wayback_js = seed_js_from_wayback(domain, ctx.timeout, ctx)
    js_refs.update(wayback_js)

    # ── Step 4: Chunk pattern probe (standard/full) ───────────────────────────
    if mode in ("standard", "full"):
        ctx.log("[js_discovery] Probing common chunk patterns...")
        chunk_js = try_chunk_patterns(base_url, tech_stack, ctx.timeout, ctx.user_agent)
        ctx.log(f"[js_discovery]   Chunk patterns → {len(chunk_js)} found")
        js_refs.update(chunk_js)

    # ── Step 5: Drain .js URLs already in ctx.url_pool (built by urls phase) ──
    pool_js = [u for u in ctx.url_pool if _is_js_url(u)]
    ctx.log(f"[js_discovery]   url_pool .js drain → {len(pool_js)} URLs")
    js_refs.update(pool_js)

    # ── Step 6: Filter to in-scope JS files ──────────────────────────────────
    in_scope = []
    for url in js_refs:
        try:
            host = urlparse(url).netloc.lower()
            bare = domain.lower()
            if host == bare or host.endswith("." + bare) or bare in host:
                in_scope.append(url)
        except Exception:
            pass

    in_scope = list(dict.fromkeys(in_scope))
    ctx.log(f"[js_discovery]   In-scope JS files: {len(in_scope)}")

    # ── Step 7: Source map detection (parallel) ───────────────────────────────
    ctx.log(f"[js_discovery] Checking {len(in_scope)} JS files for source maps...")
    source_maps = {}

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {
            ex.submit(check_source_map, url, ctx.timeout, ctx.user_agent): url
            for url in in_scope
        }
        for f in as_completed(futures):
            js_url  = futures[f]
            map_url = f.result()
            if map_url:
                source_maps[js_url] = map_url
                ctx.log(f"[js_discovery]   ★ SOURCE MAP  {js_url}")

    ctx.js_files    = in_scope
    ctx.source_maps = source_maps

    ctx.write_text("js_files.txt", "\n".join(in_scope))
    if source_maps:
        ctx.write_json("source_maps.json",
                       [{"js": k, "map": v} for k, v in source_maps.items()])

    ctx.phases_run.append("js_discovery")
    ctx.log_phase_done(phase_num, total, "js_discovery",
        f"{len(in_scope)} JS files | {len(source_maps)} source maps | "
        f"{len(wayback_js)} from Wayback | {len(pool_js)} from url_pool")
    return ctx
