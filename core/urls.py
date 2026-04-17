"""
urls.py — URL Harvest Phase

quick mode  : skipped entirely (robots.txt + sitemap seeds used directly)
standard    : wayback CDX + gau + waybackurls + waymore (passive)
full        : standard + katana live crawl
"""

import subprocess, requests, json, re, os, shutil
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.context import Context

# ── Bot/block detector (also imported by robots, js_discovery) ───────────────

BLOCK_SIGNALS = [
    "px-captcha", "_pxAppId", "PerimeterX", "pxchallenge",
    "Access Denied", "cf-browser-verification", "cf_chl_opt",
    "Checking your browser", "DDoS protection by",
    "Enable JavaScript and cookies to continue",
    "window._px", "captcha-container", "grecaptcha",
    "distil_r_blocked", "Incapsula incident",
    "Request unsuccessful", "bot detection",
    "px.js", "px-block", "blocked by",
    "security challenge", "human verification",
    "__cf_bm", "cf-ray",
]

def is_blocked(text, status_code=200):
    if status_code in (403, 429, 503, 999):
        return True
    lower = text[:3000].lower()
    return any(s.lower() in lower for s in BLOCK_SIGNALS)

# ── URL helpers ───────────────────────────────────────────────────────────────

SKIP_EXT = {
    ".png",".jpg",".jpeg",".gif",".webp",".svg",".ico",
    ".woff",".woff2",".ttf",".eot",".otf",
    ".mp4",".mp3",".webm",".ogg",
    ".pdf",".zip",".tar",".gz",".rar",".exe",".dmg",
    ".css",
}

SKIP_STRINGS = [
    "hot-update", "webpack/__", "__webpack", "sockjs",
    "node_modules", "/__hmr",
]

def _dedup_list(lst):
    seen, out = set(), []
    for u in lst:
        if u not in seen:
            seen.add(u); out.append(u)
    return out

def should_keep_url(url, domain):
    try:
        p    = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        host = p.netloc.lower().lstrip("www.")
        base = domain.lower().lstrip("www.")
        if not (host == base or host.endswith("." + base)):
            return False
        path = p.path.lower()
        ext  = os.path.splitext(path)[1]
        if ext in SKIP_EXT:
            return False
        if any(s in url for s in SKIP_STRINGS):
            return False
        return True
    except Exception:
        return False

def merge_and_filter(url_lists, domain):
    seen, unique = set(), []
    for batch in url_lists:
        for url in batch:
            url = url.strip().rstrip("/")
            if url and url not in seen and should_keep_url(url, domain):
                seen.add(url); unique.append(url)
    return unique

def dedup_with_uro(urls, workspace):
    if not shutil.which("uro"):
        return urls
    inf  = os.path.join(workspace, "_uro_input.txt")
    outf = os.path.join(workspace, "_uro_output.txt")
    try:
        with open(inf, "w") as f:
            f.write("\n".join(urls))
        subprocess.run(["uro", "-i", inf, "-o", outf],
                       capture_output=True, text=True, timeout=60)
        if os.path.exists(outf):
            deduped = [u.strip() for u in open(outf).readlines() if u.strip()]
            if deduped:
                return deduped
    except Exception:
        pass
    return urls

# ── Passive sources ───────────────────────────────────────────────────────────

CDX_PATTERNS = [
    "*.js", "*/api/*", "*.php", "*.aspx", "*.jsp",
    "*/search*", "*/v1/*", "*/v2/*", "*/graphql*",
    "*/rest/*", "*/ajax/*", "*?*",
]

def fetch_wayback_cdx(domain, timeout):
    urls = []
    base = "https://web.archive.org/cdx/search/cdx"
    for pattern in CDX_PATTERNS:
        try:
            r = requests.get(base, params={
                "url":      f"{domain}/{pattern}",
                "output":   "text",
                "fl":       "original",
                "collapse": "urlkey",
                "limit":    "500",
                "filter":   "statuscode:200",
            }, timeout=timeout)
            if r.status_code == 200 and r.text.strip():
                batch = [u.strip() for u in r.text.strip().split("\n")
                         if u.strip().startswith("http")]
                urls.extend(batch)
        except Exception:
            pass
    return _dedup_list(urls)

def fetch_urlscan(domain, timeout):
    urls = []
    try:
        r = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000",
            timeout=timeout,
            headers={"User-Agent": "jsxray/0.2"},
        )
        if r.status_code == 200:
            for result in r.json().get("results", []):
                u = result.get("page", {}).get("url", "")
                if u:
                    urls.append(u)
    except Exception:
        pass
    return urls

def run_gau(domain, timeout):
    if not shutil.which("gau"):
        return []
    try:
        result = subprocess.run(
            ["gau", "--timeout", str(timeout), "--retries", "2", domain],
            capture_output=True, text=True, timeout=timeout * 3,
        )
        return [u.strip() for u in result.stdout.splitlines()
                if u.strip().startswith("http")]
    except Exception:
        return []

def run_waybackurls(domain, timeout):
    if not shutil.which("waybackurls"):
        return []
    try:
        result = subprocess.run(
            ["waybackurls", domain],
            capture_output=True, text=True, timeout=timeout * 3,
        )
        return [u.strip() for u in result.stdout.splitlines()
                if u.strip().startswith("http")]
    except Exception:
        return []

def run_waymore(domain, timeout):
    """waymore by xnl-h4ck3r — best passive URL harvester."""
    if not shutil.which("waymore"):
        return []
    try:
        result = subprocess.run(
            ["waymore", "-i", domain, "-mode", "U", "-oU", "-"],
            capture_output=True, text=True, timeout=timeout * 3,
        )
        return [u.strip() for u in result.stdout.splitlines()
                if u.strip().startswith("http")]
    except Exception:
        return []

def run_katana(target_url, timeout):
    """Katana live crawl — only used in full mode."""
    if not shutil.which("katana"):
        return []
    try:
        result = subprocess.run(
            ["katana", "-u", target_url,
             "-d", "3", "-jc", "-fx", "-kf", "all",
             "-silent", "-timeout", str(timeout),
             "-c", "10", "-rl", "50"],
            capture_output=True, text=True, timeout=timeout * 5,
        )
        return [u.strip() for u in result.stdout.splitlines()
                if u.strip().startswith("http")]
    except Exception:
        return []

# ── Phase runner ──────────────────────────────────────────────────────────────

def run(ctx: Context, phase_num=3, total=9) -> Context:
    parsed = urlparse(ctx.target_url) if ctx.target_url else None
    domain = (parsed.netloc if parsed and parsed.netloc else ctx.target).lstrip("www.")

    mode = getattr(ctx, "mode", "standard")

    # Quick mode: robots + sitemap already in url_pool from intake/robots phases.
    # No external tools needed — skip straight to JS discovery.
    if mode == "quick":
        ctx.log(f"[urls] Quick mode — skipping tool harvest, using {len(ctx.url_pool)} seed URLs")
        ctx.write_text("all_urls.txt", "\n".join(ctx.url_pool))
        ctx.phases_run.append("urls")
        ctx.log_phase_done(phase_num, total, "urls",
            f"{len(ctx.url_pool)} seed URLs (robots+sitemap, no tool harvest in quick mode)")
        return ctx

    print(f"[urls] Harvesting URLs for {domain}  [mode={mode}]...")
    results = {}

    # Build source set based on mode
    sources = {
        "wayback_cdx":  (fetch_wayback_cdx,  [domain,      ctx.timeout]),
        "urlscan":      (fetch_urlscan,       [domain,      ctx.timeout]),
        "gau":          (run_gau,             [domain,      ctx.timeout]),
        "waybackurls":  (run_waybackurls,     [domain,      ctx.timeout]),
        "waymore":      (run_waymore,         [domain,      ctx.timeout]),
    }
    if mode == "full":
        sources["katana"] = (run_katana, [ctx.target_url, ctx.timeout])

    with ThreadPoolExecutor(max_workers=len(sources)) as ex:
        futures = {
            ex.submit(fn, *args): name
            for name, (fn, args) in sources.items()
        }
        for f in as_completed(futures):
            name = futures[f]
            try:
                batch         = f.result() or []
                results[name] = batch
                print(f"[urls]   {name:<15} → {len(batch):>5} URLs")
            except Exception as e:
                results[name] = []
                print(f"[urls]   {name:<15} → ERROR: {e}")

    # Merge: passive archives first, then live
    ordered = [
        results.get("wayback_cdx",  []),
        results.get("urlscan",      []),
        results.get("waymore",      []),
        results.get("gau",          []),
        results.get("waybackurls",  []),
        results.get("katana",       []),
        # always include robots/sitemap seeds
        [r.get("resolved_url") or r["url"] for r in ctx.robots_live if r.get("status") == 200],
        ctx.sitemap_urls,
        ctx.url_pool,
    ]

    merged = merge_and_filter(ordered, domain)
    print(f"[urls]   merged (pre-uro)  → {len(merged):>5} URLs")

    if len(merged) > 50:
        merged = dedup_with_uro(merged, ctx.workspace)
        print(f"[urls]   after uro        → {len(merged):>5} URLs")

    if not merged:
        print(f"[urls] ⚠  0 URLs after filter — check domain or bot protection")

    ctx.url_pool = merged
    ctx.write_json("url_sources.json", {src: len(b) for src, b in results.items()})
    ctx.write_text("all_urls.txt", "\n".join(merged))

    ctx.phases_run.append("urls")
    ctx.log_phase_done(phase_num, total, "urls",
        f"{len(merged)} URLs | " +
        " ".join(f"{n}={len(b)}" for n, b in results.items()))
    return ctx
