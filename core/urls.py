"""
urls.py — URL Harvest Phase

FIX 4:  Before calling uro to deduplicate the full URL pool we now extract
        every unique query-parameter name from the raw (pre-uro) list and
        store them in ctx.pre_uro_params.  probe.py will inject each of
        those params onto the root URL so nothing discovered pre-dedup is lost.

FIX 5:  Add xnLinkFinder as a URL source (standard + full modes).
        Runs: xnLinkFinder -i <target_url> -sp <target_url> -sf -siv -o -
"""

import os, shutil, subprocess, requests
from urllib.parse import urlparse, parse_qs, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.context import Context

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

# Phrases that indicate a WAF/bot-block page
_BLOCK_PHRASES = [
    "access denied", "403 forbidden", "blocked",
    "captcha", "are you a human", "security check",
    "ray id", "cloudflare", "bot protection",
    "ddos protection", "please enable javascript",
    "just a moment", "verifying you are human",
]


def is_blocked(html: str, status_code) -> bool:
    if status_code == 403:
        return True
    text = html.lower()
    return any(phrase in text for phrase in _BLOCK_PHRASES)


def _dedup(lst):
    seen, out = set(), []
    for u in lst:
        if u not in seen:
            seen.add(u); out.append(u)
    return out


def should_keep(url, domain):
    try:
        p    = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        host = p.netloc.lower().lstrip("www.")
        base = domain.lower().lstrip("www.")
        if not (host == base or host.endswith("." + base)):
            return False
        path = p.path.lower()
        if os.path.splitext(path)[1] in SKIP_EXT:
            return False
        if any(s in url for s in SKIP_STRINGS):
            return False
        return True
    except Exception:
        return False


def merge_and_filter(batches, domain):
    seen, unique = set(), []
    for batch in batches:
        for url in batch:
            url = url.strip().rstrip("/")
            if url and url not in seen and should_keep(url, domain):
                seen.add(url); unique.append(url)
    return unique


# ── FIX 4: extract param names from ALL URLs before uro deduplication ────────
def harvest_params_pre_uro(urls):
    """Return every query-param name seen across the raw (pre-uro) URL list."""
    params = set()
    for url in urls:
        try:
            qs = parse_qs(urlparse(url).query, keep_blank_values=True)
            params.update(qs.keys())
        except Exception:
            pass
    return params


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


# ── Source harvesters ─────────────────────────────────────────────────────────

CDX_PATTERNS = [
    "*.js","*/api/*","*.php","*.aspx","*.jsp",
    "*/search*","*/v1/*","*/v2/*","*/graphql*",
    "*/rest/*","*/ajax/*","*?*",
]

def fetch_wayback_cdx(domain, timeout):
    urls = []
    base = "https://web.archive.org/cdx/search/cdx"
    for pat in CDX_PATTERNS:
        try:
            r = requests.get(base, params={
                "url": f"{domain}/{pat}", "output": "text",
                "fl": "original", "collapse": "urlkey",
                "limit": "500", "filter": "statuscode:200",
            }, timeout=timeout)
            if r.status_code == 200 and r.text.strip():
                urls.extend([u.strip() for u in r.text.strip().split("\n")
                              if u.strip().startswith("http")])
        except Exception:
            pass
    return _dedup(urls)


def fetch_urlscan(domain, timeout):
    urls = []
    try:
        r = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000",
            timeout=timeout, headers={"User-Agent": "jsxray/0.2"},
        )
        if r.status_code == 200:
            for res in r.json().get("results", []):
                u = res.get("page", {}).get("url", "")
                if u:
                    urls.append(u)
    except Exception:
        pass
    return urls


def run_tool(cmd, timeout):
    if not shutil.which(cmd[0]):
        return []
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout * 3)
        return [u.strip() for u in result.stdout.splitlines()
                if u.strip().startswith("http")]
    except Exception:
        return []


def run_katana(target_url, timeout):
    return run_tool(
        ["katana", "-u", target_url, "-d", "3", "-jc", "-fx", "-kf", "all",
         "-silent", "-timeout", str(timeout), "-c", "10", "-rl", "50"],
        timeout,
    )


def run_xnlinkfinder(target_url, timeout):
    """Run xnLinkFinder against target_url.
    Outputs one URL per line to stdout; we filter for http(s) lines.
    -sf  = stop at first found
    -siv = skip invalid SSL
    -sp  = scope prefix (stay in-scope)
    -o - = write to stdout
    """
    return run_tool(
        [
            "xnLinkFinder",
            "-i",  target_url,
            "-sp", target_url,
            "-sf",
            "-siv",
            "-o",  "-",
        ],
        timeout,
    )


# ── Phase runner ──────────────────────────────────────────────────────────────

def run(ctx, phase_num=3, total=9):
    parsed = urlparse(ctx.target_url) if ctx.target_url else None
    domain = (parsed.netloc if parsed and parsed.netloc else ctx.target).lstrip("www.")
    mode   = getattr(ctx, "mode", "standard")

    # Quick mode: skip tool harvest, still harvest pre-uro params from seeds
    if mode == "quick":
        pre = harvest_params_pre_uro(ctx.url_pool)
        existing = set(getattr(ctx, "js_global_params", []))
        ctx.pre_uro_params = sorted(pre - existing)
        ctx.log(
            f"[urls] Quick mode — using {len(ctx.url_pool)} seed URLs"
            f" | {len(ctx.pre_uro_params)} pre-uro params"
        )
        ctx.write_text("all_urls.txt", "\n".join(ctx.url_pool))
        ctx.write_text("pre_uro_params.txt", "\n".join(ctx.pre_uro_params))
        ctx.phases_run.append("urls")
        ctx.log_phase_done(phase_num, total, "urls",
            f"{len(ctx.url_pool)} seed URLs | "
            f"{len(ctx.pre_uro_params)} pre-uro params (quick mode)")
        return ctx

    print(f"[urls] Harvesting URLs for {domain}  [mode={mode}]...")
    results = {}

    sources = {
        "wayback_cdx":   (fetch_wayback_cdx,   [domain,          ctx.timeout]),
        "urlscan":       (fetch_urlscan,        [domain,          ctx.timeout]),
        "gau":           (run_tool,             [["gau", "--timeout", str(ctx.timeout),
                                                  "--retries", "2", domain], ctx.timeout]),
        "waybackurls":   (run_tool,             [["waybackurls", domain],    ctx.timeout]),
        "waymore":       (run_tool,             [["waymore", "-i", domain, "-mode", "U",
                                                  "-oU", "-"],               ctx.timeout]),
        "xnlinkfinder":  (run_xnlinkfinder,     [ctx.target_url,  ctx.timeout]),
    }
    if mode == "full":
        sources["katana"] = (run_katana, [ctx.target_url, ctx.timeout])

    with ThreadPoolExecutor(max_workers=len(sources)) as ex:
        futures = {
            ex.submit(fn, *args): name
            for name, (fn, args) in sources.items()
        }
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                batch         = fut.result() or []
                results[name] = batch
                print(f"[urls]   {name:<15} → {len(batch):>5} URLs")
            except Exception as e:
                results[name] = []
                print(f"[urls]   {name:<15} → ERROR: {e}")

    # Merge all sources
    ordered = [
        results.get("wayback_cdx",   []),
        results.get("urlscan",       []),
        results.get("waymore",       []),
        results.get("gau",           []),
        results.get("waybackurls",   []),
        results.get("xnlinkfinder",  []),
        results.get("katana",        []),
        [r.get("resolved_url") or r["url"]
         for r in ctx.robots_live if r.get("status") == 200],
        getattr(ctx, "sitemap_urls", []),
        ctx.url_pool,
    ]
    merged = merge_and_filter(ordered, domain)
    print(f"[urls]   merged (pre-uro)  → {len(merged):>5} URLs")

    # FIX 4: harvest param names from the full pre-uro set BEFORE uro strips
    #         duplicate-param variants (e.g. ?q=1 and ?q=2 both contribute "q")
    pre_params = harvest_params_pre_uro(merged)
    existing   = set(getattr(ctx, "js_global_params", []))
    ctx.pre_uro_params = sorted(pre_params - existing)
    print(
        f"[urls]   pre-uro params   → {len(pre_params):>5} unique param names"
        f" ({len(ctx.pre_uro_params)} new vs js_extract)"
    )

    if len(merged) > 50:
        merged = dedup_with_uro(merged, ctx.workspace)
        print(f"[urls]   after uro        → {len(merged):>5} URLs")

    if not merged:
        print("[urls]   0 URLs after filter — check domain or bot protection")

    ctx.url_pool = merged
    ctx.write_json("url_sources.json", {s: len(b) for s, b in results.items()})
    ctx.write_text("all_urls.txt",        "\n".join(merged))
    ctx.write_text("pre_uro_params.txt",  "\n".join(ctx.pre_uro_params))

    ctx.phases_run.append("urls")
    ctx.log_phase_done(
        phase_num, total, "urls",
        f"{len(merged)} URLs | "
        + " ".join(f"{n}={len(b)}" for n, b in results.items())
        + f" | pre_uro_params={len(ctx.pre_uro_params)}",
    )
    return ctx
