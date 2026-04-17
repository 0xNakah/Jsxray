import re, requests
from urllib.parse import urljoin, urlparse
from core.context import Context

BANNER = r"""
     _ ___  _____
    | / __| \  / _ ___ _ _  _
 _  | \__ \  X | '_/ _` | || |
| |_| |___/ / \|_| \__,_|\_, |
 \___/     /_/\_\         |__/
 XSS Intelligence Engine v0.1
"""

HEADERS = {
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer":         "https://www.google.com/",
    "DNT":             "1",
    "Connection":      "keep-alive",
}


def normalize_target(target: str):
    """Return (target_url, domain).
    Preserves www. if supplied; domain is bare (no www/scheme) for workspace naming.
    """
    if not target.startswith("http"):
        target_url = f"https://{target}"
    else:
        target_url = target
    target_url = target_url.rstrip("/")
    netloc = urlparse(target_url).netloc
    domain = netloc.lstrip("www.")
    return target_url, domain


def detect_canonical(target_url: str, timeout: int, headers: dict):
    """Follow root URL redirects to find the real canonical base.

    e.g. https://tripadvisor.com  →  https://www.tripadvisor.com
    Returns (canonical_base, canonical_netloc).
    Falls back to the original URL on any error.
    """
    try:
        r = requests.get(target_url, timeout=timeout, headers=headers,
                         allow_redirects=True)
        final  = r.url.rstrip("/")
        parsed = urlparse(final)
        canonical_base = f"{parsed.scheme}://{parsed.netloc}"
        return canonical_base, parsed.netloc
    except Exception:
        parsed = urlparse(target_url)
        return f"{parsed.scheme}://{parsed.netloc}", parsed.netloc


def fetch_robots(target_url: str, timeout: int, headers: dict):
    """Try robots.txt on canonical, www, and bare domain."""
    parsed   = urlparse(target_url)
    base     = f"{parsed.scheme}://{parsed.netloc}"
    bare     = parsed.netloc.lstrip("www.")
    www_base = f"{parsed.scheme}://www.{bare}"

    candidates = list(dict.fromkeys([base, www_base]))  # dedup while preserving order
    for base_try in candidates:
        url = f"{base_try}/robots.txt"
        try:
            r = requests.get(url, timeout=timeout, headers=headers,
                             allow_redirects=True)
            if r.status_code == 200 and len(r.text) > 10:
                if any(k in r.text for k in
                       ["Disallow", "disallow", "User-agent", "user-agent", "Allow"]):
                    return r.text, url
        except Exception:
            pass
    return "", ""


def fetch_sitemap(target_url: str, timeout: int, headers: dict):
    """Try sitemap.xml and sitemap_index.xml on canonical + www."""
    parsed   = urlparse(target_url)
    base     = f"{parsed.scheme}://{parsed.netloc}"
    www_base = f"{parsed.scheme}://www.{parsed.netloc.lstrip('www.')}"
    urls     = []

    for base_try in list(dict.fromkeys([base, www_base])):
        for sm_path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"]:
            try:
                r = requests.get(f"{base_try}{sm_path}", timeout=timeout,
                                 headers=headers, allow_redirects=True)
                if r.status_code == 200 and "<loc>" in r.text:
                    found = re.findall(r'<loc>(https?://[^<]+)</loc>', r.text)
                    urls.extend(found)
                    if urls:
                        return list(set(urls))
            except Exception:
                pass
    return []


def detect_tech_stack(target_url: str, timeout: int, headers: dict):
    """Lightweight fingerprint of server/framework from response headers + body."""
    tech = []
    try:
        r = requests.get(target_url, timeout=timeout, headers=headers,
                         allow_redirects=True)
        h   = {k.lower(): v for k, v in r.headers.items()}
        body = r.text[:8000]

        # Server / X-Powered-By
        for hdr in ("server", "x-powered-by", "x-generator", "x-aspnet-version"):
            if hdr in h:
                tech.append(h[hdr])

        # Framework hints from body
        hints = {
            "React":          ["__REACT_DEVTOOLS", "data-reactroot", "data-reactid"],
            "Next.js":        ["__NEXT_DATA__", "_next/static"],
            "Angular":        ["ng-version", "<app-root", "ng-app"],
            "Vue.js":         ["__vue__", "data-v-", "<div id=\"app\""],
            "WordPress":      ["wp-content", "wp-includes"],
            "Drupal":         ["Drupal.settings", "/sites/default/files"],
            "Cloudflare":     ["cf-ray", "__cf_bm", "cloudflare"],
            "GraphQL":        ["/graphql", "__typename", "operationName"],
            "PerimeterX":     ["_pxAppId", "px.js", "PerimeterX"],
            "Akamai":         ["akamai", "akam/"],
        }
        for name, sigs in hints.items():
            if any(sig.lower() in body.lower() or sig.lower() in str(h) for sig in sigs):
                tech.append(name)

        # CSP present?
        if "content-security-policy" in h:
            tech.append("CSP")
        else:
            tech.append("no-CSP")
    except Exception:
        pass
    return list(set(tech))


def run(ctx: Context, phase_num=1, total=9) -> Context:
    if not ctx.silent:
        print(BANNER)

    ctx.target_url, domain = normalize_target(ctx.target)
    ctx.target = domain

    output_dir = ctx.config.get("defaults", {}).get("output_dir", "recon")
    ctx.setup_workspace(output_dir)

    headers = {**HEADERS, "User-Agent": ctx.user_agent}

    # ── Canonical URL detection ───────────────────────────────────────────────
    canonical_base, canonical_netloc = detect_canonical(ctx.target_url, ctx.timeout, headers)
    if canonical_netloc != urlparse(ctx.target_url).netloc:
        ctx.log(f"[intake] Redirect    : {ctx.target_url} → {canonical_base}")
        ctx.target_url = canonical_base
    ctx.canonical_url = canonical_base

    ctx.log(f"[intake] Target URL : {ctx.target_url}")
    ctx.log(f"[intake] Domain     : {ctx.target}")
    ctx.log(f"[intake] Workspace  : {ctx.workspace}")

    # ── Tech stack fingerprint ────────────────────────────────────────────────
    tech = detect_tech_stack(ctx.target_url, ctx.timeout, headers)
    if tech:
        ctx.tech_stack = tech
        ctx.log(f"[intake] Tech stack : {', '.join(tech)}")

    # ── robots.txt ───────────────────────────────────────────────────────────
    raw, robots_url = fetch_robots(ctx.target_url, ctx.timeout, headers)
    if raw:
        ctx.robots_raw = raw
        ctx.write_text("robots_raw.txt", raw)
        ctx.log(f"[intake] robots.txt  : {len(raw)} bytes  ({robots_url})")
    else:
        ctx.log(f"[intake] robots.txt  : not found")

    # ── sitemap.xml ──────────────────────────────────────────────────────────
    sitemap_urls = fetch_sitemap(ctx.target_url, ctx.timeout, headers)
    if sitemap_urls:
        ctx.sitemap_urls = sitemap_urls
        ctx.url_pool.extend(sitemap_urls)
        ctx.log(f"[intake] sitemap.xml : {len(sitemap_urls)} URLs")
    else:
        ctx.log(f"[intake] sitemap.xml : not found")

    ctx.phases_run.append("intake")
    ctx.log_phase_done(phase_num, total, "intake",
        f"canonical={ctx.canonical_url} | "
        f"robots={'yes' if ctx.robots_raw else 'no'} | "
        f"sitemap={len(ctx.sitemap_urls)} URLs | "
        f"tech=[{', '.join(tech[:4]) if tech else 'unknown'}]")
    return ctx
