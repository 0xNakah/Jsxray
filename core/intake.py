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

_BODY_LIMIT = 32 * 1024  # 32 KB is enough for fingerprinting


def normalize_target(target: str):
    if not target.startswith("http"):
        target_url = f"https://{target}"
    else:
        target_url = target
    target_url = target_url.rstrip("/")
    netloc = urlparse(target_url).netloc
    domain = netloc.lstrip("www.")
    return target_url, domain


def _fetch_root(target_url: str, timeout: int, headers: dict):
    """
    Fetch the root URL once with streaming enabled.
    Returns (response, body_snippet) where body_snippet is at most _BODY_LIMIT bytes.
    On failure returns (None, "").
    """
    try:
        r = requests.get(target_url, timeout=timeout, headers=headers,
                         allow_redirects=True, stream=True)
        body = b""
        for chunk in r.iter_content(chunk_size=8192):
            body += chunk
            if len(body) >= _BODY_LIMIT:
                break
        r._content = body          # cache so r.text works normally
        r.encoding = r.encoding or "utf-8"
        return r, body.decode(r.encoding, errors="replace")
    except Exception:
        return None, ""


def detect_canonical(response, target_url: str):
    """
    Derive the canonical base URL from the already-fetched response.
    Falls back to target_url if response is None.
    """
    if response is not None:
        final  = response.url.rstrip("/")
        parsed = urlparse(final)
        canonical_base = f"{parsed.scheme}://{parsed.netloc}"
        return canonical_base, parsed.netloc
    parsed = urlparse(target_url)
    return f"{parsed.scheme}://{parsed.netloc}", parsed.netloc


def fetch_robots(target_url: str, timeout: int, headers: dict):
    parsed   = urlparse(target_url)
    base     = f"{parsed.scheme}://{parsed.netloc}"
    bare     = parsed.netloc.lstrip("www.")
    www_base = f"{parsed.scheme}://www.{bare}"

    candidates = list(dict.fromkeys([base, www_base]))
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


def detect_tech_stack(response, body: str):
    """
    Fingerprint from an already-fetched response + body snippet.
    Also returns csp_missing flag separately.
    """
    tech = []
    csp_missing = True
    if response is None:
        return tech, csp_missing

    h = {k.lower(): v for k, v in response.headers.items()}

    for hdr in ("server", "x-powered-by", "x-generator", "x-aspnet-version"):
        if hdr in h:
            tech.append(h[hdr])

    hints = {
        "React":      ["__REACT_DEVTOOLS", "data-reactroot", "data-reactid"],
        "Next.js":    ["__NEXT_DATA__", "_next/static"],
        "Angular":    ["ng-version", "<app-root", "ng-app"],
        "Vue.js":     ["__vue__", "data-v-", "<div id=\"app\""],
        "WordPress":  ["wp-content", "wp-includes"],
        "Drupal":     ["Drupal.settings", "/sites/default/files"],
        "Cloudflare": ["cf-ray", "__cf_bm", "cloudflare"],
        "GraphQL":    ["/graphql", "__typename", "operationName"],
        "PerimeterX": ["_pxAppId", "px.js", "PerimeterX"],
        "Akamai":     ["akamai", "akam/"],
    }
    for name, sigs in hints.items():
        if any(sig.lower() in body.lower() or sig.lower() in str(h) for sig in sigs):
            tech.append(name)

    if "content-security-policy" in h:
        csp_missing = False

    return list(set(tech)), csp_missing


def run(ctx: Context, phase_num=1, total=9) -> Context:
    if not ctx.silent:
        print(BANNER)

    ctx.target_url, domain = normalize_target(ctx.target)
    ctx.target = domain

    output_dir = ctx.config.get("defaults", {}).get("output_dir", "recon")
    ctx.setup_workspace(output_dir)

    headers = {**HEADERS, "User-Agent": ctx.user_agent}

    # ── Single root fetch (reused for canonical + fingerprinting) ──────────────
    root_response, body_snippet = _fetch_root(ctx.target_url, ctx.timeout, headers)

    # ── Canonical URL ──────────────────────────────────────────────────
    canonical_base, canonical_netloc = detect_canonical(root_response, ctx.target_url)
    if canonical_netloc != urlparse(ctx.target_url).netloc:
        ctx.log(f"[intake] Redirect    : {ctx.target_url} → {canonical_base}")
        ctx.target_url = canonical_base
    ctx.canonical_url = canonical_base

    ctx.log(f"[intake] Target URL : {ctx.target_url}")
    ctx.log(f"[intake] Domain     : {ctx.target}")
    ctx.log(f"[intake] Workspace  : {ctx.workspace}")

    # ── Tech stack (no extra HTTP request) ─────────────────────────────
    tech, csp_missing = detect_tech_stack(root_response, body_snippet)
    if tech:
        ctx.tech_stack = tech
        ctx.log(f"[intake] Tech stack : {', '.join(tech)}")
    ctx.csp_missing = csp_missing
    if csp_missing:
        ctx.log("[intake] CSP        : missing")

    # ── robots.txt ────────────────────────────────────────────────────────────
    raw, robots_url = fetch_robots(ctx.target_url, ctx.timeout, headers)
    if raw:
        ctx.robots_raw = raw
        ctx.write_text("robots_raw.txt", raw)
        ctx.log(
