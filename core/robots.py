import re, requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.context import Context
from core.urls import is_blocked

SKIP_EXT = (
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css',
    '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip', '.tar',
    '.gz', '.mp4', '.mp3', '.webp', '.bmp',
)

# Paths that are never interesting for XSS
SKIP_PATH_PATTERNS = [
    r'^/media/',
    r'^/static/',
    r'^/pdfs/',
    r'^/js\d?/',
    r'^/cds/media',
]

HIGH_VALUE_PATTERNS = [
    r'search', r'query', r'q=', r'redirect', r'url=', r'callback',
    r'return', r'next', r'goto', r'dest', r'error', r'message',
    r'template', r'view', r'page', r'preview', r'debug',
    r'api', r'json', r'ajax', r'data',
]


def parse_robots(raw: str):
    """Extract all Allow/Disallow paths from robots.txt, all user-agents."""
    paths = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith(("disallow:", "allow:")):
            p = line.split(":", 1)[1].strip()
            if p and p != "/" and "*" not in p and "$" not in p:
                paths.append(p)
    return list(set(paths))


def is_interesting_path(path: str) -> bool:
    """Heuristic: flag paths likely to accept parameters."""
    lp = path.lower()
    if any(re.search(pat, lp) for pat in SKIP_PATH_PATTERNS):
        return False
    if any(re.search(pat, lp) for pat in HIGH_VALUE_PATTERNS):
        return True
    return False


def probe_path(base_url: str, path: str, timeout: int, ua: str,
               canonical_base: str = None):
    """Probe one robots.txt path using the canonical base host.

    Uses allow_redirects=True so we get the actual final response,
    not the 301 on the apex-domain redirect host.
    Stores resolved_url when the final URL differs from the constructed one.
    """
    effective_base = canonical_base if canonical_base else base_url
    parsed = urlparse(effective_base)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    url    = urljoin(base + "/", path.lstrip("/"))

    result = {
        "path":         path,
        "url":          url,
        "status":       None,
        "content_type": "",
        "length":       0,
        "redirect_to":  None,
        "interesting":  False,
        "note":         "",
        "resolved_url": None,
        "high_value":   is_interesting_path(path),
    }
    try:
        r = requests.get(
            url, timeout=timeout,
            headers={
                "User-Agent":      ua,
                "Accept":          "text/html,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Referer":         base,
            },
            allow_redirects=True,
        )
        result["status"]       = r.status_code
        result["content_type"] = r.headers.get("content-type", "")
        result["length"]       = len(r.content)
        result["resolved_url"] = r.url if r.url != url else None

        if r.status_code == 200:
            if is_blocked(r.text, r.status_code):
                result["note"] = "bot-blocked"
            else:
                ct = result["content_type"].lower()
                if "text/html" in ct:
                    result["interesting"] = True
                    result["note"]        = "HTML — XSS candidate"
                elif "json" in ct:
                    result["interesting"] = True
                    result["note"]        = "JSON API"
                elif "javascript" in ct:
                    result["interesting"] = True
                    result["note"]        = "JS endpoint"
        elif r.status_code == 403:
            result["interesting"] = True
            result["note"]        = "403 — try bypass"
        elif r.status_code == 401:
            result["interesting"] = True
            result["note"]        = "401 — auth required"
        elif r.status_code in (301, 302, 303, 307, 308):
            # Final hop is still a redirect (external, etc.)
            result["redirect_to"] = r.headers.get("Location", "")
            result["note"]        = f"redirect → {result['redirect_to']}"
    except requests.exceptions.Timeout:
        result["status"] = "timeout"
    except Exception as e:
        result["status"] = "error"
        result["note"]   = str(e)[:80]
    return result


def run(ctx: Context, phase_num=2, total=9) -> Context:
    if not ctx.robots_raw:
        ctx.phases_run.append("robots")
        ctx.log_phase_done(phase_num, total, "robots", "no robots.txt — phase skipped")
        return ctx

    ctx.log(f"[robots] Parsing {len(ctx.robots_raw)} bytes...")

    raw_paths = parse_robots(ctx.robots_raw)
    paths     = [p for p in raw_paths
                 if not any(p.lower().endswith(e) for e in SKIP_EXT)]
    ctx.robots_paths = paths

    canonical_base = getattr(ctx, "canonical_url", None) or ctx.target_url
    ctx.log(f"[robots] {len(raw_paths)} paths → {len(paths)} after filter "
            f"| canonical: {canonical_base} | 20 threads")

    results = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {
            ex.submit(probe_path, ctx.target_url, p, ctx.timeout,
                      ctx.user_agent, canonical_base): p
            for p in paths
        }
        for f in as_completed(futures):
            r = f.result()
            results.append(r)
            if not ctx.silent and r["interesting"]:
                flag = "★" if r.get("high_value") else " "
                print(f"[robots] {flag} {str(r['status']):>5}  "
                      f"{r['path']:<50}  {r['note']}")

    # Sort: high-value + interesting first
    results.sort(key=lambda x: (not x.get("high_value"), not x["interesting"],
                                 str(x["status"])))
    ctx.robots_live = results

    # Feed live HTML pages into url_pool using resolved_url
    for r in results:
        if r["status"] == 200:
            live_url = r.get("resolved_url") or r["url"]
            if live_url not in ctx.url_pool:
                ctx.url_pool.append(live_url)

    # Write condensed JSON — only interesting entries to keep file small
    interesting = [r for r in results if r["interesting"]]
    ctx.write_json("robots_paths.json", {
        "total":       len(paths),
        "live":        len([r for r in results if r["status"] == 200]),
        "interesting": len(interesting),
        "results":     results,
    })

    live     = len([r for r in results if r["status"] == 200])
    f403     = len([r for r in results if r["status"] == 403])
    redir    = len([r for r in results if r["status"] in (301, 302, 307, 308)])
    timeouts = len([r for r in results if r["status"] == "timeout"])

    ctx.phases_run.append("robots")
    ctx.log_phase_done(phase_num, total, "robots",
        f"{len(paths)} paths | {live} live | {f403} 403 | "
        f"{redir} redirect | {timeouts} timeout | "
        f"{len(interesting)} interesting")
    return ctx
