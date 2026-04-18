"""
crawl.py — Active Crawl Phase (xnLinkFinder)

Runs AFTER deep so it benefits from:
  - source-map-discovered endpoints added to ctx.url_pool
  - js_extract endpoint list
  - robots.txt / sitemap URLs already in pool

xnLinkFinder is seeded with every in-scope URL in ctx.url_pool,
crawls each one (following href/src/action/script tags, robots.txt,
sitemap.xml), and merges newly discovered URLs back into ctx.url_pool
before probe builds its pairs list.

Skipped gracefully if xnLinkFinder is not installed.
"""

import shutil, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from core.context import Context
from core.urls import should_keep, _dedup

MAX_SEEDS = 150
MAX_WORKERS = 15

HIGH_VALUE_KEYWORDS = [
    "/api/", "/graphql", "/search", "/ajax", "/rest/",
    "/v1/", "/v2/", "/v3/", "/user", "/account", "/admin",
    "/query", "/data", "/fetch", "/get", "/post",
]


def _is_valid_endpoint(url: str) -> bool:
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        netloc = p.netloc.split(":")[0]
        if not netloc or "." not in netloc:
            return False
        if len(netloc.rsplit(".", 1)[-1]) < 2:
            return False
        return True
    except Exception:
        return False


def _prioritize(candidates: list) -> list:
    """Put high-value API/search endpoints first so the cap keeps the best seeds."""
    high, normal = [], []
    for url in candidates:
        if any(kw in url.lower() for kw in HIGH_VALUE_KEYWORDS):
            high.append(url)
        else:
            normal.append(url)
    return high + normal


def _run_xnlinkfinder(url: str, timeout: int, ua: str) -> list:
    """Run xnLinkFinder against a single URL; return list of http(s) URLs."""
    try:
        result = subprocess.run(
            [
                "xnLinkFinder",
                "-i",  url,
                "-sp", url,
                "-siv",
                "-o",  "-",
                "--timeout", str(timeout),
            ],
            capture_output=True,
            text=True,
            timeout=timeout * 3,
        )
        return [
            u.strip()
            for u in result.stdout.splitlines()
            if u.strip().startswith("http")
        ]
    except Exception:
        return []


def run(ctx: Context, phase_num: int = 7, total: int = 10) -> Context:
    if not shutil.which("xnLinkFinder"):
        ctx.log("[crawl] xnLinkFinder not found — skipping crawl phase")
        ctx.phases_run.append("crawl")
        ctx.log_phase_done(phase_num, total, "crawl", "skipped (xnLinkFinder not installed)")
        return ctx

    parsed = urlparse(ctx.target_url) if ctx.target_url else None
    domain = (parsed.netloc if parsed and parsed.netloc else ctx.target).lstrip("www.")

    # Build seed list: deduplicated, in-scope, high-value first
    candidates = _dedup([
        u for u in (ctx.url_pool + ctx.js_endpoints)
        if _is_valid_endpoint(u) and should_keep(u, domain)
    ])
    candidates = _prioritize(candidates)
    seed_urls  = candidates[:MAX_SEEDS]

    ctx.log(f"[crawl] xnLinkFinder crawling {len(seed_urls)} seed URLs "
            f"({MAX_WORKERS} workers)...")

    found    = []
    pool_set = set(ctx.url_pool)
    workers  = min(MAX_WORKERS, len(seed_urls))

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(_run_xnlinkfinder, url, ctx.timeout, ctx.user_agent): url
            for url in seed_urls
        }
        done = 0
        for fut in as_completed(futures):
            url = futures[fut]
            try:
                batch = fut.result()
                found.extend(batch)
                done += 1
                if batch and not ctx.silent:
                    ctx.log(f"[crawl]   [{done}/{len(seed_urls)}] +{len(batch)} → {url}")
            except Exception as e:
                ctx.log(f"[crawl]   error on {url}: {e}")

    # Filter to new, valid, in-scope URLs only
    new_urls = [
        u for u in _dedup(found)
        if _is_valid_endpoint(u) and should_keep(u, domain) and u not in pool_set
    ]

    ctx.log(f"[crawl] {len(found)} raw → {len(new_urls)} new in-scope URLs")
    ctx.url_pool = _dedup(ctx.url_pool + new_urls)
    ctx.write_text("crawl_urls.txt", "\n".join(new_urls))

    ctx.phases_run.append("crawl")
    ctx.log_phase_done(
        phase_num, total, "crawl",
        f"{len(seed_urls)} seeds | {len(new_urls)} new URLs → pool now {len(ctx.url_pool)}"
    )
    return ctx
