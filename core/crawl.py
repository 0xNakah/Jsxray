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
from urllib.parse import urlparse
from core.context import Context
from core.urls import should_keep, _dedup


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
            timeout=timeout * 4,
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

    # Seed: deduplicated in-scope URLs from the full pool
    seed_urls = _dedup([
        u for u in (ctx.url_pool + ctx.js_endpoints)
        if _is_valid_endpoint(u) and should_keep(u, domain)
    ])

    # Cap seeds to avoid extremely long crawl times
    MAX_SEEDS = 80
    if len(seed_urls) > MAX_SEEDS:
        seed_urls = seed_urls[:MAX_SEEDS]

    ctx.log(f"[crawl] xnLinkFinder crawling {len(seed_urls)} seed URLs...")

    found = []
    for url in seed_urls:
        batch = _run_xnlinkfinder(url, ctx.timeout, ctx.user_agent)
        found.extend(batch)

    # Validate + filter to in-scope only
    new_urls = [
        u for u in _dedup(found)
        if _is_valid_endpoint(u) and should_keep(u, domain)
        and u not in set(ctx.url_pool)
    ]

    ctx.log(f"[crawl] xnLinkFinder found {len(found)} raw URLs → {len(new_urls)} new in-scope")
    ctx.url_pool = _dedup(ctx.url_pool + new_urls)
    ctx.write_text("crawl_urls.txt", "\n".join(new_urls))

    ctx.phases_run.append("crawl")
    ctx.log_phase_done(
        phase_num, total, "crawl",
        f"{len(seed_urls)} seeds | {len(new_urls)} new URLs → pool now {len(ctx.url_pool)}"
    )
    return ctx
