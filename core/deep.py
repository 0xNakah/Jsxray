import requests
from core.context import Context


def parse_source_map(map_url, timeout, ua):
    try:
        r = requests.get(map_url, timeout=timeout, headers={"User-Agent": ua})
        sources = r.json().get("sources", [])
        return [s for s in sources if any(k in s for k in
                ['route', 'page', 'api', 'view', 'controller', 'endpoint'])]
    except Exception:
        return []


def run(ctx: Context, phase_num=6, total=9) -> Context:
    ctx.log("[deep] Starting deep phase (source maps only)...")

    if ctx.source_maps:
        ctx.log(f"[deep] Parsing {len(ctx.source_maps)} source maps...")
        new_eps = 0
        for js_url, map_url in ctx.source_maps.items():
            try:
                eps = parse_source_map(map_url, ctx.timeout, ctx.user_agent)
                ctx.js_endpoints.extend(eps)
                new_eps += len(eps)
                if eps:
                    ctx.log(f"[deep]   {map_url} → {len(eps)} endpoints")
            except Exception as e:
                ctx.log(f"[deep]   source map error ({map_url}): {e}")
        ctx.log(f"[deep] Source maps done — {new_eps} new endpoints added")
    else:
        ctx.log("[deep] No source maps found — nothing to parse")

    ctx.phases_run.append("deep")
    ctx.log_phase_done(
        phase_num, total, "deep",
        f"{len(ctx.source_maps or {})} source maps parsed"
        + (f", {sum(1 for _ in ctx.js_endpoints)} total endpoints" if ctx.js_endpoints else "")
    )
    return ctx
