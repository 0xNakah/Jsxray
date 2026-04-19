import subprocess, os, json, requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.context import Context
from core.config import check_tool

HIGH_VALUE_KEYWORDS = [
    "/api/", "/graphql", "/search", "/ajax", "/rest/",
    "/v1/", "/v2/", "/v3/", "/user", "/account", "/admin",
    "/query", "/data", "/fetch", "/get", "/post",
]


def _resolve_wordlist(ctx) -> str | None:
    """
    Resolve the wordlist path in priority order:
      1. ctx.config['defaults']['wordlist']  (jsxray.toml)
      2. <workspace>/js_params_wordlist.txt  (legacy fallback)
    Returns the path if the file exists and is non-empty, else None.
    """
    candidates = [
        ctx.config.get("defaults", {}).get("wordlist", ""),
        os.path.join(ctx.workspace, "js_params_wordlist.txt"),
    ]
    for path in candidates:
        if path and os.path.isfile(path) and os.path.getsize(path) >= 5:
            return path
    return None


def parse_source_map(map_url, timeout, ua):
    try:
        r = requests.get(map_url, timeout=timeout, headers={"User-Agent": ua})
        sources = r.json().get("sources", [])
        return [s for s in sources if any(k in s for k in
                ['route', 'page', 'api', 'view', 'controller', 'endpoint'])]
    except Exception:
        return []


def run_x8(url, wordlist, out_file, config, ua):
    tool = config.get("tools", {}).get("x8", "x8")
    for method in ["GET", "POST"]:
        try:
            subprocess.run(
                [tool, "-u", url, "-w", wordlist, "-o", out_file, "-O", "json",
                 "-m", method, "--header", f"User-Agent: {ua}",
                 "-q", "--stable", "--disable-progress-bar"],
                capture_output=True, timeout=90,
            )
            if os.path.exists(out_file) and os.path.getsize(out_file) > 2:
                with open(out_file) as f:
                    data = json.load(f)
                if data:
                    return data
        except Exception:
            pass
    return {}


def run_arjun(url, wordlist, out_file, config, ua):
    tool = config.get("tools", {}).get("arjun", "arjun")
    try:
        subprocess.run(
            [tool, "-u", url, "-w", wordlist, "--stable", "-oJ", out_file, "-q",
             "--headers", f"User-Agent: {ua}"],
            capture_output=True, timeout=90,
        )
        if os.path.exists(out_file):
            with open(out_file) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _probe_url(url, wordlist, config, ua, workspace, use_x8, use_arjun):
    """Run x8 and/or arjun on a single URL, merge results, clean up temp files."""
    key      = abs(hash(url)) % 9999999
    combined = {}
    tmp_files = []

    futures_map = {}
    with ThreadPoolExecutor(max_workers=2) as ex:
        if use_x8:
            out = os.path.join(workspace, f"x8_{key}.json")
            tmp_files.append(out)
            futures_map[ex.submit(run_x8, url, wordlist, out, config, ua)] = "x8"
        if use_arjun:
            out = os.path.join(workspace, f"arjun_{key}.json")
            tmp_files.append(out)
            futures_map[ex.submit(run_arjun, url, wordlist, out, config, ua)] = "arjun"

        for fut in as_completed(futures_map):
            try:
                data = fut.result() or {}
                for ep, params in data.items():
                    if params:
                        combined.setdefault(ep, set()).update(params)
            except Exception:
                pass

    # Clean up temp JSON files after reading
    for tmp in tmp_files:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

    return {ep: list(p) for ep, p in combined.items()}


def _prioritize(candidates):
    """Put high-value API/search endpoints first."""
    high, normal = [], []
    for url in candidates:
        if any(kw in url.lower() for kw in HIGH_VALUE_KEYWORDS):
            high.append(url)
        else:
            normal.append(url)
    return high + normal


def run(ctx: Context, phase_num=6, total=9) -> Context:
    ctx.log("[deep] Starting deep phase...")

    if ctx.source_maps:
        ctx.log(f"[deep] Parsing {len(ctx.source_maps)} source maps...")
        for js_url, map_url in ctx.source_maps.items():
            try:
                eps = parse_source_map(map_url, ctx.timeout, ctx.user_agent)
                ctx.js_endpoints.extend(eps)
                if eps:
                    ctx.log(f"[deep]   Source map \u2192 {len(eps)} new endpoints")
            except Exception as e:
                ctx.log(f"[deep]   Source map error ({map_url}): {e}")

    wordlist = _resolve_wordlist(ctx)
    if not wordlist:
        ctx.phases_run.append("deep")
        ctx.log_phase_done(phase_num, total, "deep",
                           "source maps parsed, no wordlist for param discovery "
                           "(set defaults.wordlist in jsxray.toml)")
        return ctx

    ctx.log(f"[deep] Wordlist: {wordlist}")

    use_x8    = check_tool("x8",    ctx.config)
    use_arjun = check_tool("arjun", ctx.config)

    if not use_x8 and not use_arjun:
        ctx.log("[deep] Neither x8 nor arjun found \u2014 skipping param discovery")
        ctx.phases_run.append("deep")
        ctx.log_phase_done(phase_num, total, "deep",
                           "source maps parsed (install x8 or arjun for hidden param discovery)")
        return ctx

    tools_active = ", ".join(t for t, ok in [("x8", use_x8), ("arjun", use_arjun)] if ok)
    ctx.log(f"[deep] Using [{tools_active}] in parallel for hidden param discovery...")

    # Build candidate list — no-query endpoints, in-scope, prioritised
    seen, candidates = set(), []
    for url in ctx.url_pool + ctx.js_endpoints:
        if "?" not in url and url.startswith("http") and url not in seen:
            seen.add(url)
            candidates.append(url)

    candidates = _prioritize(candidates)[:200]
    ctx.log(f"[deep] Probing {len(candidates)} endpoints...")

    hidden = {}
    workers = min(10, len(candidates))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(_probe_url, url, wordlist, ctx.config,
                      ctx.user_agent, ctx.workspace, use_x8, use_arjun): url
            for url in candidates
        }
        for fut in as_completed(futures):
            url = futures[fut]
            try:
                data = fut.result()
                for ep, params in data.items():
                    if params:
                        hidden[ep] = params
                        ctx.log(f"[deep]   \u2605 {len(params)} params on {ep}")
            except Exception as e:
                ctx.log(f"[deep]   error on {url}: {e}")

    ctx.hidden_params = hidden
    ctx.write_json("hidden_params.json", hidden)
    total_hidden = sum(len(p) for p in hidden.values())
    ctx.phases_run.append("deep")
    ctx.log_phase_done(phase_num, total, "deep",
                       f"{total_hidden} hidden params via [{tools_active}] "
                       f"across {len(hidden)} endpoints")
    return ctx
