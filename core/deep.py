import subprocess, os, json, requests
from core.context import Context
from core.config import check_tool

def parse_source_map(map_url, timeout, ua):
    try:
        r = requests.get(map_url, timeout=timeout, headers={"User-Agent": ua})
        sources = r.json().get("sources",[])
        return [s for s in sources if any(k in s for k in ['route','page','api','view','controller','endpoint'])]
    except:
        return []

def run_x8(url, wordlist, out_file, config, ua):
    tool = config.get("tools",{}).get("x8","x8")
    for method in ["GET","POST"]:
        try:
            subprocess.run([tool,"-u",url,"-w",wordlist,"-o",out_file,"-O","json",
                            "-m",method,"--header",f"User-Agent: {ua}",
                            "-q","--stable","--disable-progress-bar"],
                           capture_output=True, timeout=60)
            if os.path.exists(out_file) and os.path.getsize(out_file) > 2:
                data = json.load(open(out_file))
                if data: return data
        except:
            pass
    return {}

def run_arjun(url, wordlist, out_file, config, ua):
    tool = config.get("tools",{}).get("arjun","arjun")
    try:
        subprocess.run([tool,"-u",url,"-w",wordlist,"--stable","-oJ",out_file,"-q",
                        "--headers",f"User-Agent: {ua}"],
                       capture_output=True, timeout=60)
        if os.path.exists(out_file):
            return json.load(open(out_file))
    except:
        pass
    return {}

def run(ctx: Context, phase_num=6, total=9) -> Context:
    ctx.log(f"[deep] Starting deep phase...")

    if ctx.source_maps:
        ctx.log(f"[deep] Parsing {len(ctx.source_maps)} source maps...")
        for js_url, map_url in ctx.source_maps.items():
            eps = parse_source_map(map_url, ctx.timeout, ctx.user_agent)
            ctx.js_endpoints.extend(eps)
            if eps:
                ctx.log(f"[deep]   Source map → {len(eps)} new endpoints")

    wordlist = os.path.join(ctx.workspace, "js_params_wordlist.txt")
    if not os.path.exists(wordlist) or os.path.getsize(wordlist) < 5:
        ctx.phases_run.append("deep")
        ctx.log_phase_done(phase_num, total, "deep", "source maps parsed, no wordlist for param discovery")
        return ctx

    use_x8    = check_tool("x8", ctx.config)
    use_arjun = check_tool("arjun", ctx.config)
    tool_name = "x8" if use_x8 else ("arjun" if use_arjun else None)

    if not tool_name:
        ctx.log(f"[deep] Neither x8 nor arjun found — skipping param discovery")
        ctx.phases_run.append("deep")
        ctx.log_phase_done(phase_num, total, "deep",
            "source maps parsed (install x8 or arjun for hidden param discovery)")
        return ctx

    ctx.log(f"[deep] Using {tool_name} for hidden param discovery...")
    candidates, seen = [], set()
    for url in ctx.url_pool + ctx.js_endpoints:
        if "?" not in url and url.startswith("http") and url not in seen:
            seen.add(url); candidates.append(url)

    targets = candidates[:30]
    ctx.log(f"[deep] Probing {len(targets)} endpoints with {tool_name}...")
    hidden = {}
    for url in targets:
        key      = abs(hash(url)) % 999999
        out_file = os.path.join(ctx.workspace, f"{tool_name}_{key}.json")
        data     = run_x8(url, wordlist, out_file, ctx.config, ctx.user_agent) if use_x8 \
                   else run_arjun(url, wordlist, out_file, ctx.config, ctx.user_agent)
        if data:
            for ep, params in data.items():
                if params:
                    hidden[ep] = list(params)
                    ctx.log(f"[deep]   ★ {len(params)} params on {ep}")

    ctx.hidden_params = hidden
    ctx.write_json("hidden_params.json", hidden)
    total_hidden = sum(len(p) for p in hidden.values())
    ctx.phases_run.append("deep")
    ctx.log_phase_done(phase_num, total, "deep",
        f"{total_hidden} hidden params discovered via {tool_name}")
    return ctx
