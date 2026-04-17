from core.context import Context

EMOJI = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵"}

def burp_queue(findings):
    lines = ["# JSXray — Burp Queue (sorted by score)",
             "# Paste into Burp Repeater / Intruder\n"]
    for f in findings:
        csp_n = "no-csp" if f.get("csp_missing") else ("unsafe-inline" if f.get("csp_unsafe_inline") else "has-csp")
        pay   = " | ".join(f.get("payloads",[])[:2])
        lines.append(
            f"[{f['priority'].upper()}] {f['probe_url']}\n"
            f"  param={f['param']}  context={f.get('context','?')}  csp={csp_n}  score={f['score']}\n"
            f"  payloads: {pay}\n"
            f"  source: {f.get('source','?')}\n"
        )
    return "\n".join(lines)

def run(ctx: Context, phase_num=9, total=9) -> Context:
    summary = ctx.to_summary()
    ctx.write_json("summary.json", summary)
    ctx.write_json("reflections.json", ctx.findings)
    ctx.write_text("burp_queue.txt", burp_queue(ctx.findings))

    s = summary["stats"]
    print(f"\n{'='*60}")
    print(f"  JSXray — Scan Complete")
    print(f"{'='*60}")
    print(f"  Target   : {ctx.target}")
    print(f"  Mode     : {ctx.mode}")
    print(f"  Workspace: {ctx.workspace}")
    print(f"{'─'*60}")
    print(f"  robots.txt : {s['robots_paths']} paths  ({s['robots_live']} live, {s['robots_403']} 403, {s['robots_redirect']} redirect)")
    print(f"  URL pool   : {s['url_pool']} URLs")
    print(f"  JS files   : {s['js_files']} files  ({s['source_maps']} source maps)")
    print(f"  Endpoints  : {s['js_endpoints']} extracted")
    print(f"  Params     : {s['js_global_params']} extracted  (+{s['hidden_params']} hidden)")
    print(f"  Reflections: {s['reflections']} probed")
    print(f"{'─'*60}")
    print(f"  🔴 Critical : {s['critical']}")
    print(f"  🟠 High     : {s['high']}")
    print(f"  🟡 Medium   : {s['medium']}")
    print(f"  🔵 Low      : {s['low']}")
    if ctx.findings:
        print(f"{'─'*60}")
        print(f"  Top findings:")
        for f in ctx.findings[:5]:
            e = EMOJI.get(f['priority'],'⚪')
            print(f"  {e} [{f['score']:>3}] {f['param']:<20} {f['url'][:48]}")
    print(f"{'='*60}")
    print(f"\n[jsxray] Results → {ctx.workspace}/")

    ctx.phases_run.append("output")
    return ctx
