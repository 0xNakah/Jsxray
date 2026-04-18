import shutil
from core.context import Context

def _trunc(s, width):
    s = str(s)
    return s if len(s) <= width else s[:width - 1] + "…"

def secrets_report(secrets):
    lines = ["# JSXray — Secret Hints", "# Review each match manually before reporting\n"]
    for s in secrets:
        lines.append(
            f"[{s['type'].upper()}]\n"
            f"  file  : {s['url']}\n"
            f"  match : {s['match']}\n"
        )
    return "\n".join(lines)

def nuclei_targets(js_endpoints, js_param_map):
    lines = ["# JSXray — Nuclei / ffuf targets", "# Format: URL  (params as comment)\n"]
    for ep in js_endpoints:
        params = js_param_map.get(ep, [])
        comment = f"  # params: {', '.join(params[:10])}" if params else ""
        lines.append(f"{ep}{comment}")
    return "\n".join(lines)

def run(ctx: Context, phase_num=9, total=9) -> Context:
    summary = ctx.to_summary()
    ctx.write_json("summary.json", summary)

    secrets = []
    for fd in ctx.js_file_data:
        secrets.extend(fd.get("secrets", []))

    if secrets:
        ctx.write_text("secrets_report.txt", secrets_report(secrets))
        ctx.write_json("secrets.json", secrets)

    if ctx.js_endpoints:
        ctx.write_text("nuclei_targets.txt", nuclei_targets(ctx.js_endpoints, ctx.js_param_map))

    term_w = shutil.get_terminal_size((120, 24)).columns
    url_w  = max(40, term_w - 60)

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
    if secrets:
        print(f"  Secrets    : {len(secrets)} hints  → secrets_report.txt")
    if ctx.failed_phases:
        print(f"  ⚠  Failed  : {', '.join(ctx.failed_phases)}")
    print(f"{'─'*60}")
    if ctx.js_global_params:
        from core.js_extract import HIGH_VALUE_PARAMS
        hv = [p for p in ctx.js_global_params if p in HIGH_VALUE_PARAMS]
        if hv:
            print(f"  High-value params: {', '.join(hv[:15])}")
    if ctx.js_endpoints:
        print(f"  Top endpoints:")
        for ep in ctx.js_endpoints[:5]:
            print(f"    {_trunc(ep, url_w)}")
    print(f"{'='*60}")
    print(f"\n[jsxray] Results → {ctx.workspace}/")

    ctx.phases_run.append("output")
    return ctx
