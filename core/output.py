import shutil
from core.context import Context

def _trunc(s, width):
    s = str(s)
    return s if len(s) <= width else s[:width - 1] + "\u2026"

def _dedup_secrets(secrets: list) -> list:
    """
    Deduplicate secrets by (type, match) — the actual credential value.
    When the same secret appears in multiple JS files, keep the first
    occurrence (which carries the most relevant url) and discard repeats.
    """
    seen = set()
    out  = []
    for s in secrets:
        key = (s.get("type", ""), s.get("match", ""))
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out

def secrets_report(secrets):
    lines = ["# JSXray \u2014 Secret Hints", "# Review each match manually before reporting\n"]
    for s in secrets:
        lines.append(
            f"[{s['type'].upper()}]\n"
            f"  file  : {s['url']}\n"
            f"  match : {s['match']}\n"
        )
    return "\n".join(lines)

def nuclei_targets(js_endpoints, js_param_map):
    lines = ["# JSXray \u2014 Nuclei / ffuf targets", "# Format: URL  (params as comment)\n"]
    for ep in js_endpoints:
        params = js_param_map.get(ep, [])
        comment = f"  # params: {', '.join(params[:10])}" if params else ""
        lines.append(f"{ep}{comment}")
    return "\n".join(lines)

def run(ctx: Context, phase_num=9, total=9) -> Context:
    summary = ctx.to_summary()
    ctx.write_json("summary.json", summary)

    raw_secrets = []
    for fd in ctx.js_file_data:
        raw_secrets.extend(fd.get("secrets", []))

    secrets = _dedup_secrets(raw_secrets)
    dupes   = len(raw_secrets) - len(secrets)

    if secrets:
        ctx.write_text("secrets_report.txt", secrets_report(secrets))
        ctx.write_json("secrets.json", secrets)
        if dupes:
            ctx.log(f"[output] secrets: {len(raw_secrets)} raw \u2192 {len(secrets)} unique ({dupes} duplicates removed)")

    if ctx.js_endpoints:
        ctx.write_text("nuclei_targets.txt", nuclei_targets(ctx.js_endpoints, ctx.js_param_map))

    term_w = shutil.get_terminal_size((120, 24)).columns
    url_w  = max(40, term_w - 60)

    s = summary["stats"]
    print(f"\n{'='*60}")
    print(f"  JSXray \u2014 Scan Complete")
    print(f"{'='*60}")
    print(f"  Target   : {ctx.target}")
    print(f"  Mode     : {ctx.mode}")
    print(f"  Workspace: {ctx.workspace}")
    print(f"{'\u2500'*60}")
    print(f"  robots.txt : {s['robots_paths']} paths  ({s['robots_live']} live, {s['robots_403']} 403, {s['robots_redirect']} redirect)")
    print(f"  URL pool   : {s['url_pool']} URLs")
    print(f"  JS files   : {s['js_files']} files  ({s['source_maps']} source maps)")
    print(f"  Endpoints  : {s['js_endpoints']} extracted")
    print(f"  Params     : {s['js_global_params']} extracted  (+{s['hidden_params']} hidden)")
    if secrets:
        dupe_note = f"  ({dupes} dupes removed)" if dupes else ""
        print(f"  Secrets    : {len(secrets)} unique hints{dupe_note}  \u2192 secrets_report.txt")
    if ctx.failed_phases:
        print(f"  \u26a0  Failed  : {', '.join(ctx.failed_phases)}")
    print(f"{'\u2500'*60}")
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
    print(f"\n[jsxray] Results \u2192 {ctx.workspace}/")

    ctx.phases_run.append("output")
    return ctx
