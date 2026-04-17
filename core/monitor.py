import os, json, glob, requests
from core.context import Context

def get_previous_run(ctx):
    base = ctx.config.get("defaults",{}).get("output_dir","recon")
    safe = ctx.target.replace("https://","").replace("http://","").replace("/","_")
    pattern = os.path.join(base, safe, "*", "summary.json")
    runs = sorted(glob.glob(pattern))
    current = os.path.join(ctx.workspace, "summary.json")
    runs = [r for r in runs if r != current]
    if not runs:
        return None
    prev_dir = os.path.dirname(runs[-1])
    out = {}
    for fname in ["reflections.json","js_params.json"]:
        fpath = os.path.join(prev_dir, fname)
        if os.path.exists(fpath):
            out[fname.replace(".json","")] = json.load(open(fpath))
    js_f = os.path.join(prev_dir, "js_files.txt")
    if os.path.exists(js_f):
        out["js_files"] = open(js_f).read().splitlines()
    return out

def send_alert(ctx, message):
    cfg = ctx.config.get("alerts",{})
    webhook = cfg.get("discord_webhook","")
    if webhook:
        try:
            requests.post(webhook, json={"content": message}, timeout=10)
            ctx.log("[monitor] Discord alert sent")
        except:
            pass
    token   = cfg.get("telegram_token","")
    chat_id = cfg.get("telegram_chat_id","")
    if token and chat_id:
        try:
            requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                          json={"chat_id": chat_id, "text": message}, timeout=10)
            ctx.log("[monitor] Telegram alert sent")
        except:
            pass

def run(ctx: Context, phase_num=10, total=10) -> Context:
    ctx.log(f"[monitor] Diffing against previous scan...")
    prev = get_previous_run(ctx)
    if not prev:
        ctx.log(f"[monitor] No previous run found")
        ctx.phases_run.append("monitor")
        ctx.log_phase_done(phase_num, total, "monitor", "first run — nothing to diff")
        return ctx

    diff = {"new_findings":[], "new_js_files":[], "new_params":[]}

    prev_probe_urls = {f.get("probe_url") for f in prev.get("reflections",[])}
    for f in ctx.findings:
        if f.get("probe_url") not in prev_probe_urls:
            diff["new_findings"].append(f)

    prev_js = set(prev.get("js_files",[]))
    diff["new_js_files"] = list(set(ctx.js_files) - prev_js)

    prev_params = set(prev.get("js_params",{}).get("global_params",[]))
    diff["new_params"] = list(set(ctx.js_global_params) - prev_params)

    ctx.diff = diff
    ctx.write_json("diff.json", diff)

    nf = len(diff["new_findings"])
    nj = len(diff["new_js_files"])
    np = len(diff["new_params"])

    if nf > 0 or nj > 0 or np > 0:
        msg = (f"**JSXray Alert — {ctx.target}**\n"
               f"🔴 New findings: {nf}\n📄 New JS files: {nj}\n🔑 New params: {np}")
        if diff["new_findings"]:
            top = diff["new_findings"][0]
            msg += f"\nTop: `{top.get('param')}` @ `{top.get('url','')[:80]}`"
        send_alert(ctx, msg)

    ctx.phases_run.append("monitor")
    ctx.log_phase_done(phase_num, total, "monitor",
        f"{nf} new findings | {nj} new JS files | {np} new params")
    return ctx
