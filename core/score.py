from core.context import Context

HIGH_VALUE = {
    'q','query','search','keyword','text','input','msg','message','content',
    'comment','description','title','subject','body','note','redirect',
    'redirect_uri','redirect_url','return','returnUrl','next','continue',
    'callback','url','goto','dest','destination','target','ref','referer',
    'referrer','back','forward','location','template','view','page','layout',
    'format','theme','style','debug','test','preview','mode','dev',
}

def score_finding(f):
    if not f.get("reflects"):
        return 0
    s = 40
    s += {"js_exec":30,"js_string":25,"html_body":20,"html_attr":15,"json":5,"unknown":10}.get(f.get("context",""),0)
    if f.get("csp_missing"):       s += 25
    if f.get("csp_unsafe_inline"): s += 15
    if f.get("csp_unsafe_eval"):   s += 10
    if f.get("csp_wildcard"):      s +=  8
    s += {"robots":15,"robots+js":18,"js_map":10,"x8":12,"arjun":8,"url_pool":0}.get(f.get("source",""),0)
    if f.get("param","").lower() in HIGH_VALUE: s += 20
    return min(s, 100)

def priority_label(score):
    if score >= 80: return "critical"
    if score >= 60: return "high"
    if score >= 40: return "medium"
    return "low"

def run(ctx: Context, phase_num=8, total=9) -> Context:
    ctx.log(f"[score] Scoring {len(ctx.reflections)} probe results...")
    findings = []
    for r in ctx.reflections:
        if not r.get("reflects"):
            continue
        s = score_finding(r)
        findings.append({**r, "score": s, "priority": priority_label(s)})
    findings.sort(key=lambda x: x["score"], reverse=True)
    ctx.findings = findings

    c = len([f for f in findings if f["priority"]=="critical"])
    h = len([f for f in findings if f["priority"]=="high"])
    m = len([f for f in findings if f["priority"]=="medium"])
    l = len([f for f in findings if f["priority"]=="low"])

    ctx.phases_run.append("score")
    ctx.log_phase_done(phase_num, total, "score",
        f"{c} critical, {h} high, {m} medium, {l} low")
    return ctx
