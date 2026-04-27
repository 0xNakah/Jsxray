"""
js_extract.py — JS Orchestration Phase

Fetches JS files and source maps, then delegates:
  - Params      → ast_extract (Node.js AST, no regex)
  - Endpoints   → ENDPOINT_PATTERNS (regex)
  - Lazy chunks → LAZY_CHUNK_PATTERNS (regex)
  - Secrets     → SECRET_PATTERNS (regex)
"""

import re
import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.context import Context
from core.ast_extract import extract_params_detailed

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept":     "*/*",
}

HIGH_VALUE_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "redirecturl", "redirecturi",
    "return", "returnurl", "returnuri", "return_url", "return_uri",
    "next", "continue", "forward", "goto", "dest", "destination",
    "target", "ref", "referer", "referrer", "back", "location", "url", "uri",
    "q", "query", "search", "keyword", "keywords", "term", "terms", "text",
    "input", "msg", "message", "content", "comment", "description", "title",
    "subject", "body", "note", "name", "value", "data", "payload",
    "template", "view", "page", "layout", "format", "theme", "style",
    "lang", "language", "locale", "currency", "country", "region",
    "debug", "test", "preview", "mode", "dev", "verbose", "trace",
    "token", "state", "code", "nonce", "scope", "response_type",
    "file", "filename", "path", "dir", "folder", "upload", "attachment",
    "callback", "cb", "jsonp", "handler", "fn",
}


def _host_in_scope(host: str, domain: str) -> bool:
    host = (host or "").lower().lstrip("www.")
    base = (domain or "").lower().lstrip("www.")
    return bool(host) and bool(base) and (host == base or host.endswith("." + base))


ENDPOINT_PATTERNS = [
    re.compile(
        r"""(?:fetch|axios(?:\.\w+)?|http\.(?:get|post|put|delete|patch))\s*"""
        r"""\(\s*['"` ]([^'"` \s]{3,}(?:/[^'"` \s]*)?)['"` ]"""
    ),
    re.compile(r"""['"` ](/(?:api|v\d+|rest|graphql|ajax|service|data|endpoint|query)[^'"` \s]{0,100})['"` ]"""),
    re.compile(r"""['"` ](/[a-zA-Z0-9_\-./]{3,80}\?[a-zA-Z0-9_\-=&%+.]{2,100})['"` ]"""),
    re.compile(r"""['"` ](https?://[^'"` \s]{10,200})['"` ]"""),
    re.compile(r"""(?:path|route|url|href|src|action)\s*[:=]\s*['"` ](/[^'"` \s]{2,80})['"` ]"""),
]

LAZY_CHUNK_PATTERNS = [
    re.compile(r'''\bimport\s*\(\s*(?:/\*.*?\*/\s*)*[\'"]([^\'"]+\.js(?:\?[^\'"]*)?)[\'"]\s*\)''', re.IGNORECASE | re.DOTALL),
    re.compile(r'''\brequire\.ensure\s*\(.*?,\s*.*?,\s*[\'"]([^\'"]+)[\'"]\s*\)''', re.IGNORECASE | re.DOTALL),
    re.compile(r'''[\'"]([^\'"]*chunk[^\'"]*\.js(?:\?[^\'"]*)?)[\'"]''', re.IGNORECASE),
    re.compile(r'''[\'"]([^\'"]*\/(?:static|assets|chunks?|js)\/[^\'"]+\.js(?:\?[^\'"]*)?)[\'"]''', re.IGNORECASE),
]

SECRET_PATTERNS = {
    "aws_access_key":        re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
    "aws_secret_key":        re.compile(r'(?i)aws.{0,20}[\'\"]{1}[0-9a-zA-Z/+]{40}[\'\"]{1}'),
    "azure_storage_conn":    re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"),
    "azure_sas_token":       re.compile(r"(?i)sv=\d{4}-\d{2}-\d{2}&s[sco]=.{10,200}&sig=[A-Za-z0-9%+/=]{40,}"),
    "gcp_service_account":   re.compile(r'"type"\s*:\s*"service_account"'),
    "gcp_api_key":           re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "stripe_live_key":       re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "stripe_restricted_key": re.compile(r"rk_live_[0-9a-zA-Z]{24,}"),
    "paypal_braintree":      re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    "square_token":          re.compile(r"sq0atp-[0-9A-Za-z\-_]{22}"),
    "square_oauth_secret":   re.compile(r"sq0csp-[0-9A-Za-z\-_]{43}"),
    "jwt_token":             re.compile(r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*"),
    "github_pat":            re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    "github_oauth":          re.compile(r"gho_[0-9a-zA-Z]{36}"),
    "github_app_token":      re.compile(r"(?:ghu|ghs)_[0-9a-zA-Z]{36}"),
    "gitlab_pat":            re.compile(r"glpat-[0-9a-zA-Z\-_]{20}"),
    "npmrc_token":           re.compile(r"//registry\.npmjs\.org/:_authToken=[0-9a-zA-Z\-_]{36,}"),
    "openai_key":            re.compile(r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}"),
    "anthropic_key":         re.compile(r"sk-ant-api\d{2}-[A-Za-z0-9\-_]{93}AA"),
    "slack_token":           re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,250}"),
    "slack_webhook":         re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}"),
    "twilio_account_sid":    re.compile(r"AC[a-z0-9]{32}"),
    "twilio_auth_token":     re.compile(r'(?i)twilio.{0,20}[\'\"]{1}[a-f0-9]{32}[\'\"]{1}'),
    "sendgrid_key":          re.compile(r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}"),
    "mailchimp_key":         re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}"),
    "generic_db_conn":       re.compile(r'(?i)(?:mongodb|mysql|postgres|redis|mssql)://[^:]+:[^@]+@[^\s"\' ]+'),
    "private_key_pem":       re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "heroku_api_key":        re.compile(r'(?i)[hH]eroku.{0,20}[\'\"]{1}[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[\'\"]{1}'),
    "generic_secret":        re.compile(r'(?i)(?:secret|api_key|apikey|token|passwd|password|auth)[\'\"]{0,1}\s*[:=]\s*[\'\"]{1}([A-Za-z0-9\-_/+]{20,})[\'\"]{1}'),
}


def fetch_js(url, timeout, ua):
    try:
        r = requests.get(
            url,
            timeout=timeout,
            headers={**HEADERS, "User-Agent": ua},
            allow_redirects=True,
        )
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return ""


_SOURCE_PATH_NOISE = re.compile(
    r"(?:node_modules|webpack/runtime|__webpack|\.(?:test|spec|stories|d\.ts))",
    re.IGNORECASE,
)


def _sources_to_hint_text(sources: list) -> str:
    lines = []
    for src in sources:
        if not src or not isinstance(src, str):
            continue
        if _SOURCE_PATH_NOISE.search(src):
            continue
        clean = re.sub(r'^webpack:/+[^/]*', '', src)
        clean = re.sub(r'[?#].*$', '', clean)
        clean = re.sub(r'\.(?:js|ts|jsx|tsx|vue|svelte)$', '', clean, flags=re.IGNORECASE)
        if '/' not in clean:
            continue
        clean = re.sub(r'^(?:\.\./)+', '/', clean)
        clean = re.sub(r'^\.',  '/', clean)
        if not clean.startswith('/'):
            clean = '/' + clean
        lines.append(f'path: "{clean}"')
    return '\n'.join(lines)


def fetch_source_map(map_url, timeout, ua):
    try:
        r = requests.get(
            map_url,
            timeout=timeout,
            headers={**HEADERS, "User-Agent": ua},
            allow_redirects=True,
        )
        if r.status_code != 200:
            return ""
        data = r.json()
        sources_content = data.get("sourcesContent", [])
        combined = "\n\n".join(s for s in sources_content if s and isinstance(s, str))
        if combined:
            return combined
        sources = data.get("sources", [])
        hint_text = _sources_to_hint_text(sources)
        if hint_text:
            return hint_text
        return r.text
    except Exception:
        pass
    return ""


def _is_valid_endpoint(url: str) -> bool:
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        netloc = p.netloc.split(":")[0]
        if not netloc or "." not in netloc:
            return False
        if len(netloc.rsplit(".", 1)[-1]) < 2:
            return False
        return True
    except Exception:
        return False


def _is_in_scope_endpoint(url: str, domain: str) -> bool:
    try:
        return _host_in_scope(urlparse(url).netloc, domain)
    except Exception:
        return False


def _looks_like_chunk_path(path: str) -> bool:
    if not path or "${" in path:
        return False
    lp = path.lower()
    return lp.endswith(".js") and (
        "chunk" in lp or "/static/" in lp or "/assets/" in lp or "/js/" in lp
        or "/chunks/" in lp or lp.startswith(("./", "../", "/", "static/",
        "assets/", "js/", "chunks/", "_next/", "public/", "dist/", "build/", "bundle/"))
    )


def _resolve_chunk_ref(ref: str, current_js_url: str) -> str:
    ASSET_PREFIXES = (
        "static/", "assets/", "js/", "chunks/", "_next/", "public/",
        "dist/", "build/", "bundle/",
    )
    if any(ref.startswith(p) for p in ASSET_PREFIXES):
        parsed = urlparse(current_js_url)
        return f"{parsed.scheme}://{parsed.netloc}/{ref}"
    return urljoin(current_js_url, ref)


def extract_endpoints(text, base_url, domain):
    endpoints = set()
    for pattern in ENDPOINT_PATTERNS:
        for m in pattern.finditer(text):
            raw = m.group(1).strip()
            if "${" in raw:
                continue
            url = raw if raw.startswith("http") else urljoin(base_url, raw)
            if _is_valid_endpoint(url) and _is_in_scope_endpoint(url, domain):
                endpoints.add(url)
    return list(endpoints)


def extract_lazy_chunks(text, current_js_url, domain):
    chunks = set()
    for pattern in LAZY_CHUNK_PATTERNS:
        for m in pattern.finditer(text):
            ref = m.group(1).strip()
            if not _looks_like_chunk_path(ref):
                continue
            resolved = _resolve_chunk_ref(ref, current_js_url)
            if _is_valid_endpoint(resolved) and _is_in_scope_endpoint(resolved, domain):
                chunks.add(resolved)
    return sorted(chunks)


def extract_secrets(text, js_url):
    secrets = []
    for name, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(text):
            match_str = m.group(0)
            if re.match(r"^[xX\*<>{}|]+$", match_str):
                continue
            secrets.append({"url": js_url, "type": name, "match": match_str[:120]})
    return secrets


def process_js_file(js_url, map_url, base_url, domain, timeout, ua):
    result = {
        "url":         js_url,
        "map_url":     map_url,
        "endpoints":   [],
        "params":      [],
        "secrets":     [],
        "lazy_chunks": [],
        "source":      "js",
    }

    if map_url:
        text = fetch_source_map(map_url, timeout, ua)
        result["source"] = "sourcemap"
        if not text:
            text = fetch_js(js_url, timeout, ua)
            result["source"] = "js_fallback"
    else:
        text = fetch_js(js_url, timeout, ua)

    if not text:
        return result

    detailed = extract_params_detailed(text)
    result["params"]      = sorted({p["value"] for p in detailed})
    result["endpoints"]   = extract_endpoints(text, base_url, domain)
    result["secrets"]     = extract_secrets(text, js_url)
    result["lazy_chunks"] = extract_lazy_chunks(text, js_url, domain)
    return result


def run(ctx: Context, phase_num=5, total=9):
    base_url = getattr(ctx, "canonical_url", None) or ctx.target_url
    domain   = urlparse(base_url).netloc.lstrip("www.")

    if not ctx.js_files:
        ctx.log("[js_extract] No JS files to process — skipping")
        ctx.phases_run.append("js_extract")
        ctx.log_phase_done(phase_num, total, "js_extract", "0 JS files")
        return ctx

    ctx.log(f"[js_extract] Processing {len(ctx.js_files)} JS files ({len(ctx.source_maps)} with source maps)...")

    all_results       = []
    global_params     = set()
    global_ep         = set()
    param_map         = {}  # endpoint -> set of param names
    all_secrets       = []
    seen_js           = set(ctx.js_files)
    lazy_chunks_total = set()

    def _process_batch(js_urls):
        results = []
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {
                ex.submit(
                    process_js_file, js_url, ctx.source_maps.get(js_url),
                    base_url, domain, ctx.timeout, ctx.user_agent,
                ): js_url
                for js_url in js_urls
            }
            for fut in as_completed(futures):
                results.append(fut.result())
        return results

    def _merge(r):
        global_params.update(r["params"])
        global_ep.update(r["endpoints"])
        all_secrets.extend(r["secrets"])
        lazy_chunks_total.update(r["lazy_chunks"])
        for ep in r["endpoints"]:
            param_map.setdefault(ep, set()).update(r["params"])

    first_pass = _process_batch(ctx.js_files)
    for r in first_pass:
        all_results.append(r)
        _merge(r)
        if not ctx.silent and (r["params"] or r["endpoints"] or r["lazy_chunks"]):
            sec_lbl   = f"  ★ {len(r['secrets'])} secrets"       if r["secrets"]     else ""
            chunk_lbl = f"  +{len(r['lazy_chunks'])} lazy chunks" if r["lazy_chunks"] else ""
            ctx.log(
                f"[js_extract]   {r['source']:12}  "
                f"{len(r['params']):3} params  "
                f"{len(r['endpoints']):3} endpoints{sec_lbl}{chunk_lbl}  {r['url']}"
            )

    # Second pass — lazy-loaded chunks (1 level deep, skip already-seen)
    new_chunks = [u for u in sorted(lazy_chunks_total) if u not in seen_js]
    if new_chunks:
        ctx.log(f"[js_extract] Processing {len(new_chunks)} lazy-loaded chunks (1-level deep)...")
        seen_js.update(new_chunks)
        for r in _process_batch(new_chunks):
            all_results.append(r)
            _merge(r)
            if not ctx.silent and (r["params"] or r["endpoints"]):
                sec_lbl = f"  ★ {len(r['secrets'])} secrets" if r["secrets"] else ""
                ctx.log(
                    f"[js_extract]   {r['source']:12}  "
                    f"{len(r['params']):3} params  "
                    f"{len(r['endpoints']):3} endpoints{sec_lbl}  {r['url']}"
                )

    # Merge any inline script data collected by js_discovery
    global_ep.update(getattr(ctx, "inline_script_endpoints", []))
    global_params.update(getattr(ctx, "inline_script_params", []))

    ctx.js_files         = sorted(seen_js)
    ctx.js_global_params = sorted(global_params)
    ctx.js_endpoints     = sorted(global_ep)
    ctx.js_param_map     = {ep: sorted(p) for ep, p in param_map.items()}
    ctx.js_file_data     = all_results

    high_value = [p for p in ctx.js_global_params if p in HIGH_VALUE_PARAMS]

    ctx.write_json("js_endpoints.json", ctx.js_endpoints)
    ctx.write_json("js_params.json", {
        "total_params": len(ctx.js_global_params),
        "high_value":   high_value,
        "all_params":   ctx.js_global_params,
        "by_endpoint":  ctx.js_param_map,
    })
    ctx.write_text("js_params_flat.txt",    "\n".join(ctx.js_global_params))
    ctx.write_text("js_endpoints_flat.txt", "\n".join(ctx.js_endpoints))
    ctx.write_text("js_files.txt",          "\n".join(ctx.js_files))

    if lazy_chunks_total:
        ctx.write_json("lazy_chunks.json", sorted(lazy_chunks_total))

    if all_secrets:
        ctx.write_json("js_secrets_hints.json", all_secrets)
        ctx.log(f"[js_extract]   {len(all_secrets)} potential secrets → js_secrets_hints.json")

    if high_value and not ctx.silent:
        ctx.log(f"[js_extract]   High-value params: {', '.join(high_value[:20])}")

    ctx.phases_run.append("js_extract")
    ctx.log_phase_done(
        phase_num, total, "js_extract",
        f"{len(ctx.js_files)} JS files | "
        f"{len(ctx.js_global_params)} params | "
        f"{len(high_value)} high-value | "
        f"{len(ctx.js_endpoints)} endpoints | "
        f"{len(all_secrets)} secret hints | "
        f"{len(lazy_chunks_total)} lazy chunks",
    )
    return ctx
