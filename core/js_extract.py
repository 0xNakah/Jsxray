"""
js_extract.py — JS Parameter & Endpoint Extraction

Fixes applied
─────────────
FIX 4a  Add destructuring patterns:
         const { q, page, sort } = params / query / req.query / req.body
FIX 4b  Add FormData.append("name", ...) / fd.append("name", ...)
FIX 4c  Add axios({ params: { q, page } }) object-shorthand keys
FIX 4d  Add JSON.stringify({ q, page }) object-literal keys

Noise reduction
───────────────
FIX 5a  Filter frontend/framework/template noise such as:
         ng-click, ng-if, data-*, aria-*, v-*, x-*, hx-*
FIX 5b  Filter obvious non-parameter tokens:
         null, true, false, undefined, window, document, this, prototype, constructor
FIX 5c  Drop common UI/CSS-ish names that create false positives:
         form-group, dropdown-item, tooltip, field-name
FIX 5d  Correct destructuring alias parsing:
         const { search: alias } = query  → extract "search", not "alias"

FIX 6   Validate resolved endpoint URLs — drop anything whose netloc is
         empty, has no dot, or whose scheme is not http/https.

FIX 7   Drop camelCase identifiers before lowercasing.
         HTTP params are snake_case / kebab-case / lowercase — never camelCase.
         Any token with an internal uppercase letter (e.g. appendChild,
         getBoundingClientRect) is a JS identifier and is silently rejected.
         Also catches uppercase-prefix mixed case (XMLData, HTMLContent).

FIX 8   fetch_source_map now also extracts route hints from the `sources`
         array when sourcesContent is empty or unavailable.

FIX 9   extract_params no longer double-passes PARAM_BLOCK entries.
         Destructuring patterns use _parse_destructure only;
         object-literal patterns use _parse_object_keys only.
"""

import re, requests, json
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.context import Context

HEADERS = {
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept":          "*/*",
}

HIGH_VALUE_PARAMS = {
    "redirect","redirect_uri","redirect_url","redirecturl","redirecturi",
    "return","returnurl","returnuri","return_url","return_uri",
    "next","continue","forward","goto","dest","destination",
    "target","ref","referer","referrer","back","location","url","uri",
    "q","query","search","keyword","keywords","term","terms","text",
    "input","msg","message","content","comment","description","title",
    "subject","body","note","name","value","data","payload",
    "template","view","page","layout","format","theme","style",
    "lang","language","locale","currency","country","region",
    "debug","test","preview","mode","dev","verbose","trace",
    "token","state","code","nonce","scope","response_type",
    "file","filename","path","dir","folder","upload","attachment",
    "callback","cb","jsonp","handler","fn",
}

# Exact noise tokens — very unlikely to be real HTTP params
NOISE_EXACT = {
    "null","true","false","undefined","window","document","this","global",
    "prototype","constructor","__proto__","length","valueof","tostring",
    "classname","innerhtml","outerhtml","innertext","textcontent",
    "onclick","onload","onerror","onfocus","onblur","onchange","onsubmit",
    "tooltip","dropdown-item","form-group","field-name",
    "needsadmin","usagestats","productid","appguid","appname",
    "glue-show","form-control","input-group",
}

# Prefixes common in frontend directives / template attrs — never real params
NOISE_PREFIXES = (
    "ng-", "data-", "aria-", "v-", "x-", "hx-",
)

# Pattern-based noise (applied post-lowercase)
NOISE_PATTERNS = [
    re.compile(r"^on[a-z]+$"),          # onclick / onmouseover / etc.
    re.compile(r"^(?:js|css|html)$"),   # generic filetype noise
]

# FIX 7 (extended): catches both standard camelCase (userId) and
# uppercase-prefix mixed case (XMLData, HTMLContent, getBoundingClientRect).
# Rules:
#   - standard camelCase:  lowercase letter followed by uppercase  → [a-z][A-Z]
#   - PascalCase / mixed:  uppercase letter followed by lowercase  → [A-Z][a-z]
#     (this catches XMLData: 'L'→'D' is [A-Z][a-z], and getBoundingClientRect)
# All-caps acronyms used as real params (ID, URL, OK, API) are fully uppercase
# and contain no [a-z][A-Z] or [A-Z][a-z] transitions, so they pass through.
_CAMEL_RE = re.compile(r'[a-z][A-Z]|[A-Z][a-z]')


def _is_camel_case(name: str) -> bool:
    """Return True if name looks like a JS identifier rather than an HTTP param.

    Rejects:
      - standard camelCase:           userId, addEventListener
      - uppercase-prefix mixed case:  XMLData, HTMLContent, getBoundingClientRect

    Passes through:
      - all-lowercase:  search, page, sort
      - snake_case:     redirect_uri, user_id
      - kebab-case:     redirect-uri
      - all-caps:       ID, URL, API, OK  (real params exist in all-caps)
    """
    return bool(_CAMEL_RE.search(name))


def is_noise_param(name: str) -> bool:
    """Return True if name should be discarded (not a real HTTP param).

    Expects the name already lowercased. For camelCase detection call
    _is_camel_case() on the original token BEFORE lowercasing.
    """
    if not name:
        return True
    n = name.strip().lower()
    if len(n) < 2 or len(n) > 40:
        return True
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9_\-]*$", n):
        return True
    if n in NOISE_EXACT:
        return True
    if any(n.startswith(prefix) for prefix in NOISE_PREFIXES):
        return True
    if any(pat.match(n) for pat in NOISE_PATTERNS):
        return True
    return False


def _host_in_scope(host: str, domain: str) -> bool:
    host = (host or "").lower().lstrip("www.")
    base = (domain or "").lower().lstrip("www.")
    return bool(host) and bool(base) and (host == base or host.endswith("." + base))


# ── Endpoint patterns ─────────────────────────────────────────────────────────
ENDPOINT_PATTERNS = [
    re.compile(
        r"""(?:fetch|axios(?:\.\w+)?|http\.(?:get|post|put|delete|patch))\s*"""
        r"""\(\s*['"`]([^'"`\s]{3,}(?:/[^'"`\s]*)?)['"`]"""
    ),
    re.compile(r"""['"`](/(?:api|v\d+|rest|graphql|ajax|service|data|endpoint|query)[^'"`\s]{0,100})['"`]"""),
    re.compile(r"""['"`](/[a-zA-Z0-9_\-./]{3,80}\?[a-zA-Z0-9_\-=&%+.]{2,100})['"`]"""),
    re.compile(r"""['"`](https?://[^'"`\s]{10,200})['"`]"""),
    re.compile(r"""(?:path|route|url|href|src|action)\s*[:=]\s*['"`](/[^'"`\s]{2,80})['"`]"""),
]

# ── Single-name parameter patterns ───────────────────────────────────────────
PARAM_SINGLE = [
    # URLSearchParams .get / .set / .append / .has
    re.compile(
        r"""(?:searchParams|URLSearchParams|params)\s*"""
        r"""\.(?:get|append|set|has)\s*\(\s*['"`]([a-zA-Z0-9_\-]{1,40})['"`]"""
    ),
    # query string  ?param=  &param=
    re.compile(r"""[?&]([a-zA-Z0-9_\-]{1,40})="""),
    # object property access: params.foo  query["foo"]  req.query.foo
    re.compile(
        r"""(?:params|query|qs|req\.query|args|opts)\s*[.\[]\s*['"`]?"""
        r"""([a-zA-Z0-9_\-]{1,40})['"`]?"""
    ),
    # body / payload access — require quote or dot to avoid matching JS keywords
    re.compile(
        r"""(?:body|payload|data|form|req\.body)\s*(?:\.\s*|\[\s*['"`])"""
        r"""([a-zA-Z0-9_\-]{1,40})"""
    ),
    # const q = params.q  (captures the var name, same as the param)
    re.compile(r"""(?:const|let|var)\s+([a-zA-Z0-9_]{1,30})\s*=\s*(?:params|query|searchParams)\s*\."""),
    # GraphQL: $variable: String
    re.compile(r"""\$([a-zA-Z0-9_]{1,30})\s*:\s*(?:String|Int|Boolean|ID|Float)"""),
    # FormData.append("name", ...)  fd.append('name', ...)
    re.compile(r"""(?:formData|formdata|form|fd|new\s+FormData\s*\(\s*\))\s*\.append\s*\(\s*['"`]([a-zA-Z0-9_\-]{1,40})['"`]"""),
    # generic .append('name', ...) chains
    re.compile(r"""\.append\s*\(\s*['"`]([a-zA-Z0-9_\-]{1,40})['"`]"""),
]

# ── Block patterns (destructuring / object literals) ─────────────────────────
# FIX 9: Each entry is a (pattern, parser) tuple so extract_params knows
# exactly which parser to apply — no more double-passing the same block.
#
# Destructuring patterns  → _parse_destructure
#   Handles: const { q, page, sort='asc', search: alias } = params
#   Takes LHS of colon, so { search: localVar } → 'search', not 'localVar'.
#
# Object-literal patterns → _parse_object_keys
#   Handles: { q, page: val, sort: fn() }  (keys only, not values)

PARAM_BLOCK_DESTRUCTURE = [
    # const { q, page, sort } = params / query / req.query / req.body
    re.compile(
        r"""(?:const|let|var)\s*\{([^}]{1,300})\}\s*=\s*"""
        r"""(?:params|query|searchParams|req\.query|req\.body|qs|body|payload)"""
    ),
]

PARAM_BLOCK_OBJECT = [
    # axios({ params: { q, page } })
    re.compile(r"""params\s*:\s*\{([^}]{1,300})\}"""),
    # fetch body  JSON.stringify({ q, page, sort })
    re.compile(r"""JSON\.stringify\s*\(\s*\{([^}]{1,300})\}\s*\)"""),
    # qs.stringify({ q, page })
    re.compile(r"""qs\.stringify\s*\(\s*\{([^}]{1,300})\}\s*\)"""),
]

# ── Secret patterns (TruffleHog-aligned) ─────────────────────────────────────
SECRET_PATTERNS = {
    # Cloud — AWS
    "aws_access_key":        re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
    "aws_secret_key":        re.compile(r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),

    # Cloud — Azure
    "azure_storage_conn":    re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"),
    "azure_sas_token":       re.compile(r"(?i)sv=\d{4}-\d{2}-\d{2}&s[sco]=.{10,200}&sig=[A-Za-z0-9%+/=]{40,}"),

    # Cloud — GCP
    "gcp_service_account":   re.compile(r'"type"\s*:\s*"service_account"'),
    "gcp_api_key":           re.compile(r"AIza[0-9A-Za-z\-_]{35}"),

    # Payment & Finance
    "stripe_live_key":       re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "stripe_restricted_key": re.compile(r"rk_live_[0-9a-zA-Z]{24,}"),
    "paypal_braintree":      re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    "square_token":          re.compile(r"sq0atp-[0-9A-Za-z\-_]{22}"),
    "square_oauth_secret":   re.compile(r"sq0csp-[0-9A-Za-z\-_]{43}"),

    # Tokens & Auth
    "jwt_token":             re.compile(r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*"),
    "github_pat":            re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    "github_oauth":          re.compile(r"gho_[0-9a-zA-Z]{36}"),
    "github_app_token":      re.compile(r"(?:ghu|ghs)_[0-9a-zA-Z]{36}"),
    "gitlab_pat":            re.compile(r"glpat-[0-9a-zA-Z\-_]{20}"),
    "npmrc_token":           re.compile(r"//registry\.npmjs\.org/:_authToken=[0-9a-zA-Z\-_]{36,}"),

    # AI / LLM
    "openai_key":            re.compile(r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}"),
    "anthropic_key":         re.compile(r"sk-ant-api\d{2}-[A-Za-z0-9\-_]{93}AA"),

    # Communication
    "slack_token":           re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,250}"),
    "slack_webhook":         re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}"),
    "twilio_account_sid":    re.compile(r"AC[a-z0-9]{32}"),
    "twilio_auth_token":     re.compile(r"(?i)twilio.{0,20}['\"][a-f0-9]{32}['\"]"),
    "sendgrid_key":          re.compile(r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}"),
    "mailchimp_key":         re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}"),

    # Infrastructure
    "generic_db_conn":       re.compile(r"(?i)(?:mongodb|mysql|postgres|redis|mssql)://[^:]+:[^@]+@[^\s\"']+"),
    "private_key_pem":       re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "heroku_api_key":        re.compile(r"(?i)[hH]eroku.{0,20}['\"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"]"),

    # Generic high-entropy fallback
    "generic_secret":        re.compile(r"(?i)(?:secret|api_key|apikey|token|passwd|password|auth)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9\-_/+]{20,})['\"]"),
}


# ── Block parsers ─────────────────────────────────────────────────────────────

def _parse_destructure(block):
    """Extract param names from { q, page, sort='asc', search: alias }.
    Takes LHS of colon so { search: localVar } yields 'search', not 'localVar'.
    """
    names = []
    for token in block.split(","):
        token = token.strip()
        if not token or token.startswith("..."):
            continue
        if "=" in token:
            token = token.split("=", 1)[0].strip()
        if ":" in token:
            token = token.split(":", 1)[0].strip()
        raw  = token.strip().strip("'\"` ; ")
        if _is_camel_case(raw):
            continue
        name = raw.lower()
        if not is_noise_param(name):
            names.append(name)
    return names


def _parse_object_keys(block):
    """Extract key names from { q, page: val, sort: fn() }."""
    names = []
    for token in block.split(","):
        token = token.strip()
        if not token or token.startswith("..."):
            continue
        raw = token.split(":", 1)[0].strip().strip("'\"` ; ")
        if _is_camel_case(raw):
            continue
        key = raw.lower()
        if not is_noise_param(key):
            names.append(key)
    return names


# ── HTTP helpers ──────────────────────────────────────────────────────────────

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


# FIX 8: When sourcesContent is absent or empty, fall back to extracting
# route-hint paths from the `sources` array and injecting them as synthetic
# endpoint candidates into the returned text so extract_endpoints() can pick
# them up in the normal flow.
_SOURCE_PATH_NOISE = re.compile(
    r"(?:node_modules|webpack/runtime|__webpack|\.(test|spec|stories|d\.ts))",
    re.IGNORECASE,
)

def _sources_to_hint_text(sources: list) -> str:
    """Convert source map `sources` file paths to a synthetic JS snippet.

    Paths like '../src/api/users.js' are emitted as:
        path: "/api/users"
    so that ENDPOINT_PATTERNS pick them up naturally.
    """
    lines = []
    for src in sources:
        if not src or not isinstance(src, str):
            continue
        if _SOURCE_PATH_NOISE.search(src):
            continue
        # Normalise: strip webpack:// prefix, query strings, hash
        clean = re.sub(r'^webpack:/+[^/]*', '', src)
        clean = re.sub(r'[?#].*$', '', clean)
        clean = re.sub(r'\.(?:js|ts|jsx|tsx|vue|svelte)$', '', clean, flags=re.IGNORECASE)
        # Keep only path-like segments (at least one slash and alpha char)
        if '/' not in clean:
            continue
        # Collapse relative dots: strip leading ./ or ../
        clean = re.sub(r'^(?:\.\./)+', '/', clean)
        clean = re.sub(r'^\.',  '/', clean)
        if not clean.startswith('/'):
            clean = '/' + clean
        lines.append(f'path: "{clean}"')
    return '\n'.join(lines)


def fetch_source_map(map_url, timeout, ua):
    """Fetch and decode a source map.

    Priority:
      1. sourcesContent  — inlined original source (best signal)
      2. sources paths   — file path hints → synthetic endpoint text (FIX 8)
      3. raw map text    — fallback
    """
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

        # 1. Prefer inlined source content
        sources_content = data.get("sourcesContent", [])
        combined = "\n\n".join(s for s in sources_content if s and isinstance(s, str))
        if combined:
            return combined

        # 2. FIX 8: fall back to path hints from `sources` array
        sources = data.get("sources", [])
        hint_text = _sources_to_hint_text(sources)
        if hint_text:
            return hint_text

        # 3. Raw map text as last resort
        return r.text

    except Exception:
        pass
    return ""


# ── URL validation ────────────────────────────────────────────────────────────

def _is_valid_endpoint(url: str) -> bool:
    """Return True only if url has a proper scheme and a routable hostname."""
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        netloc = p.netloc.split(":")[0]
        if not netloc or "." not in netloc:
            return False
        tld = netloc.rsplit(".", 1)[-1]
        if len(tld) < 2:
            return False
        return True
    except Exception:
        return False


def _is_in_scope_endpoint(url: str, domain: str) -> bool:
    try:
        host = urlparse(url).netloc
        return _host_in_scope(host, domain)
    except Exception:
        return False


# ── Core extraction ───────────────────────────────────────────────────────────

def extract_endpoints(text, base_url, domain):
    endpoints = set()
    for pattern in ENDPOINT_PATTERNS:
        for m in pattern.finditer(text):
            ep = m.group(1).strip()
            resolved = ep if ep.startswith("http") else urljoin(base_url, ep)
            if _is_valid_endpoint(resolved) and _is_in_scope_endpoint(resolved, domain):
                endpoints.add(resolved)
    return list(endpoints)


def extract_params(text):
    params = set()

    # Single-token patterns
    for pattern in PARAM_SINGLE:
        for m in pattern.finditer(text):
            raw  = m.group(1).strip()
            if _is_camel_case(raw):
                continue
            name = raw.lower()
            if not is_noise_param(name):
                params.add(name)

    # FIX 9: destructuring patterns — parse as destructure only
    for pattern in PARAM_BLOCK_DESTRUCTURE:
        for m in pattern.finditer(text):
            for name in _parse_destructure(m.group(1)):
                params.add(name)

    # FIX 9: object-literal patterns — parse as object keys only
    for pattern in PARAM_BLOCK_OBJECT:
        for m in pattern.finditer(text):
            for name in _parse_object_keys(m.group(1)):
                params.add(name)

    return sorted(params)


def extract_secrets(text, js_url):
    secrets = []
    for name, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(text):
            match_str = m.group(0)
            # Skip obvious placeholder/template values
            if re.match(r"^[xX\*<>{}|]+$", match_str):
                continue
            secrets.append({
                "url":       js_url,
                "type":      name,
                "match":     match_str[:120],
            })
    return secrets


def process_js_file(js_url, map_url, base_url, domain, timeout, ua):
    result = {
        "url": js_url,
        "map_url": map_url,
        "endpoints": [],
        "params": [],
        "secrets": [],
        "source": "js",
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

    result["endpoints"] = extract_endpoints(text, base_url, domain)
    result["params"]    = extract_params(text)
    result["secrets"]   = extract_secrets(text, js_url)
    return result


# ── Phase runner ──────────────────────────────────────────────────────────────

def run(ctx, phase_num=5, total=9):
    base_url = getattr(ctx, "canonical_url", None) or ctx.target_url
    domain   = urlparse(base_url).netloc.lstrip("www.")

    if not ctx.js_files:
        ctx.log("[js_extract] No JS files to process — skipping")
        ctx.phases_run.append("js_extract")
        ctx.log_phase_done(phase_num, total, "js_extract", "0 JS files")
        return ctx

    ctx.log(
        f"[js_extract] Processing {len(ctx.js_files)} JS files "
        f"({len(ctx.source_maps)} with source maps)..."
    )

    all_results   = []
    global_params = set()
    global_ep     = set()
    param_map     = {}
    all_secrets   = []

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {
            ex.submit(
                process_js_file,
                js_url,
                ctx.source_maps.get(js_url),
                base_url,
                domain,
                ctx.timeout,
                ctx.user_agent,
            ): js_url
            for js_url in ctx.js_files
        }

        for fut in as_completed(futures):
            r = fut.result()
            all_results.append(r)
            global_params.update(r["params"])
            global_ep.update(r["endpoints"])
            all_secrets.extend(r["secrets"])

            for ep in r["endpoints"]:
                param_map.setdefault(ep, set()).update(r["params"])

            if not ctx.silent and (r["params"] or r["endpoints"]):
                sec_lbl = f"  ★ {len(r['secrets'])} secrets" if r["secrets"] else ""
                ctx.log(
                    f"[js_extract]   {r['source']:12}  "
                    f"{len(r['params']):3} params  "
                    f"{len(r['endpoints']):3} endpoints{sec_lbl}"
                    f"  {r['url']}"
                )

    ctx.js_global_params = sorted(global_params)
    ctx.js_endpoints     = sorted(global_ep)
    ctx.js_param_map     = {ep: sorted(p) for ep, p in param_map.items()}
    ctx.js_file_data     = all_results

    high_value = [p for p in ctx.js_global_params if p in HIGH_VALUE_PARAMS]

    ctx.write_json("js_params.json", {
        "total_params": len(ctx.js_global_params),
        "high_value":   high_value,
        "all_params":   ctx.js_global_params,
        "by_endpoint":  ctx.js_param_map,
    })
    ctx.write_json("js_endpoints.json", {
        "total":     len(ctx.js_endpoints),
        "endpoints": ctx.js_endpoints,
    })
    ctx.write_text("js_params_flat.txt",    "\n".join(ctx.js_global_params))
    ctx.write_text("js_endpoints_flat.txt", "\n".join(ctx.js_endpoints))

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
        f"{len(all_secrets)} secret hints",
    )
    return ctx
