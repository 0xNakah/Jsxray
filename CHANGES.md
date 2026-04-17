# JSXray Changes

## Bug Fixes
- **intake**: `detect_canonical()` — follows apex→www redirects before any phase runs
- **robots**: `probe_path()` — uses canonical base URL, `allow_redirects=True`, stores `resolved_url`
- **probe**: `build_probe_list()` — uses `canonical_url` + `resolved_url` for endpoint resolution

## Improvements

### quick mode redesigned
- Removed `urls` phase from quick mode (no gau/katana/waymore needed)
- Pipeline: intake → robots → js_discovery → js_extract → probe → score → output
- Fully self-contained, zero external tool dependency for quick scans

### timeout
- Default timeout raised to **60 seconds**
- Pass `--timeout N` to override per run

### urls.py
- Added **waymore** (xnl-h4ck3r) as a URL source alongside gau/waybackurls
- Quick mode short-circuits immediately (uses robots+sitemap seeds only)
- Standard mode: wayback_cdx + urlscan + waymore + gau + waybackurls (parallel)
- Full mode: standard + katana live crawl
- All tool calls gracefully skip if binary not in PATH

### js_discovery.py (rewritten)
- Step 1: fetch canonical root + all live robots pages + sitemap pages (parallel, 20 threads)
- Step 2: Wayback CDX passive JS seed (no target contact)
- Step 3: Common chunk patterns (Next.js / webpack) in standard/full mode
- Step 4: Parallel source map detection for every JS file found
- Tech-stack-aware chunk enumeration

### js_extract.py (rewritten)
- Expanded endpoint regex patterns (fetch/axios/router/href/src/action)
- Expanded param patterns (URLSearchParams, req.query, GraphQL $variables, body keys)
- **Secret/API key detection** → `js_secrets_hints.json`
- High-value param list covers redirect, SSRF, XSS sinks, auth, upload params
- Source map content used when available (richer than minified JS)
- Flat text output: `js_params_flat.txt`, `js_endpoints_flat.txt`

### config.py
- Default timeout: 60s
- quick mode phases: `intake,robots,js_discovery,js_extract,probe,score,output`
