# JSXray

JavaScript recon tool for bug bounty hunting. Discovers JS files, extracts parameters and endpoints, crawls discovered URLs for more findings, and optionally enumerates subdomains.

---

## Install

```bash
git clone https://github.com/0xNakah/Jsxray.git
cd Jsxray
pip install requests flask
```

For `standard` and `full` modes, install the external tools you need:

```
subfinder   amass   gau   waybackurls   waymore
httpx   x8   arjun   uro   xnLinkFinder   katana
```

Quick mode works with no external tools.

---

## Usage

```bash
python3 jsxray.py -t target.com
python3 jsxray.py -t target.com --mode quick
python3 jsxray.py -t target.com --mode full --silent
python3 jsxray.py -t target.com --skip-phases deep
python3 jsxray.py -t target.com --timeout 120 --no-dashboard
```

---

## Modes

| Mode | What it runs | External tools needed |
|---|---|---|
| `quick` | robots → JS discovery → JS extract → endpoint crawl | None |
| `standard` | quick + passive URL collection + deep + crawl | gau / waymore / x8 / arjun |
| `full` | standard + subdomain enumeration | subfinder / amass + above |

---

## What it finds

- JavaScript files from live pages, robots.txt, and collected URLs
- Parameters extracted from JS source, source maps, and lazy-loaded chunks
- Endpoints referenced in JS (`fetch`, `axios`, path strings)
- New params and endpoints found by crawling discovered URLs
- Secrets and API key patterns in JS (AWS, Stripe, JWT, etc.)
- Subdomains (full mode only)

---

## Output

Results are written to `recon/<target>_<timestamp>/`:

```
js_files.txt                  — all discovered JS files
js_params_flat.txt            — all extracted parameters
js_endpoints_flat.txt         — all extracted endpoints
js_params.json                — params with high-value flagging
js_endpoints.json             — endpoints with per-file breakdown
lazy_chunks.json              — lazy-loaded JS chunks found
js_secrets_hints.json         — potential secrets / API keys
crawl_params_flat.txt         — params found by endpoint crawl
crawl_endpoints_flat.txt      — endpoints found by endpoint crawl
crawl_extra_js.txt            — new JS files found during crawl
```

---

## Options

```
-t, --target        Target domain or URL (required)
-m, --mode          quick / standard / full  (default: standard)
--phases            Run specific phases only  (comma-separated)
--skip-phases       Skip specific phases
-o, --output-dir    Output directory  (default: recon/)
--timeout           HTTP timeout in seconds  (default: 60)
-s, --silent        Compact output only
--no-dashboard      Skip the web dashboard
--config            Path to jsxray.toml
--port              Dashboard port  (default: 5000)
```

---

## Legal

Only use on targets you are authorized to test.
