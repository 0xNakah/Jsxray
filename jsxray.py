#!/usr/bin/env python3
"""
JSXray — XSS Intelligence Engine
Usage: python3 jsxray.py -t target.com [options]
"""

import argparse, sys, os, time, threading, webbrowser, atexit
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.context import Context
from core.config  import load_config, get_phases_for_mode
from plugins.loader import (
    load_plugins,
    run_plugins_on_context_ready,
    run_plugins_post_scan,
    teardown_plugins,
)

VALID_PHASES = [
    "intake", "subdomains", "robots", "urls",
    "js_discovery", "js_extract", "endpoint_crawl", "deep", "crawl", "output",
]

PHASE_MAP = {
    "intake":          "core.intake",
    "subdomains":      "core.subdomains",
    "robots":          "core.robots",
    "urls":            "core.urls",
    "js_discovery":    "core.js_discovery",
    "js_extract":      "core.js_extract",
    "endpoint_crawl":  "core.endpoint_crawl",
    "deep":            "core.deep",
    "crawl":           "core.crawl",
    "output":          "core.output",
}

def parse_args():
    p = argparse.ArgumentParser(
        description="JSXray — XSS Intelligence Engine",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Modes:
  quick     → intake, robots, js_discovery, js_extract, endpoint_crawl, output
              NO external tools. robots.txt → live pages → JS files → params.
              Fast, self-contained, no gau/katana/waymore required.

  standard  → quick + urls phase (waymore/gau/waybackurls/commoncrawl/otx)
              + deep (x8 + arjun in parallel) + crawl (xnLinkFinder)
              Best for bug bounty: max param coverage with passive sources.

  full      → standard + subdomains
              (subfinder, amass, crtsh, otx, rapiddns, hackertarget, anubis)

Examples:
  python3 jsxray.py -t target.com
  python3 jsxray.py -t target.com --mode quick
  python3 jsxray.py -t target.com --mode full --silent
  python3 jsxray.py -t target.com --skip-phases deep
  python3 jsxray.py -t target.com --phases intake,robots,js_discovery,js_extract,endpoint_crawl,output
  python3 jsxray.py -t target.com --timeout 120
        """
    )
    p.add_argument("-t", "--target",     required=True,  help="Target domain or URL")
    p.add_argument("-m", "--mode",       default="standard",
                   choices=["quick", "standard", "full"],
                   help="Scan mode (default: standard)")
    p.add_argument("--phases",           help="Explicit comma-separated phase list (overrides mode)")
    p.add_argument("--skip-phases",      help="Comma-separated phases to skip")
    p.add_argument("-o", "--output-dir", default=None,   help="Output directory (default: recon/)")
    p.add_argument("--config",           default=None,   help="Path to jsxray.toml")
    p.add_argument("--port",             type=int, default=None, help="Dashboard port (default: 5000)")
    p.add_argument("--timeout",          type=int, default=None,
                   help="HTTP timeout in seconds (default: 60)")
    p.add_argument("-s", "--silent",     action="store_true",
                   help="Silent mode — only print compact phase summaries")
    p.add_argument("--no-dashboard",     action="store_true",
                   help="Skip launching the web dashboard")
    return p.parse_args()

def build_phase_list(args, config):
    if args.phases:
        phases = [p.strip() for p in args.phases.split(",") if p.strip() in VALID_PHASES]
    else:
        phases = get_phases_for_mode(config, args.mode)

    if args.skip_phases:
        skip   = {p.strip() for p in args.skip_phases.split(",")}
        phases = [p for p in phases if p not in skip]

    if "intake" not in phases:  phases.insert(0, "intake")
    if "output" not in phases:  phases.append("output")
    return phases

def run_phase(phase_name, ctx, phase_num, total):
    module_path = PHASE_MAP.get(phase_name)
    if not module_path:
        print(f"[jsxray] Unknown phase: {phase_name} — skipping")
        return ctx
    try:
        import importlib
        module = importlib.import_module(module_path)
        ctx    = module.run(ctx, phase_num=phase_num, total=total)
    except Exception as e:
        print(f"[jsxray] Phase '{phase_name}' failed: {e}")
        import traceback; traceback.print_exc()
        ctx.log_error(phase_name, str(e))
        ctx.failed_phases.append(phase_name)
    return ctx

def launch_dashboard(workspace, port):
    try:
        from dashboard.server import create_app
        recon_dir = os.path.dirname(os.path.dirname(workspace))
        app       = create_app(recon_dir=recon_dir)
        def open_browser():
            time.sleep(1.2)
            webbrowser.open(f"http://localhost:{port}")
        threading.Thread(target=open_browser, daemon=True).start()
        print(f"[jsxray] Dashboard → http://localhost:{port}  (Ctrl+C to stop)\n")
        app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
    except ImportError:
        print("[jsxray] Flask not installed — run: pip install flask")
    except OSError as e:
        print(f"[jsxray] Dashboard failed on port {port}: {e}")

def main():
    args   = parse_args()
    config = load_config(args.config)

    if args.output_dir: config["defaults"]["output_dir"] = args.output_dir
    if args.port:       config["defaults"]["port"]       = args.port
    if args.timeout:    config["defaults"]["timeout"]    = args.timeout

    phases = build_phase_list(args, config)
    total  = len(phases)

    # ── Load plugins ──────────────────────────────────────────────────────────
    plugins = load_plugins(config)
    atexit.register(teardown_plugins, plugins)
    # ─────────────────────────────────────────────────────────────────────────

    ctx = Context(
        target     = args.target,
        mode       = args.mode,
        phases     = phases,
        config     = config,
        timeout    = config["defaults"].get("timeout", 60),
        user_agent = config["defaults"].get("user_agent", "Mozilla/5.0"),
        silent     = args.silent,
    )

    print(f"\n[jsxray] Target : {args.target}")
    print(f"[jsxray] Mode   : {args.mode}  (phases: {', '.join(phases)})")
    print(f"[jsxray] Timeout: {ctx.timeout}s\n")

    t0 = time.time()
    for i, phase in enumerate(phases, 1):
        if not args.silent:
            print(f"\n[{i}/{total}] ── {phase.upper()} {'─'*40}")
        ctx = run_phase(phase, ctx, phase_num=i, total=total)

        # ── Plugin hook: right after intake ───────────────────────────────────
        if phase == "intake":
            run_plugins_on_context_ready(plugins, ctx)
        # ─────────────────────────────────────────────────────────────────────

    elapsed = time.time() - t0
    print(f"\n[jsxray] Done in {elapsed:.1f}s  →  {ctx.workspace}/")

    if ctx.failed_phases:
        print(f"[jsxray] ⚠  Failed phases: {', '.join(ctx.failed_phases)}")

    # ── Plugin hook: post-scan ────────────────────────────────────────────────
    if plugins:
        print(f"\n[jsxray] Running {len(plugins)} plugin(s)...")
        run_plugins_post_scan(plugins, ctx)
    # ─────────────────────────────────────────────────────────────────────────

    if not args.no_dashboard:
        port = config["defaults"].get("port", 5000)
        launch_dashboard(ctx.workspace, port)

if __name__ == "__main__":
    main()
