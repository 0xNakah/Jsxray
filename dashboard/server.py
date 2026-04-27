import os, json, glob
from flask import Flask, jsonify, send_from_directory, send_file

# ── Helpers ─────────────────────────────────────────────────────────────────

def _load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None

def _load_lines(path):
    """Return non-empty, non-comment lines from a text file."""
    try:
        with open(path) as f:
            return [l.rstrip() for l in f if l.strip() and not l.startswith("#")]
    except Exception:
        return []

def _workspace(recon_dir, target, timestamp):
    return os.path.join(recon_dir, target, timestamp)

def _safe_jsonify(data, empty=None):
    if data is None:
        return jsonify(empty if empty is not None else {})
    return jsonify(data)


def create_app(recon_dir="recon"):
    app = Flask(__name__, static_folder="static")
    recon_dir = os.path.abspath(recon_dir)

    # ── Index ───────────────────────────────────────────────────────────────
    @app.route("/")
    def index():
        idx = os.path.join(app.static_folder, "index.html")
        if os.path.exists(idx):
            return send_file(idx)
        return ("<h2>JSXray Dashboard</h2>"
                "<p>Deploy the Next.js frontend into <code>dashboard/static/</code>.</p>"
                "<p>API is live at <a href='/api/runs'>/api/runs</a></p>")

    # ── List all runs ────────────────────────────────────────────────────────
    @app.route("/api/runs")
    def get_runs():
        runs = []
        for path in sorted(glob.glob(os.path.join(recon_dir, "*", "*", "summary.json")), reverse=True):
            try:
                data = json.load(open(path))
                data["_path"] = path
                runs.append(data)
            except Exception:
                pass
        return jsonify(runs)

    @app.route("/api/targets")
    def get_targets():
        targets = sorted([d for d in os.listdir(recon_dir)
                          if os.path.isdir(os.path.join(recon_dir, d))])
        return jsonify(targets)

    # ── Full run dump (all JSON files) ─────────────────────────────────────────
    @app.route("/api/run/<target>/<timestamp>")
    def get_run(target, timestamp):
        base   = _workspace(recon_dir, target, timestamp)
        result = {}
        json_files = [
            "summary.json", "secrets.json", "js_secrets_hints.json",
            "js_endpoints.json", "crawl_endpoints.json", "crawl_endpoints_flat.txt",
            "js_params.json", "js_params_high_confidence.txt", "js_params_flat.txt",
            "robots_paths.json", "source_maps.json", "sitemap_urls.json",
            "reflections.json", "diff.json",
        ]
        for fname in json_files:
            fpath = os.path.join(base, fname)
            key   = fname.replace(".json", "").replace(".txt", "")
            if fname.endswith(".json"):
                data = _load_json(fpath)
            else:
                data = _load_lines(fpath) or None
            if data is not None:
                result[key] = data
        return jsonify(result)

    # ── MCP-facing focused endpoints ──────────────────────────────────────────
    #  These mirror what the MCP tools query so the MCP server can proxy them.

    @app.route("/api/run/<target>/<timestamp>/summary")
    def get_summary(target, timestamp):
        path = os.path.join(_workspace(recon_dir, target, timestamp), "summary.json")
        return _safe_jsonify(_load_json(path), {"note": "summary.json not found"})

    @app.route("/api/run/<target>/<timestamp>/secrets")
    def get_secrets(target, timestamp):
        base    = _workspace(recon_dir, target, timestamp)
        secrets = _load_json(os.path.join(base, "secrets.json")) or []
        hints   = _load_json(os.path.join(base, "js_secrets_hints.json")) or []
        return jsonify({"secrets": secrets, "hints": hints, "total": len(secrets)})

    @app.route("/api/run/<target>/<timestamp>/endpoints")
    def get_endpoints(target, timestamp):
        base     = _workspace(recon_dir, target, timestamp)
        js_eps   = _load_json(os.path.join(base, "js_endpoints.json")) or []
        crawl_ep = _load_json(os.path.join(base, "crawl_endpoints.json")) or []
        all_eps  = list(dict.fromkeys(js_eps + crawl_ep))
        return jsonify({
            "endpoints":    all_eps,
            "js_count":     len(js_eps),
            "crawl_count":  len(crawl_ep),
            "total":        len(all_eps),
        })

    @app.route("/api/run/<target>/<timestamp>/params")
    def get_params(target, timestamp):
        base = _workspace(recon_dir, target, timestamp)
        hc   = _load_lines(os.path.join(base, "js_params_high_confidence.txt"))
        flat = _load_lines(os.path.join(base, "js_params_flat.txt"))
        full = _load_json(os.path.join(base, "js_params.json")) or {}
        return jsonify({
            "high_confidence": hc,
            "all_params":      flat,
            "per_file":        full,
        })

    @app.route("/api/run/<target>/<timestamp>/nuclei")
    def get_nuclei(target, timestamp):
        path    = os.path.join(_workspace(recon_dir, target, timestamp), "nuclei_targets.txt")
        targets = _load_lines(path)
        return jsonify({"targets": targets, "total": len(targets)})

    # ── Latest run shortcuts ───────────────────────────────────────────────────
    #  /api/latest/<target>/secrets  etc. — always returns the most recent scan

    def _latest_timestamp(target):
        target_dir = os.path.join(recon_dir, target)
        if not os.path.isdir(target_dir):
            return None
        stamps = sorted(
            [d for d in os.listdir(target_dir) if os.path.isdir(os.path.join(target_dir, d))],
            reverse=True,
        )
        return stamps[0] if stamps else None

    @app.route("/api/latest/<target>/summary")
    def latest_summary(target):
        ts = _latest_timestamp(target)
        if not ts:
            return jsonify({"note": "no scans found for target"}), 404
        return get_summary(target, ts)

    @app.route("/api/latest/<target>/secrets")
    def latest_secrets(target):
        ts = _latest_timestamp(target)
        if not ts:
            return jsonify({"note": "no scans found for target"}), 404
        return get_secrets(target, ts)

    @app.route("/api/latest/<target>/endpoints")
    def latest_endpoints(target):
        ts = _latest_timestamp(target)
        if not ts:
            return jsonify({"note": "no scans found for target"}), 404
        return get_endpoints(target, ts)

    @app.route("/api/latest/<target>/params")
    def latest_params(target):
        ts = _latest_timestamp(target)
        if not ts:
            return jsonify({"note": "no scans found for target"}), 404
        return get_params(target, ts)

    @app.route("/api/latest/<target>/nuclei")
    def latest_nuclei(target):
        ts = _latest_timestamp(target)
        if not ts:
            return jsonify({"note": "no scans found for target"}), 404
        return get_nuclei(target, ts)

    # ── Legacy ────────────────────────────────────────────────────────────────────
    @app.route("/api/findings/<target>/<timestamp>")
    def get_findings(target, timestamp):
        fpath = os.path.join(_workspace(recon_dir, target, timestamp), "reflections.json")
        return jsonify(_load_json(fpath) or [])

    # ── Static files ───────────────────────────────────────────────────────────────
    @app.route("/<path:path>")
    def static_files(path):
        return send_from_directory(app.static_folder, path)

    return app
