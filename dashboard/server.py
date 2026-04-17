import os, json, glob
from flask import Flask, jsonify, send_from_directory, send_file

def create_app(recon_dir="recon"):
    app = Flask(__name__, static_folder="static")
    recon_dir = os.path.abspath(recon_dir)

    @app.route("/")
    def index():
        idx = os.path.join(app.static_folder, "index.html")
        if os.path.exists(idx):
            return send_file(idx)
        return ("<h2>JSXray Dashboard</h2>"
                "<p>Deploy the Next.js frontend into <code>dashboard/static/</code>.</p>"
                "<p>API is live at <a href='/api/runs'>/api/runs</a></p>")

    @app.route("/api/runs")
    def get_runs():
        runs = []
        for path in sorted(glob.glob(os.path.join(recon_dir,"*","*","summary.json")), reverse=True):
            try:
                data = json.load(open(path))
                data["_path"] = path
                runs.append(data)
            except:
                pass
        return jsonify(runs)

    @app.route("/api/run/<target>/<timestamp>")
    def get_run(target, timestamp):
        base = os.path.join(recon_dir, target, timestamp)
        result = {}
        for fname in ["summary.json","reflections.json","js_params.json",
                      "robots_paths.json","js_endpoints.json","diff.json"]:
            fpath = os.path.join(base, fname)
            if os.path.exists(fpath):
                result[fname.replace(".json","")] = json.load(open(fpath))
        return jsonify(result)

    @app.route("/api/findings/<target>/<timestamp>")
    def get_findings(target, timestamp):
        fpath = os.path.join(recon_dir, target, timestamp, "reflections.json")
        return jsonify(json.load(open(fpath))) if os.path.exists(fpath) else jsonify([])

    @app.route("/api/targets")
    def get_targets():
        targets = sorted([d for d in os.listdir(recon_dir)
                          if os.path.isdir(os.path.join(recon_dir, d))])
        return jsonify(targets)

    @app.route("/<path:path>")
    def static_files(path):
        return send_from_directory(app.static_folder, path)

    return app
