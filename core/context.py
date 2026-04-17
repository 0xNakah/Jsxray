import os, json
from datetime import datetime
from dataclasses import dataclass, field


@dataclass
class Context:
    # ── Identity ──────────────────────────────────────────────────────────────
    target:        str = ""
    target_url:    str = ""
    canonical_url: str = ""   # real live base after redirect detection
    timestamp:     str = field(default_factory=lambda: datetime.now().strftime("%Y%m%d_%H%M%S"))
    workspace:     str = ""
    mode:          str = "standard"
    phases:        list = field(default_factory=list)
    config:        dict = field(default_factory=dict)
    timeout:       int  = 10
    user_agent:    str  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    silent:        bool = False

    # ── Intake ────────────────────────────────────────────────────────────────
    tech_stack:    list = field(default_factory=list)   # fingerprinted stack
    robots_raw:    str  = ""
    robots_paths:  list = field(default_factory=list)
    robots_live:   list = field(default_factory=list)
    sitemap_urls:  list = field(default_factory=list)

    # ── Subdomains ────────────────────────────────────────────────────────────
    subdomains:       list = field(default_factory=list)
    subdomain_robots: dict = field(default_factory=dict)

    # ── URLs ──────────────────────────────────────────────────────────────────
    url_pool:         list = field(default_factory=list)
    url_sources:      dict = field(default_factory=dict)   # source → count

    # ── JS discovery ──────────────────────────────────────────────────────────
    js_files:         list = field(default_factory=list)
    source_maps:      dict = field(default_factory=dict)

    # ── JS extraction ────────────────────────────────────────────────────────
    js_param_map:     dict = field(default_factory=dict)
    js_global_params: list = field(default_factory=list)
    js_endpoints:     list = field(default_factory=list)
    js_file_data:     list = field(default_factory=list)

    # ── Deep ──────────────────────────────────────────────────────────────────
    hidden_params:    dict = field(default_factory=dict)

    # ── Probe / Score / Output ────────────────────────────────────────────────
    reflections:      list = field(default_factory=list)
    findings:         list = field(default_factory=list)

    # ── Monitor ───────────────────────────────────────────────────────────────
    diff:             dict = field(default_factory=dict)

    # ── Meta ──────────────────────────────────────────────────────────────────
    phases_run:       list = field(default_factory=list)
    errors:           list = field(default_factory=list)
    scan_start:       float = field(default_factory=lambda: __import__('time').time())

    # ─────────────────────────────────────────────────────────────────────────

    def setup_workspace(self, base_dir="recon"):
        safe = (self.target
                .replace("https://", "")
                .replace("http://", "")
                .replace("/", "_"))
        self.workspace = os.path.join(base_dir, safe, self.timestamp)
        os.makedirs(self.workspace, exist_ok=True)
        return self.workspace

    def log(self, msg, always=False):
        if not self.silent or always:
            print(msg)

    def log_phase_done(self, phase_num, total, phase_name, summary):
        print(f"[{phase_num}/{total}] {phase_name:<15} ✓  {summary}")

    def write_json(self, filename, data):
        path = os.path.join(self.workspace, filename)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        return path

    def write_text(self, filename, content):
        path = os.path.join(self.workspace, filename)
        with open(path, "w") as f:
            f.write(content)
        return path

    def log_error(self, phase, error):
        self.errors.append({"phase": phase, "error": str(error)})

    def elapsed(self):
        import time
        return round(time.time() - self.scan_start, 1)

    def to_summary(self):
        return {
            "target":       self.target,
            "canonical_url": self.canonical_url,
            "timestamp":    self.timestamp,
            "mode":         self.mode,
            "elapsed_s":    self.elapsed(),
            "phases_run":   self.phases_run,
            "tech_stack":   self.tech_stack,
            "errors":       self.errors,
            "stats": {
                "robots_paths":     len(self.robots_paths),
                "robots_live":      len([r for r in self.robots_live if r.get("status") == 200]),
                "robots_403":       len([r for r in self.robots_live if r.get("status") == 403]),
                "robots_redirect":  len([r for r in self.robots_live if r.get("status") in (301, 302, 307, 308)]),
                "url_pool":         len(self.url_pool),
                "url_sources":      self.url_sources,
                "js_files":         len(self.js_files),
                "source_maps":      len(self.source_maps),
                "js_endpoints":     len(self.js_endpoints),
                "js_global_params": len(self.js_global_params),
                "hidden_params":    sum(len(v) for v in self.hidden_params.values()),
                "reflections":      len(self.reflections),
                "findings":         len(self.findings),
                "critical":         len([f for f in self.findings if f.get("priority") == "critical"]),
                "high":             len([f for f in self.findings if f.get("priority") == "high"]),
                "medium":           len([f for f in self.findings if f.get("priority") == "medium"]),
                "low":              len([f for f in self.findings if f.get("priority") == "low"]),
            },
        }
