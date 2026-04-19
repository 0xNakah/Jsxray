import os, shutil
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

DEFAULT_CONFIG = {
    "defaults": {
        "output_dir":   "recon",
        "port":         5000,
        "open_browser": True,
        "timeout":      60,
        "user_agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    },
    "tools": {
        "katana":       "katana",
        "subfinder":    "subfinder",
        "amass":        "amass",
        "chaos":        "chaos",
        "gau":          "gau",
        "waybackurls":  "waybackurls",
        "waymore":      "waymore",
        "httpx":        "httpx",
        "x8":           "x8",
        "arjun":        "arjun",
        "uro":          "uro",
        "xnLinkFinder": "xnLinkFinder",
    },
    "mode": {
        # quick: no external tools — robots → JS → params → endpoint crawl. Fast.
        "quick":    {"phases": ["intake", "robots", "js_discovery", "js_extract", "endpoint_crawl", "output"]},
        # standard: passive harvest + endpoint crawl + deep + active crawl
        "standard": {"phases": ["intake", "robots", "urls", "js_discovery", "js_extract", "endpoint_crawl", "deep", "crawl", "output"]},
        # full: subdomains + everything
        "full":     {"phases": ["intake", "subdomains", "robots", "urls", "js_discovery", "js_extract", "endpoint_crawl", "deep", "crawl", "output"]},
    },
}

def load_config(config_path=None):
    import copy
    config = copy.deepcopy(DEFAULT_CONFIG)
    paths = [
        config_path,
        "jsxray.toml",
        os.path.join(os.path.dirname(__file__), "..", "jsxray.toml"),
    ]
    for path in paths:
        if path and os.path.exists(path):
            if tomllib is None:
                break
            try:
                with open(path, "rb") as f:
                    user = tomllib.load(f)
                for section, values in user.items():
                    if section in config and isinstance(config[section], dict):
                        config[section].update(values)
                    else:
                        config[section] = values
            except Exception as e:
                print(f"[config] Warning: {e}")
            break
    return config

def get_phases_for_mode(config, mode):
    return list(config.get("mode", {}).get(mode, {}).get("phases", []))

def check_tool(name, config):
    binary = config.get("tools", {}).get(name, name)
    return shutil.which(binary) is not None
