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
        "timeout":      60,           # 1 minute default
        "user_agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    },
    "tools": {
        "katana":      "katana",
        "subfinder":   "subfinder",
        "gau":         "gau",
        "waybackurls": "waybackurls",
        "waymore":     "waymore",
        "httpx":       "httpx",
        "x8":          "x8",
        "arjun":       "arjun",
        "uro":         "uro",
    },
    "mode": {
        # quick: NO external tools. robots.txt → pages → JS → params. Fast.
        "quick":    {"phases": ["intake","robots","js_discovery","js_extract","probe","score","output"]},
        # standard: adds tool-based URL harvest + deep param discovery
        "standard": {"phases": ["intake","robots","urls","js_discovery","js_extract","deep","probe","score","output"]},
        # full: subdomains + everything
        "full":     {"phases": ["intake","subdomains","robots","urls","js_discovery","js_extract","deep","probe","score","output"]},
        # watch: standard + monitor diff
        "watch":    {"phases": ["intake","robots","urls","js_discovery","js_extract","probe","score","output","monitor"]},
    },
    "alerts": {
        "discord_webhook":  "",
        "telegram_token":   "",
        "telegram_chat_id": "",
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
