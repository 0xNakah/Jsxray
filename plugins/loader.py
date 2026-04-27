"""
JSXray Plugin Loader

Discovers, validates, and instantiates plugins declared in jsxray.toml
under [plugins.<name>] sections, then fires lifecycle hooks at the
correct points in the scan.

Expected TOML shape
-------------------
    [plugins.mcp]
    enabled = true
    # ... plugin-specific keys ...

    [plugins.discord]
    enabled = true
    webhook = "https://..."

Plugin resolution order
-----------------------
1.  If the block contains  module = "pkg.submodule"  that path is used.
2.  If the name matches a key in _BUILTIN_REGISTRY the registry path is used.
3.  Falls back to  plugins.<name>  (file inside the plugins/ package).

Every module must expose a class named  Plugin  that inherits BasePlugin.
"""
import importlib
from typing import List
from plugins.base import BasePlugin


# Maps short TOML names → importable module paths for built-in plugins.
# Add an entry here whenever a new built-in is created.
_BUILTIN_REGISTRY: dict = {
    "mcp": "plugins.builtin.mcp_plugin",
}


# ── Internal helpers ─────────────────────────────────────────────────────────

def _resolve_module(name: str, plugin_cfg: dict) -> str:
    """Return the importable module path for a plugin entry."""
    if "module" in plugin_cfg:
        return plugin_cfg["module"]
    if name in _BUILTIN_REGISTRY:
        return _BUILTIN_REGISTRY[name]
    return f"plugins.{name}"


# ── Public API ───────────────────────────────────────────────────────────────

def load_plugins(config: dict) -> List[BasePlugin]:
    """
    Read [plugins.*] from the config dict and return a list of
    instantiated, enabled BasePlugin objects.
    """
    plugins_cfg: dict = config.get("plugins", {})
    loaded: List[BasePlugin] = []

    for name, plugin_cfg in plugins_cfg.items():
        if not isinstance(plugin_cfg, dict):
            plugin_cfg = {}

        if not plugin_cfg.get("enabled", True):
            print(f"[loader] Plugin '{name}' disabled — skipping")
            continue

        module_path = _resolve_module(name, plugin_cfg)

        try:
            mod = importlib.import_module(module_path)
        except ModuleNotFoundError as e:
            print(f"[loader] ✗ Cannot import plugin '{name}' ({module_path}): {e}")
            continue

        cls = getattr(mod, "Plugin", None)
        if cls is None or not (isinstance(cls, type) and issubclass(cls, BasePlugin)):
            print(f"[loader] ✗ '{module_path}' has no valid Plugin class — skipping")
            continue

        try:
            instance = cls(config=plugin_cfg)
            loaded.append(instance)
            print(f"[loader] ✓ Loaded plugin '{instance.name}' v{instance.version}")
        except Exception as e:
            print(f"[loader] ✗ Failed to instantiate plugin '{name}': {e}")

    return loaded


def run_plugins_on_context_ready(plugins: List[BasePlugin], ctx) -> None:
    """
    Fire on_context_ready() on every loaded plugin.
    Call this immediately after the intake phase completes.
    """
    for plugin in plugins:
        try:
            plugin.on_context_ready(ctx)
        except Exception as e:
            print(f"[loader] Plugin '{plugin.name}' on_context_ready() failed: {e}")


def run_plugins_post_scan(plugins: List[BasePlugin], ctx) -> None:
    """
    Fire run() on every loaded plugin.
    Call this after all scan phases have completed.
    """
    for plugin in plugins:
        try:
            plugin.run(ctx)
        except Exception as e:
            print(f"[loader] Plugin '{plugin.name}' run() failed: {e}")


def teardown_plugins(plugins: List[BasePlugin]) -> None:
    """
    Fire teardown() on every loaded plugin.
    Register via atexit so it always runs, even on keyboard interrupt.
    """
    for plugin in plugins:
        try:
            plugin.teardown()
        except Exception:
            pass
