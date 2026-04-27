"""
JSXray Plugin Base
Every plugin inherits BasePlugin and implements the run() hook.
"""
from abc import ABC, abstractmethod


class BasePlugin(ABC):
    """
    Contract every JSXray plugin must fulfil.

    Lifecycle
    ---------
    1.  __init__(config)       -- called once at load-time with the plugin's config dict
    2.  on_context_ready(ctx)  -- optional, called right after the intake phase
    3.  run(ctx)               -- called after ALL phases complete (post-scan hook)
    4.  teardown()             -- optional, called at program exit
    """

    # ── Class-level metadata (override in subclass) ──────────────────────────
    name: str        = "unnamed_plugin"
    description: str = ""
    version: str     = "0.1.0"
    #: plugin_type tag for routing/introspection
    #: values: generic | mcp | notifier | exporter | ai
    plugin_type: str = "generic"

    def __init__(self, config: dict = None):
        self.config  = config or {}
        self.enabled = self.config.get("enabled", True)

    # ── Optional hooks ───────────────────────────────────────────────────────

    def on_context_ready(self, ctx):
        """
        Called immediately after the intake phase.
        Override to inspect or enrich ctx before the main scan phases run.
        Must return ctx.
        """
        return ctx

    # ── Required hook ────────────────────────────────────────────────────────

    @abstractmethod
    def run(self, ctx):
        """
        Post-scan hook. Receives the fully-populated Context after all
        phases have completed. Must return ctx.
        """
        ...

    # ── Optional cleanup ─────────────────────────────────────────────────────

    def teardown(self):
        """Called at program exit. Override for cleanup (close sockets, etc.)."""
        pass

    # ── Helpers ──────────────────────────────────────────────────────────────

    def log(self, msg: str):
        print(f"[plugin:{self.name}] {msg}")
