"""atlaso_client — the tool-agnostic thin client core.

Ships with NO engine. Talks to the brain (smart recall/deposit), keeps a local
SQLite cache for instant writes + offline keyword recall, and syncs in the
background. Per-tool connectors (Claude Code, Claude Desktop, Codex, …) wrap this.

    from atlaso_client import Client
    c = Client()                       # reads ~/.atlaso/auth.json
    c.remember("Ashish prefers pnpm")  # instant local + background push
    hits = c.recall("package manager") # server when online, local when offline
    c.sync_once()                      # push outbox + pull new
"""
from .cache import Cache
from .core import Client

__all__ = ["Client", "Cache"]
__version__ = "0.1.0"
