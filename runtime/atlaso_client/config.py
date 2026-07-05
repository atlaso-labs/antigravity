"""Where the thin client finds its auth + local cache, and the server URL.

Mirrors the SDK's ``atlaso connect`` conventions WITHOUT importing the SDK — the
thin client ships with NO engine. It reads the same ``auth.json`` the CLI writes
({server, token, user_id, device_id}) from the same directory.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

# Production brain (overridable). Matches the SDK's _connect.DEFAULT_SERVER.
DEFAULT_SERVER = os.environ.get("ATLASO_SERVER", "https://mcp.atlaso.ai")


def atlaso_dir() -> Path:
    """The global Atlaso dir — same resolution order as the SDK CLI."""
    base = (
        os.environ.get("ATLASO_GLOBAL_PATH")
        or os.environ.get("ATLASO_PATH")
        or str(Path.home() / ".atlaso")
    )
    return Path(base).expanduser()


def auth_path() -> Path:
    return atlaso_dir() / "auth.json"


def cache_path() -> Path:
    """Local commodity cache (a plain SQLite mirror — NOT the engine field.db)."""
    override = os.environ.get("ATLASO_CACHE")
    return Path(override).expanduser() if override else atlaso_dir() / "cache.db"


def load_auth() -> dict | None:
    """Return the {server, token, user_id, device_id} dict, or None if not connected."""
    try:
        obj = json.loads(auth_path().read_text())
    except (OSError, ValueError):
        return None
    return obj if isinstance(obj, dict) else None
