"""Shared Ambient Memory block cache for every connector.

So a connector's SessionStart can emit the orientation block INSTANTLY (file-only,
no network) and stay fast, while the block is refreshed in the background sync.
Identity-scoped (device + tool) + TTL'd; atomic write. Mirrors the plugin's
ambient_cache discipline so all tools behave identically.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Optional

from . import config

TTL = int(os.environ.get("ATLASO_AMBIENT_TTL", "900"))  # 15 min


def _path(tool: Optional[str]) -> Path:
    return config.atlaso_dir() / f"ambient_{tool or 'default'}.json"


def load(tool: Optional[str], identity: str, ttl: int = TTL) -> Optional[str]:
    """Return the cached block for THIS (tool, identity) if fresh, else None."""
    try:
        obj = json.loads(_path(tool).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(obj, dict) or obj.get("id") != identity:
        return None
    try:
        if (time.time() - float(obj.get("checked_at", 0))) >= ttl:
            return None
    except (TypeError, ValueError):
        return None
    b = obj.get("block")
    return b if isinstance(b, str) and b.strip() else None


def save(tool: Optional[str], identity: str, block: Optional[str]) -> None:
    p = _path(tool)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"block": block, "id": identity, "checked_at": time.time()}, f)
        os.replace(tmp, p)
    except OSError:
        pass
