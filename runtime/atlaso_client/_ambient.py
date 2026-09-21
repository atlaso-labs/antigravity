"""Shared scoped Ambient Memory snapshots.

Snapshots are for inspection/background refresh. SessionStart always validates
online so disabling Ambient affects the next session, even with a fresh cache.
Account/credential identity, tool, project and TTL isolate each atomic record.
"""
from __future__ import annotations

import hashlib
import math
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Optional

from . import config

TTL = int(os.environ.get("ATLASO_AMBIENT_TTL", "900"))  # 15 min


def _path(tool: Optional[str], project: Optional[str] = None) -> Path:
    # Versioned namespace: old account-wide records are never candidates for a
    # scoped brief. Hash both inputs so keys cannot become filesystem paths.
    key = hashlib.sha256(json.dumps([tool, project]).encode()).hexdigest()
    return config.atlaso_dir() / "ambient-v1" / f"{key}.json"


def load(tool: Optional[str], identity: str, ttl: int = TTL,
         *, project: Optional[str] = None) -> Optional[str]:
    """Return the cached block for THIS (tool, identity) if fresh, else None."""
    try:
        obj = json.loads(_path(tool, project).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(obj, dict) or obj.get("id") != identity or obj.get("project") != project:
        return None
    try:
        age = time.time() - float(obj.get("checked_at", 0))
        if not math.isfinite(age) or age < 0 or age >= ttl:
            return None
    except (TypeError, ValueError):
        return None
    b = obj.get("block")
    return b if isinstance(b, str) and b.strip() else None


def save(tool: Optional[str], identity: str, block: Optional[str],
         *, project: Optional[str] = None) -> None:
    p = _path(tool, project)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"block": block, "id": identity, "project": project, "checked_at": time.time()}, f)
            os.replace(tmp, p)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    except OSError:
        pass
