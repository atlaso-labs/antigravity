"""Shared scoped Ambient Memory snapshots.

Snapshots are for inspection/background refresh. SessionStart always validates
online so disabling Ambient affects the next session, even with a fresh cache.
Account/credential identity, tool, project and TTL isolate each atomic record.

A snapshot is a copy of recalled memory text, so a forget deletes every snapshot
file (purge): they are inspection-only and rebuilt by the next sync's refresh.

A snapshot holds brief text only with the server's scrub attestation
(``SCRUB_VERSION``, the ``brief_scrub`` field of /v1/ambient). An older server
clipped notes before scrubbing them, so a cut credential could be too short for any
pattern to recognize, and no later pass can recover it. A snapshot with text but
without the attestation is deleted on read and never served.
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
SCRUB_VERSION = 2  # the server's brief_scrub value this client trusts


def attested(scrub: object) -> bool:
    """True only for the exact integer attestation (not 2.0, "2" or True)."""
    return type(scrub) is int and scrub == SCRUB_VERSION


def _dir() -> Path:
    return config.atlaso_dir() / "ambient-v1"


def _path(tool: Optional[str], project: Optional[str] = None) -> Path:
    # Versioned namespace: old account-wide records are never candidates for a
    # scoped brief. Hash both inputs so keys cannot become filesystem paths.
    key = hashlib.sha256(json.dumps([tool, project]).encode()).hexdigest()
    return _dir() / f"{key}.json"


def load_status(tool: Optional[str], identity: str, ttl: int = TTL,
                *, project: Optional[str] = None) -> tuple[Optional[str], bool]:
    """(block, legacy). ``block`` is the cached text for THIS (tool, identity, project)
    if fresh and attested, else None. ``legacy`` is True when the file held brief text
    without the scrub attestation; that file has just been deleted."""
    path = _path(tool, project)
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, False
    if not isinstance(obj, dict):
        return None, False
    b = obj.get("block")
    if not (isinstance(b, str) and b.strip()):
        return None, False
    if not attested(obj.get("scrub")):
        try:
            path.unlink()
        except OSError:
            pass
        return None, True
    if obj.get("id") != identity or obj.get("project") != project:
        return None, False
    try:
        age = time.time() - float(obj.get("checked_at", 0))
        if not math.isfinite(age) or age < 0 or age >= ttl:
            return None, False
    except (TypeError, ValueError):
        return None, False
    return b, False


def load(tool: Optional[str], identity: str, ttl: int = TTL,
         *, project: Optional[str] = None) -> Optional[str]:
    """Return the cached block for THIS (tool, identity) if fresh and attested, else None."""
    return load_status(tool, identity, ttl, project=project)[0]


def save(tool: Optional[str], identity: str, block: Optional[str],
         *, project: Optional[str] = None, scrub: Optional[int] = None) -> None:
    """Write the snapshot. Pass ``scrub=SCRUB_VERSION`` only for a block the server
    attested; any other block is stored as no block (nothing unattested on disk)."""
    if not attested(scrub):
        block, scrub = None, None
    p = _path(tool, project)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"block": block, "id": identity, "project": project,
                           "checked_at": time.time(), "scrub": scrub}, f)
            os.replace(tmp, p)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    except OSError:
        pass


def purge() -> int:
    """Delete every snapshot file (and any temp file a writer left behind) for
    every tool, project and identity on this machine. Called on a forget: a
    snapshot records no memory ids, and another tool's snapshot of the same
    account can hold the same text. Returns how many files were deleted; never
    raises."""
    n = 0
    try:
        entries = list(_dir().iterdir())
    except OSError:
        return 0
    for p in entries:
        if p.suffix in (".json", ".tmp") and p.is_file():
            try:
                p.unlink()
                n += 1
            except OSError:
                pass
    return n
