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
    """Return the {server, token, user_id, device_id} dict, or None if not connected.

    This is the SHARED bearer — every integration on the machine reads it. It stays
    for compatibility (old plugin versions know nothing else) and as the bootstrap
    credential a tool trades in for one of its own. Prefer tool_auth() for traffic."""
    try:
        obj = json.loads(auth_path().read_text())
    except (OSError, ValueError):
        return None
    return obj if isinstance(obj, dict) else None


# ── per-tool credentials ────────────────────────────────────────────────────
#
# Each integration keeps its OWN credential in ~/.atlaso/tools/<tool>.json, so the
# brain can tell two tools on one machine apart — and so removing one tool can
# actually stop it, which is impossible while they all present the same bearer.
#
# SEPARATE FILES, not a `tools: {...}` map inside auth.json: two plugins can run at
# the same moment, and a shared map means a read-modify-write race where one clobbers
# the other's credential. A file per tool has no such race — each writer touches only
# its own path.

def tool_auth_path(tool: str) -> Path:
    return atlaso_dir() / "tools" / f"{tool}.json"


def load_tool_auth(tool: str) -> dict | None:
    """This tool's own credential, or None if it hasn't got one yet."""
    try:
        obj = json.loads(tool_auth_path(tool).read_text())
    except (OSError, ValueError):
        return None
    return obj if isinstance(obj, dict) and obj.get("token") else None


def save_tool_auth(tool: str, obj: dict) -> None:
    """Write atomically at 0600 — a torn credential file is a bricked integration,
    and the temp file must never exist world-readable even for an instant."""
    p = tool_auth_path(tool)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(f".{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def clear_tool_auth(tool: str) -> None:
    try:
        tool_auth_path(tool).unlink()
    except OSError:
        pass
