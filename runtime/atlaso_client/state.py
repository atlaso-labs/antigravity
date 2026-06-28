"""Persisted cloud-link state for the thin client.

A device/tool is either CLOUD-LINKED (valid token + an entitled tool) or
LOCAL-ONLY (no token, a revoked/expired token, or a tool that isn't entitled on
the current plan). LOCAL-ONLY is PERSISTED so the client never hammers a dead
token (or re-checks entitlement) on every turn, and so a connector can show a
one-time "running local-only" notice. A successful ``atlaso connect`` clears it.

Stored next to auth.json + cache.db (``atlaso_dir()/cloud_state.json``), so it
follows the same global-vs-project resolution as the rest of the client.

Memories are NEVER affected by this state — local recall/capture keep working in
LOCAL-ONLY; only cloud sync pauses until the device is re-linked.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Optional

from . import config

# How long a verified verdict (linked or not_entitled) is trusted before the
# client re-checks entitlement with the brain. Keeps the hot path network-free
# between checks while still picking up a dashboard plan/active-tool change.
ENTITLEMENT_TTL = int(os.environ.get("ATLASO_ENTITLEMENT_TTL", "600"))  # 10 min

LINKED = "linked"
LOCAL_ONLY = "local_only"

# reasons for LOCAL_ONLY
REVOKED = "revoked"              # token rejected by a reachable brain (disconnected/expired)
NOT_ENTITLED = "not_entitled"   # tool isn't the active tool on a free plan
NOT_CONNECTED = "not_connected"  # never linked (no token)


def _path() -> Path:
    override = os.environ.get("ATLASO_STATE")
    return Path(override).expanduser() if override else config.atlaso_dir() / "cloud_state.json"


def default() -> dict:
    """An unverified (stale) LINKED verdict for no particular identity — the
    safe baseline that forces re-verification and shows no notice."""
    return {"mode": LINKED, "reason": None, "since": 0, "checked_at": 0,
            "active_tool": None, "tool": None, "device_id": None, "grace": None}


def get() -> dict:
    """Current state: {mode, reason, since, checked_at, active_tool, tool,
    device_id}. Defaults to an unverified (stale) LINKED when no file exists, so
    the next op re-verifies. `tool`/`device_id` scope the verdict to the identity
    that produced it (a different tool/device must re-verify, not inherit it)."""
    try:
        obj = json.loads(_path().read_text())
        if isinstance(obj, dict) and obj.get("mode"):
            base = default()
            base.update(obj)
            return base
    except (OSError, ValueError):
        pass
    return default()


def _write(obj: dict) -> None:
    p = _path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".cloud_state.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(obj, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, p)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError:
        pass  # best-effort; a missing state file just means "re-verify next time"


def set_local_only(reason: str, *, active_tool: Optional[str] = None,
                   tool: Optional[str] = None, device_id: Optional[str] = None) -> None:
    """Mark the device LOCAL-ONLY for the given (tool, device_id). Preserves `since`
    if we were ALREADY local-only for the SAME reason + identity, so a connector's
    one-time notice isn't re-shown every turn."""
    cur = get()
    now = int(time.time())
    same = (cur.get("mode") == LOCAL_ONLY and cur.get("reason") == reason
            and cur.get("tool") == tool and cur.get("device_id") == device_id)
    since = (cur.get("since") or now) if same else now
    # A local-only verdict means we're past the grace window (or never in one) —
    # clear any stale grace banner.
    _write({"mode": LOCAL_ONLY, "reason": reason, "since": since,
            "checked_at": now, "active_tool": active_tool,
            "tool": tool, "device_id": device_id, "grace": None})


def set_linked(*, tool: Optional[str] = None, device_id: Optional[str] = None,
               grace: Optional[dict] = None) -> None:
    """Mark (tool, device_id) CLOUD-LINKED + verified now (resets any local-only).
    `grace` carries the downgrade-grace banner state ({in_grace, days_left,
    tools_connected}) when the user is in a post-downgrade grace window, else
    None — surfaced via cloud_mode() for the connector notice."""
    _write({"mode": LINKED, "reason": None, "since": 0,
            "checked_at": int(time.time()), "active_tool": None,
            "tool": tool, "device_id": device_id, "grace": grace})


def invalidate() -> None:
    """Forget any persisted verdict (e.g. on reconnect) so the next op RE-VERIFIES
    entitlement from scratch — never grants a stale free pass to a new credential."""
    try:
        _path().unlink()
    except OSError:
        pass


def matches(st: dict, tool: Optional[str], device_id: Optional[str]) -> bool:
    """Is this verdict for the SAME identity asking now? A different tool/device
    must not inherit another's verdict."""
    return st.get("tool") == tool and st.get("device_id") == device_id


def is_fresh(st: dict) -> bool:
    """Has the current verdict been verified within the TTL? Malformed → not fresh."""
    try:
        return (int(time.time()) - int(st.get("checked_at") or 0)) < ENTITLEMENT_TTL
    except (TypeError, ValueError):
        return False
