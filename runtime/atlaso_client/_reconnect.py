"""An expired sign-in leads to reconnect, not silence (ATLASO_RECONNECT_EXPIRED).

The brain's device tokens have a fixed life (server TOKEN_TTL, 90 days). When the SHARED
bearer in auth.json dies, every tool on the device falls back to local-only, and the
first-run connect flow (connect.maybe_autoconnect) used to stay skipped for good because a
token is still on disk. This module decides, from local files only, when that same
first-run flow may run again for a token that is on disk but dead.

WHAT THE SERVER TELLS US, AND WHAT IT DOES NOT. A 401 `invalid_token` means "no live token
with this hash": expired, OR deleted. Deleted happens when the user disconnects the device
(dashboard Disconnect, `atlaso disconnect`: db.revoke_device deletes every token of the
device) or unlinks a tool in a way that signs the shared bearer out. The code cannot tell
those apart. So the reconnect is offered only when the token plausibly expired
by itself (sign_in_kind): the last call the server ACCEPTED (last_ok_at) is at least the
token life ago, or, on an install that never recorded one, auth.json's age is. A token that died young was most likely removed on purpose, and stays quiet (the
notice still explains it). Every other code is never a reconnect: `credential_revoked` and
an exchange refused with `tool_revoked` mean the user removed THIS tool, and are recorded
here so this tool never reopens the browser until a successful connect.

GUARDS, all required (due()):
  * the switch is on, a token is on disk, and it is the very token that was rejected with
    `invalid_token` while presented as the SHARED bearer (fingerprint match; a new token
    after any connect makes the record moot);
  * sign_in_kind says "expired" (last_ok_at, else auth.json age, >= TOKEN_LIFE - 1 day);
  * this tool was not removed by the user on this device;
  * at most one browser flow per day, at most MAX_TRIES per dead token (never a loop);
  * the caller (maybe_autoconnect) still applies every guard of the first-run flow:
    ATLASO_NO_CONNECT, ATLASO_EXTRACTING, CI, and the in-flight `.connecting` lock.
A successful connect (connect.save_auth) deletes the record.

The record (`reconnect.json` next to auth.json, 0600) holds a 16-hex-digit SHA-256
fingerprint of the rejected token, timestamps and tool ids. Never the token.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from . import config

DAY = 86400


def _token_life_days() -> float:
    """ATLASO_TOKEN_LIFE_DAYS, parsed safely and clamped to 30..365 (default 90)."""
    try:
        v = float(os.environ.get("ATLASO_TOKEN_LIFE_DAYS", "90"))
    except (TypeError, ValueError):
        return 90.0
    if v != v:  # NaN
        return 90.0
    return min(365.0, max(30.0, v))


TOKEN_LIFE_S = int(_token_life_days() * DAY)
_SLACK_S = DAY          # clock skew and the server's own rounding
MAX_TRIES = 3           # browser flows offered per dead token, at most one a day


def enabled() -> bool:
    """ATLASO_RECONNECT_EXPIRED (default on; 0/off/false/no: a token on disk never reopens
    the connect flow, the behaviour before this module)."""
    return os.environ.get("ATLASO_RECONNECT_EXPIRED", "1").strip().lower() not in (
        "0", "off", "false", "no")


def _path() -> Path:
    return config.atlaso_dir() / "reconnect.json"


def fingerprint(token: Optional[str]) -> Optional[str]:
    if not token or not isinstance(token, str):
        return None
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def _read() -> dict:
    try:
        obj = json.loads(_path().read_text())
        return obj if isinstance(obj, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(obj: dict) -> bool:
    """Atomic write; True when the record is on disk."""
    p = _path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".reconnect.", suffix=".tmp")
        try:
            try:
                os.fchmod(fd, 0o600)
            except (AttributeError, OSError):
                pass  # Windows: no fchmod; the folder is the user's own
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(obj, f)
            os.replace(tmp, p)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError:
        return False  # no record means no automatic reconnect, never a failure
    return True


def clear() -> None:
    """A fresh credential was saved (connect.save_auth): forget every record, including the
    last accepted call (it was the old credential's)."""
    for p in (_path(), _ok_path()):
        try:
            p.unlink()
        except OSError:
            pass
    _ok_memo["at"] = 0.0


def _removed(rec: dict) -> dict:
    r = rec.get("removed")
    return r if isinstance(r, dict) else {}


def note_tool_removed(tool: Optional[str]) -> None:
    """The server said the user removed `tool` from this device (credential_revoked, or an
    exchange refused with tool_revoked). That tool never reopens the browser until a
    successful connect clears the record."""
    if not tool:
        return
    rec = _read()
    removed = _removed(rec)
    if removed.get(tool):
        return
    removed[tool] = int(time.time())
    rec["removed"] = removed
    _write(rec)


def note_rejected(*, tool: Optional[str], code: Optional[str], cred_source: Optional[str],
                  token: Optional[str]) -> None:
    """A verified AuthRejected. Only `invalid_token` for the SHARED bearer is a reconnect
    candidate; `credential_revoked` records a user removal. Never raises."""
    try:
        if code == "credential_revoked":
            note_tool_removed(tool)
            return
        fp = fingerprint(token)
        if code != "invalid_token" or cred_source != "shared" or not fp:
            return
        rec = _read()
        if rec.get("fp") == fp:
            return  # already recorded: keep its attempt history
        _write({"fp": fp, "seen_at": int(time.time()), "spawns": [],
                "removed": _removed(rec)})
    except Exception:  # noqa: BLE001 - bookkeeping must never break a turn
        pass


# ── last_ok_at: when the server last ACCEPTED this device's credential ─────────────────────
# With server-side renewal (tokens used past half-life are extended in place, the token string
# and auth.json unchanged), a token can only expire after ~TOKEN_LIFE of NO use. So when a
# success time is recorded, it decides: rejected >= TOKEN_LIFE - 1 day after the last accepted
# call = expired; sooner = signed out on purpose (disconnect, unlink). Devices from before this
# record (none written yet) fall back to auth.json's age, right for the fixed-90-day tokens they
# hold. A UTC timestamp only (`last_ok.json`), throttled to one write an hour, cleared with every
# new credential (save_auth → clear()).
_OK_WRITE_EVERY_S = 3600
_ok_memo: dict = {"at": 0.0}


def _ok_path() -> Path:
    return config.atlaso_dir() / "last_ok.json"


def _iso(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def last_ok_at() -> Optional[float]:
    """Unix time of the last recorded accepted call, or None when never recorded."""
    try:
        raw = json.loads(_ok_path().read_text()).get("last_ok_at")
        import calendar
        return float(calendar.timegm(time.strptime(raw, "%Y-%m-%dT%H:%M:%SZ")))
    except (OSError, ValueError, TypeError, AttributeError, OverflowError):
        return None


def note_ok(*, now: Optional[float] = None) -> None:
    """The server accepted this device's shared or tool credential: record when (UTC). At most
    one file write an hour per value; never raises."""
    try:
        now = time.time() if now is None else now
        if now - _ok_memo["at"] < _OK_WRITE_EVERY_S:
            return
        prev = last_ok_at()
        _ok_memo["at"] = now
        if prev is not None and 0 <= now - prev < _OK_WRITE_EVERY_S:
            return
        p = _ok_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".last_ok.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"last_ok_at": _iso(now)}, f)
            os.replace(tmp, p)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception:  # noqa: BLE001
        pass


def shared_token_age_s() -> Optional[float]:
    """How long ago the shared bearer on disk was saved: auth.json's mtime (every writer of
    a new bearer rewrites the file: connect.save_auth, the CLI). A copy or restore that
    refreshes the mtime only makes the token look younger, which keeps the reconnect quiet
    (the safe side). None when unknown."""
    try:
        return max(0.0, time.time() - config.auth_path().stat().st_mtime)
    except OSError:
        return None


def rejected_shared(auth: Optional[dict] = None) -> Optional[dict]:
    """The record for the shared bearer on disk, if THAT token was rejected with
    invalid_token, else None."""
    auth = auth if auth is not None else (config.load_auth() or {})
    rec = _read()
    fp = fingerprint(auth.get("token"))
    return rec if fp and rec.get("fp") == fp else None


def sign_in_kind(auth: Optional[dict] = None, *, now: Optional[float] = None) -> Optional[str]:
    """For the notice AND the reconnect: None when no invalid_token rejection of the shared
    bearer on disk is recorded; else "expired" or "signed_out" (most likely removed on
    purpose):
      * last_ok_at recorded: expired iff now - last_ok_at >= TOKEN_LIFE - 1 day (with renewal
        a token only expires after that long without use);
      * never recorded (an install from before last_ok_at): expired iff auth.json's age
        (mtime) >= TOKEN_LIFE - 1 day (fixed-life tokens);
      * neither known: None."""
    auth = auth if auth is not None else (config.load_auth() or {})
    if not rejected_shared(auth):
        return None
    now = time.time() if now is None else now
    last = last_ok_at()
    if last is not None:
        quiet = now - last
    else:
        age = shared_token_age_s()
        if age is None:
            return None
        quiet = age
    return "expired" if quiet >= TOKEN_LIFE_S - _SLACK_S else "signed_out"


def due(tool: Optional[str], *, now: Optional[float] = None) -> bool:
    """May the first-run connect flow run again now, for this tool, with a token on disk?
    See the module docstring for every guard. File reads only; never raises."""
    try:
        if not enabled():
            return False
        now = time.time() if now is None else now
        auth = config.load_auth() or {}
        if not auth.get("token"):
            return False
        rec = rejected_shared(auth)
        if not rec:
            return False
        if tool and tool in _removed(rec):
            return False
        if sign_in_kind(auth, now=now) != "expired":
            return False
        spawns = [t for t in rec.get("spawns") or [] if isinstance(t, (int, float))]
        if len(spawns) >= MAX_TRIES:
            return False
        if spawns and now - max(spawns) < DAY:
            return False
        return True
    except Exception:  # noqa: BLE001
        return False


def note_spawned(*, now: Optional[float] = None) -> bool:
    """Count one browser flow for the recorded dead token, BEFORE it starts (S6): True only
    when the attempt is durably recorded and reads back, so a failed write can never let the
    flow run uncounted (a loop)."""
    try:
        rec = _read()
        if not rec.get("fp"):
            return False
        spawns: list[Any] = [t for t in rec.get("spawns") or [] if isinstance(t, (int, float))]
        stamp = int(time.time() if now is None else now)
        spawns.append(stamp)
        rec["spawns"] = spawns
        if not _write(rec):
            return False
        back = _read().get("spawns") or []
        return len(back) == len(spawns) and back[-1] == stamp
    except Exception:  # noqa: BLE001
        return False


def stopped_since() -> Optional[int]:
    """When this device's shared sign-in was first rejected (one date per device and dead
    token, whichever tool saw it first), or None."""
    rec = rejected_shared()
    at = rec.get("seen_at") if rec else None
    return int(at) if isinstance(at, (int, float)) and at > 0 else None


def may_reconnect(tool: Optional[str]) -> bool:
    """Could the browser re-approval still open for this tool (ignoring the daily spacing)?
    The notice says so only then."""
    try:
        if not enabled() or sign_in_kind() != "expired":
            return False
        rec = rejected_shared() or {}
        if tool and tool in _removed(rec):
            return False
        spawns = [t for t in rec.get("spawns") or [] if isinstance(t, (int, float))]
        return len(spawns) < MAX_TRIES
    except Exception:  # noqa: BLE001
        return False
