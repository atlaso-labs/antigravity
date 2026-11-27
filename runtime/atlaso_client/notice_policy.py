"""Session-start notices shared by the Python connectors (Claude Code, Codex, Grok Build;
Antigravity shows the same lines through its per-prompt recall hook).

Each connector owns its hook output; this module owns WHAT to say, HOW OFTEN, and the
markers that remember it, so the wording is identical across tools.

OFFLINE NOTICE (ATLASO_OFFLINE_NOTICE_REPEAT, default on). While local-only it is shown at
session start, at most once per repeat period, until the device is linked again:
  * sign-in expired (says when a browser window may open to approve the device)   daily
  * sign-in no longer valid / needs connecting again                             daily
  * signed out (most likely on purpose: Connections, atlaso disconnect)          weekly
  * this tool removed from the account (says how to stop the reminder)           weekly
  * an old account setting                                                       weekly
Weekly reminders stop after WEEKLY_MAX showings per episode. The shared sign-in (expired /
signed out) is ONE device-wide notice: one date (the first rejection of that token, whichever
tool saw it) and one timer, so several tools on a device don't each show it. Off
(0/off/false/no): once per local-only episode, as before.

HELD NOTES. While linked, at most once a day: how many older notes `atlaso held` would add
through this tool, quiet for 30 days after the user declined that exact set (held --decline).
After an upload of held notes: one line saying how many were added.

All copy is plain words: no em dashes (client/tests/test_no_em_dash_copy.py).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Callable, Optional

DAY = 86400
WEEK = 7 * DAY

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

WEEKLY_MAX = 4
DECLINE_QUIET_S = 30 * DAY

_KEPT = ("Your notes are safe on this device. After you reconnect, Atlaso uploads them, or "
         "asks first about any older ones.")


def repeat_on() -> bool:
    """ATLASO_OFFLINE_NOTICE_REPEAT (default on)."""
    return os.environ.get("ATLASO_OFFLINE_NOTICE_REPEAT", "1").strip().lower() not in (
        "0", "off", "false", "no")


def format_day(ts: Any) -> Optional[str]:
    """A unix time as a local calendar day, '24 Oct 2026' (portable: no %-d)."""
    try:
        t = time.localtime(float(ts))
    except (TypeError, ValueError, OverflowError, OSError):
        return None
    if float(ts) <= 0:
        return None
    return f"{t.tm_mday} {_MONTHS[t.tm_mon - 1]} {t.tm_year}"


def format_iso_day(iso: Any) -> Optional[str]:
    """A cache timestamp ('YYYY-MM-DDT..Z', UTC) as its day, '24 Oct 2026'."""
    if not isinstance(iso, str) or len(iso) < 10:
        return None
    try:
        y, m, d = int(iso[0:4]), int(iso[5:7]), int(iso[8:10])
    except ValueError:
        return None
    if not (1 <= m <= 12 and 1 <= d <= 31):
        return None
    return f"{d} {_MONTHS[m - 1]} {y}"


def _sign_in() -> tuple[Optional[str], Optional[int], bool, Optional[str]]:
    """(kind, device-wide stopped-since, browser may open, token fingerprint) for the shared
    sign-in, from _reconnect. Never raises."""
    try:
        from . import _reconnect
        rec = _reconnect.rejected_shared() or {}
        return (_reconnect.sign_in_kind(), _reconnect.stopped_since(), False, rec.get("fp"))
    except Exception:  # noqa: BLE001
        return None, None, False, None


def offline_spec(mode: dict, tool_label: str, tool: Optional[str] = None) -> Optional[dict]:
    """The local-only banner for this verdict: {msg, period, max, scope, key}, else None.
    scope "device" = the shared sign-in (one date, one timer per device); "tool" = this tool.
    A device that was never connected (not_connected) stays quiet: the first-run flow."""
    if not isinstance(mode, dict) or mode.get("mode") != "local_only":
        return None
    reason, cause = mode.get("reason"), mode.get("cause")
    since = mode.get("since")
    scope, key = "tool", offline_key(mode)

    def on(ts: Any) -> str:
        day = format_day(ts)
        return f" on {day}" if day else ""

    if reason in ("revoked", "auth_rejected", "reconnect_required"):
        if cause in ("credential_revoked", "tool_removed"):
            return {"msg": (f"Atlaso is not syncing {tool_label} on this device because it was "
                            "removed from your Atlaso account (in Connections, or with atlaso "
                            "unlink). Your notes stay on this device. To sync it again, run "
                            "atlaso setup. To stop this reminder, remove the Atlaso plugin "
                            f"from {tool_label}."),
                    "period": WEEK, "max": WEEKLY_MAX, "scope": scope, "key": key}
        if reason == "reconnect_required":
            return {"msg": (f"Atlaso stopped syncing on this device{on(since)} because it needs "
                            f"to be connected to your Atlaso account again. Run atlaso connect. "
                            f"{_KEPT}"),
                    "period": DAY, "max": None, "scope": scope, "key": key}
        kind, stopped, _, fp = (_sign_in() if (cause == "invalid_token"
                                               and mode.get("cred") == "shared")
                                else (None, None, False, None))
        if kind in ("expired", "signed_out"):
            when = on(stopped or since)
            dkey = f"signin:{fp}:{kind}"
            if kind == "expired":
                try:
                    from . import _reconnect
                    browser = _reconnect.may_reconnect(tool)
                except Exception:  # noqa: BLE001
                    browser = False
                fix = ("A browser window may open so you can approve this device again, or run "
                       "atlaso connect." if browser else
                       "Run atlaso connect to approve this device again.")
                return {"msg": (f"Atlaso stopped syncing on this device{when} because its "
                                f"sign-in expired. {fix} {_KEPT}"),
                        "period": DAY, "max": None, "scope": "device", "key": dkey}
            return {"msg": (f"Atlaso stopped syncing on this device{when} because it was signed "
                            "out of your Atlaso account (in Connections, or with atlaso "
                            f"disconnect). To sync again, run atlaso connect. {_KEPT}"),
                    "period": WEEK, "max": WEEKLY_MAX, "scope": "device", "key": dkey}
        return {"msg": (f"Atlaso stopped syncing on this device{on(since)} because its sign-in is "
                        f"no longer valid. Run atlaso connect to sign in again. {_KEPT}"),
                "period": DAY, "max": None, "scope": scope, "key": key}
    if reason == "not_entitled":
        return {"msg": (f"Atlaso isn't syncing {tool_label} on this device because of an old "
                        "account setting. Run atlaso setup; if that doesn't fix it, email "
                        "support@atlaso.ai."),
                "period": WEEK, "max": WEEKLY_MAX, "scope": scope, "key": key}
    return None


def offline_banner(mode: dict, tool_label: str,
                   tool: Optional[str] = None) -> Optional[tuple[str, int]]:
    """(message, repeat period) for a LOCAL-ONLY verdict, else None."""
    spec = offline_spec(mode, tool_label, tool)
    return (spec["msg"], spec["period"]) if spec else None


def _signin_marker() -> Path:
    from . import config
    return config.atlaso_dir() / "notice_signin"


def offline_due(mode: dict, tool_label: str, tool: Optional[str], tool_marker: Path, *,
                now: Optional[float] = None) -> Optional[tuple[str, Callable[[], None]]]:
    """(message, acknowledge) when the local-only banner is due now, else None. The shared
    sign-in uses the device-wide marker; everything else the connector's own marker."""
    spec = offline_spec(mode, tool_label, tool)
    if not spec:
        return None
    marker = _signin_marker() if spec["scope"] == "device" else tool_marker
    if not is_due(marker, spec["key"], spec["period"], now=now, max_shows=spec["max"]):
        return None
    return spec["msg"], (lambda: write_marker(marker, spec["key"]))


def offline_key(mode: dict) -> str:
    """What makes an offline banner 'the same episode': reason, cause and the day sync
    stopped. A new reason or a new spell is a new episode, shown at once."""
    return f"offline:{mode.get('reason')}:{mode.get('cause') or ''}:{mode.get('since') or 0}"


# ── marker: {key, at} (an older plain-text marker reads as key-only, shown at=0) ──────────
def _marker_obj(path: Path) -> dict:
    try:
        raw = path.read_text().strip()
    except OSError:
        return {}
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict) and isinstance(obj.get("key"), str):
            return obj
    except ValueError:
        pass
    return {"key": raw, "at": 0}


def read_marker(path: Path) -> tuple[Optional[str], float]:
    """(episode key, last shown unix time); an older plain-text marker reads as (text, 0)."""
    obj = _marker_obj(path)
    at = obj.get("at")
    return obj.get("key"), float(at) if isinstance(at, (int, float)) else 0.0


def write_marker(path: Path, key: str, *, now: Optional[float] = None) -> None:
    """Record a showing of episode `key` (and count showings of the same episode)."""
    obj = _marker_obj(path)
    n = obj.get("n") if obj.get("key") == key and isinstance(obj.get("n"), int) else 0
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"key": key, "at": int(time.time() if now is None else now),
                                    "n": n + 1}))
    except OSError:
        pass


def is_due(path: Path, key: str, period: Optional[int], *, now: Optional[float] = None,
           max_shows: Optional[int] = None) -> bool:
    """Due when never shown for this episode; or, with a repeat period and the repeat switch
    on, when last shown `period` ago or more and shown fewer than `max_shows` times."""
    obj = _marker_obj(path)
    if obj.get("key") != key:
        return True
    if not period or not repeat_on():
        return False
    n = obj.get("n") if isinstance(obj.get("n"), int) else 1
    if max_shows is not None and n >= max_shows:
        return False
    at = obj.get("at")
    at = float(at) if isinstance(at, (int, float)) else 0.0
    now = time.time() if now is None else now
    return now - at >= period


# ── held notes uploaded (one time) ─────────────────────────────────────────────────────────
def held_message(note: dict) -> Optional[str]:
    n = note.get("n") if isinstance(note, dict) else None
    if not isinstance(n, int) or n <= 0:
        return None
    first, last = format_iso_day(note.get("first")), format_iso_day(note.get("last"))
    if first and last and first != last:
        span = f" from {first} to {last}"
    elif first or last:
        span = f" from {first or last}"
    else:
        span = ""
    if n == 1:
        return f"Atlaso added 1 note{span} to your Atlaso account. It was waiting on this device."
    return (f"Atlaso added {n} notes{span} to your Atlaso account. They were waiting on this "
            "device.")


def held_banner(client: Any) -> Optional[tuple[str, Callable[[], None]]]:
    """(message, acknowledge) when this client's tool has a finished held-notes upload to
    report, else None. The acknowledgement consumes exactly the record shown."""
    cache, tool = getattr(client, "cache", None), getattr(client, "tool", None)
    if cache is None or not tool or not hasattr(cache, "held_notice"):
        return None
    got = cache.held_notice(tool)
    if not got:
        return None
    note, raw = got
    msg = held_message(note)
    if not msg:
        return None
    path = getattr(cache, "path", None)

    def ack() -> None:
        # the hook acknowledges after client.close(): use the file, not the closed connection
        from .cache import ack_held_notice
        if path is not None:
            ack_held_notice(path, tool, raw)

    return msg, ack


# ── held notes waiting for the user's OK (at most once a day) ─────────────────────────────
def held_legacy_message(n: int, first: Any, last: Any) -> Optional[str]:
    if not isinstance(n, int) or n <= 0:
        return None
    a, b = format_iso_day(first), format_iso_day(last)
    span = f" from {a} to {b}" if a and b and a != b else (f" from {a or b}" if (a or b) else "")
    noun, verb, them = ("note", "is", "it") if n == 1 else ("notes", "are", "them")
    return (f"Atlaso: {n} older {noun}{span} {verb} saved only on this device. To add {them} to "
            "your Atlaso account, run: atlaso held")


def _declined_path() -> Path:
    from . import config
    return config.atlaso_dir() / "held_declined.json"


def read_declined() -> dict:
    try:
        obj = json.loads(_declined_path().read_text())
        return obj if isinstance(obj, dict) else {}
    except (OSError, ValueError):
        return {}


def record_declined(tool: str, snapshot: str, *, now: Optional[float] = None) -> int:
    """The user said "not now" to exactly this held set for `tool`. Returns quiet-until."""
    t = int(time.time() if now is None else now)
    obj = read_declined()
    obj[tool] = {"snapshot": snapshot, "at": t}
    p = _declined_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj))
    return t + DECLINE_QUIET_S


def declined_quiet(tool: str, snapshot: Optional[str], *, now: Optional[float] = None) -> bool:
    """Quiet while the user's decline of this exact set is under 30 days old."""
    d = read_declined().get(tool)
    if not isinstance(d, dict) or not snapshot or d.get("snapshot") != snapshot:
        return False
    at = d.get("at")
    t = time.time() if now is None else now
    return isinstance(at, (int, float)) and t - at < DECLINE_QUIET_S


def held_legacy_banner(client: Any, mode: dict, *,
                       now: Optional[float] = None) -> Optional[tuple[str, Callable[[], None]]]:
    """(message, acknowledge) when this tool is cloud-linked and `atlaso held` would add older
    notes through it (the same number as status `addable` and the held preview), at most once
    a day, quiet for 30 days after a decline of that exact set; else None."""
    if not isinstance(mode, dict) or mode.get("mode") != "linked":
        return None
    tool = getattr(client, "tool", None)
    report = getattr(client, "_held_report", None)
    if not tool or not callable(report):
        return None
    from . import config

    marker = config.atlaso_dir() / f"notice_held_{tool}"
    seen, at = read_marker(marker)
    t = time.time() if now is None else now
    if seen is not None and t - at < DAY:
        return None  # at most once a day, whatever the count does meanwhile (checked first)
    rep = report()
    n = rep.get("addable") if isinstance(rep, dict) else None
    msg = held_legacy_message(n, rep.get("addable_first"), rep.get("addable_last")) if n else None
    if not msg:
        return None
    try:
        from . import held
        cache = getattr(client, "cache", None)
        snap = held.snapshot_id(cache.held_snapshot(tool), held.current_account()) \
            if cache is not None else None
    except Exception:  # noqa: BLE001
        snap = None
    if declined_quiet(tool, snap, now=t):
        return None
    key = f"held:{n}:{rep.get('addable_first')}:{rep.get('addable_last')}"
    return msg, (lambda: write_marker(marker, key))


def standard_notices(client: Any, mode: dict, tool_label: str, tool_marker: Path, *,
                     now: Optional[float] = None) -> list[tuple[str, Callable[[], None]]]:
    """Every due (message, acknowledge) a connector shows besides its grace / degraded
    banners, in order: the local-only banner, the held-notes upload line, the held reminder."""
    out: list[tuple[str, Callable[[], None]]] = []
    tool = getattr(client, "tool", None)
    for make in (lambda: offline_due(mode, tool_label, tool, tool_marker, now=now),
                 lambda: held_banner(client),
                 lambda: held_legacy_banner(client, mode, now=now)):
        try:
            got = make()
        except Exception:  # noqa: BLE001
            got = None
        if got:
            out.append(got)
    return out
