"""Content-free stage timing for the recall hook (recall r5).

One line per recall hook process, appended to ``<atlaso dir>/health/recall-timing.log``:

    1793000000 claude-code recall timing v=1 boot=146 imports=125 client=52 tcp=3 tls=511 ent=266 recall=628 net=1422 local=0 total=1809 net_end=ok src=server end=ok

Stage names come from ``STAGES`` and carry whole milliseconds; outcome keys come from ``OUTCOMES`` and carry one of
their fixed tokens. Nothing else can be written: every field is checked against those lists and a strict pattern
before the line is built, so no caller can put prompt text, memory text, ids, paths or payloads in the file.

Stages (a stage that did not happen is left out):
  boot     the shell guard starting the hook to this package's first line (needs bash 5's EPOCHREALTIME, which the
           guard exports as ATLASO_HOOK_T0; absent on bash 3.2)
  imports  this package's first line to the hook's main body starting
  client   building the client (credential, local cache open, HTTP client)
  tcp/tls  opening the connection to the brain (DNS is inside tcp)
  ent      the /v1/entitlement round trip, when the client had to ask
  recall   the /v1/recall round trip (request sent to response read; server time included)
  net      wall clock of the whole brain half, as the hook's deadline saw it
  local    the local cache search, when the local floor answered
  total    this package's first line to the hook's output being written (or to the deadline exit)
Outcomes: net_end ok|deadline|no_time|error|local_only, src server|local, end ok|deadline.

Why its own file: ``hooks.log`` holds the skip counters ``atlaso status`` reads for the last 24 h, and it rotates at
64 KiB. One timing line per prompt in that file would rotate skip history away within a day of heavy use. This file
rotates the same way (64 KiB, one ``.1``), so it keeps about the last 800 prompts. ``ATLASO_HOOK_TIMING=0`` turns it
off. Best-effort throughout: nothing here raises into a hook.
"""
from __future__ import annotations

import os
import re
import threading
import time
from typing import Any, Iterator
from contextlib import contextmanager

from . import config

STAGES = ("boot", "imports", "client", "tcp", "tls", "ent", "recall", "net", "local", "total")
OUTCOMES = {
    "net_end": ("ok", "deadline", "no_time", "error", "local_only"),
    "src": ("server", "local"),
    "end": ("ok", "deadline"),
}
_LOG_MAX_BYTES = 65536
_TOKEN = re.compile(r"^[a-z0-9_-]{1,32}$")
_MAX_MS = 600_000

_lock = threading.Lock()
_rec: dict[str, Any] | None = None


def enabled() -> bool:
    return os.environ.get("ATLASO_HOOK_TIMING", "1").strip().lower() not in ("0", "off", "false", "no")


def active() -> bool:
    return _rec is not None


def begin(tool: str | None, event: str, started: float) -> None:
    """Start recording for this hook process. ``started`` is the monotonic time the connector package was first
    imported (its STARTED)."""
    global _rec
    if not enabled():
        return
    try:
        now = time.monotonic()
        rec: dict[str, Any] = {"tool": tool or "unknown", "event": event, "started": started, "ms": {}, "tok": {},
                               "done": False}
        rec["ms"]["imports"] = (now - started) * 1000
        boot = _boot_ms(os.environ.get("ATLASO_HOOK_T0", ""), now, started)
        if boot is not None:
            rec["ms"]["boot"] = boot
        with _lock:
            _rec = rec
    except Exception:
        pass


def _boot_ms(t0: str, now: float, started: float) -> float | None:
    """Milliseconds from the guard's EPOCHREALTIME stamp to STARTED, or None. bash prints EPOCHREALTIME with the
    locale's decimal separator ("1793000000,123456" under a comma locale), so a comma is accepted."""
    try:
        t = float(t0.strip().replace(",", "."))
    except ValueError:
        return None
    boot = (time.time() - (now - started) - t) * 1000
    return boot if 0 <= boot < _MAX_MS else None


def add(stage: str, ms: float) -> None:
    """Add ``ms`` to a stage (stages that run twice, such as two requests' TLS, sum)."""
    if _rec is None or stage not in STAGES:
        return
    with _lock:
        if _rec is not None and not _rec["done"]:
            _rec["ms"][stage] = _rec["ms"].get(stage, 0.0) + max(0.0, float(ms))


def note(key: str, value: str) -> None:
    """Record one outcome token. The first value set for a key wins."""
    if _rec is None or value not in OUTCOMES.get(key, ()):
        return
    with _lock:
        if _rec is not None and not _rec["done"]:
            _rec["tok"].setdefault(key, value)


@contextmanager
def span(stage: str) -> Iterator[None]:
    t = time.monotonic()
    try:
        yield
    finally:
        add(stage, (time.monotonic() - t) * 1000)


def http_kwargs(kind: str) -> dict[str, Any]:
    """Keyword arguments for one httpx request: an httpcore trace callback that adds the connection set-up to
    tcp/tls and the request's own round trip (headers sent to body read) to ``kind``. Empty when not recording,
    so the request is exactly as before."""
    if _rec is None or kind not in STAGES:
        return {}
    marks: dict[str, float] = {}

    def trace(name: str, _info: dict) -> None:
        try:
            now = time.monotonic()
            if name == "connection.connect_tcp.started":
                marks["tcp"] = now
            elif name == "connection.connect_tcp.complete" and "tcp" in marks:
                add("tcp", (now - marks.pop("tcp")) * 1000)
            elif name == "connection.start_tls.started":
                marks["tls"] = now
            elif name == "connection.start_tls.complete" and "tls" in marks:
                add("tls", (now - marks.pop("tls")) * 1000)
            elif name == "http11.send_request_headers.started":
                marks["req"] = now
            elif name == "http11.receive_response_body.complete" and "req" in marks:
                add(kind, (now - marks.pop("req")) * 1000)
        except Exception:
            pass

    return {"extensions": {"trace": trace}}


def _path():
    return config.atlaso_dir() / "health" / "recall-timing.log"


def format_line(tool: str, event: str, ms: dict[str, float], tok: dict[str, str], epoch: int) -> str | None:
    """The line, or None when any field fails the allow-lists (then nothing is written)."""
    if not (_TOKEN.match(tool) and _TOKEN.match(event)):
        return None
    parts = [str(int(epoch)), tool, event, "timing", "v=1"]
    for st in STAGES:
        if st in ms:
            v = int(round(ms[st]))
            if not 0 <= v <= _MAX_MS:
                return None
            parts.append(f"{st}={v}")
    for key, allowed in OUTCOMES.items():
        if key in tok:
            if tok[key] not in allowed:
                return None
            parts.append(f"{key}={tok[key]}")
    return " ".join(parts)


def flush(end: str) -> None:
    """Write this process's line once (``end`` = ok | deadline). Never raises."""
    global _rec
    try:
        with _lock:
            rec = _rec
            if rec is None or rec["done"]:
                return
            rec["done"] = True
            ms = dict(rec["ms"])
            tok = dict(rec["tok"])
        ms["total"] = (time.monotonic() - rec["started"]) * 1000
        if end in OUTCOMES["end"]:
            tok["end"] = end
        line = format_line(rec["tool"], rec["event"], ms, tok, int(time.time()))
        if line is None:
            return
        p = _path()
        p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            if p.stat().st_size > _LOG_MAX_BYTES:
                os.replace(p, p.with_name(p.name + ".1"))
        except OSError:
            pass
        fd = os.open(str(p), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, (line + "\n").encode("ascii"))
        finally:
            os.close(fd)
    except Exception:
        pass


def reset() -> None:
    """Tests only: forget any recording."""
    global _rec
    with _lock:
        _rec = None
