"""Hook deadlines inside the Python process (rung "hooks never hang", 2026-09-30).

The shell guard (hooks/_guard.sh) kills a hook process at its wall-clock budget and throws its
stdout away. This module makes the process finish BEFORE that, so the user still gets what
could be done in time:

* ``run_hook(main, ...)`` runs a hook's ``main`` in a daemon thread with stdout captured.
  Finished inside ``ATLASO_HOOK_BUDGET`` minus a margin → its output is written. Not
  finished → nothing is written (never a partial block), one content-free skip line is
  recorded, and the process exits 0 at once. That bounds what no socket timeout can:
  getaddrinfo (DNS has no timeout in httpx), a server that trickles one byte at a time
  (httpx's timeout applies to each read), a held file lock, a stdin that never closes.
* ``call_within(fn, budget)`` bounds one piece of work, such as the brain round trip inside
  recall, so the caller can still fall back to the local cache inside the hook budget.
* ``record(tool, event, reason)`` appends ``<epoch> <tool> <event> <reason>`` to
  ``<atlaso dir>/health/hooks.log``: the same file and format the shell guard writes.
  Never text, ids, paths or payloads. ``atlaso status`` reads it.

Nothing here retries, sleeps or waits on a lock.
"""
from __future__ import annotations

import io
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

from . import config

#: The brain round trip inside a recall hook (entitlement check included). The rest of the
#: 2.5 s hook budget is interpreter start-up, the local fallback and rendering.
NETWORK_BUDGET_S = 1.5
#: Finish this far inside the shell guard's deadline, so our own exit wins the race.
_MARGIN_S = 0.3
#: Kept back from the brain call for the local fallback, rendering and writing the output.
_LOCAL_RESERVE_S = 0.35
#: The monotonic time this process must be done by, set by run_hook(); None outside a hook.
_DEADLINE: float | None = None
_LOG_MAX_BYTES = 65536
_TOKEN = re.compile(r"^[a-z0-9_-]{1,32}$")


def hook_budget(default: float) -> float:
    """The budget the shell guard gave this process (ATLASO_HOOK_BUDGET), else ``default``."""
    try:
        b = float(os.environ.get("ATLASO_HOOK_BUDGET", ""))
    except ValueError:
        return default
    return b if b > 0 else default


def _log_path() -> Path:
    return config.atlaso_dir() / "health" / "hooks.log"


def record(tool: str | None, event: str, reason: str) -> None:
    """One content-free skip line. Best-effort: never raises. Every field must be a short
    lowercase token, so no caller can smuggle text into the file."""
    fields = [tool or "unknown", event, reason]
    if not all(_TOKEN.match(f) for f in fields):
        return
    try:
        p = _log_path()
        p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            if p.stat().st_size > _LOG_MAX_BYTES:
                os.replace(p, p.with_name(p.name + ".1"))
        except OSError:
            pass
        fd = os.open(str(p), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, f"{int(time.time())} {' '.join(fields)}\n".encode("ascii"))
        finally:
            os.close(fd)
    except Exception:
        pass


def skipped_since(since_epoch: float) -> dict[str, int]:
    """Counts of skip lines at or after ``since_epoch``, keyed ``"<tool> <event> <reason>"``."""
    out: dict[str, int] = {}
    p = _log_path()
    for path in (p.with_name(p.name + ".1"), p):
        try:
            lines = path.read_text(encoding="ascii", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) != 4:
                continue
            try:
                ts = int(parts[0])
            except ValueError:
                continue
            if ts >= since_epoch:
                key = " ".join(parts[1:])
                out[key] = out.get(key, 0) + 1
    return out


def network_budget(default: float) -> float:
    """Seconds the brain call may take now: ``default``, cut so the local fallback still fits
    inside the hook deadline. 0 means there is no time for the network at all."""
    if _DEADLINE is None:
        return default
    left = _DEADLINE - time.monotonic() - _LOCAL_RESERVE_S
    return max(0.0, min(default, left))


def call_within(fn: Callable[[], Any], budget_s: float) -> tuple[bool, Any]:
    """Run ``fn`` in a daemon thread for at most ``budget_s``. Returns (True, result) when it
    finished, (False, None) when it did not. An exception inside ``fn`` is re-raised here.
    An abandoned call keeps running in the background until the process exits; it must not
    own anything the caller then uses (no shared SQLite connection)."""
    box: dict[str, Any] = {}

    def body() -> None:
        try:
            box["value"] = fn()
        except BaseException as e:  # noqa: BLE001 - handed back to the caller
            box["error"] = e

    t = threading.Thread(target=body, name="atlaso-bounded", daemon=True)
    t.start()
    t.join(max(0.0, budget_s))
    if t.is_alive():
        return False, None
    if "error" in box:
        raise box["error"]
    return True, box.get("value")


def run_hook(main: Callable[[], Any], *, tool: str | None, event: str,
             default_budget: float = 2.5, started: float | None = None) -> int:
    """Run a hook's ``main`` under the process deadline; see the module docstring.
    ``started`` is the monotonic time the process began (the connector package records it
    on import), so start-up counts against the budget. Always returns 0 (or does not
    return: ``os._exit(0)`` on a missed deadline)."""
    global _DEADLINE
    now = time.monotonic()
    _DEADLINE = min(now, started if started is not None else now) \
        + max(0.2, hook_budget(default_budget) - _MARGIN_S)
    budget = max(0.05, _DEADLINE - now)
    real = sys.stdout
    buf = io.StringIO()
    box: dict[str, Any] = {}

    def body() -> None:
        try:
            box["rc"] = main()
        except BaseException:  # noqa: BLE001 - a hook never breaks the turn
            box["rc"] = 0

    sys.stdout = buf
    try:
        t = threading.Thread(target=body, name="atlaso-hook", daemon=True)
        t.start()
        t.join(budget)
    finally:
        sys.stdout = real
    if t.is_alive():
        record(tool, event, "deadline")
        try:
            real.flush()
        finally:
            os._exit(0)
    try:
        real.write(buf.getvalue())
        real.flush()
    except Exception:
        pass
    if any(th.daemon and th.is_alive() and th.name == "atlaso-bounded"
           for th in threading.enumerate()):
        # An abandoned brain call is still in flight. Do not let interpreter shutdown wait
        # on, or tear down under, it: the output is out, leave now.
        os._exit(0)
    return 0
