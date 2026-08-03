"""Debounced background flush for the outbox — shared by every connector.

The WAF/outbox incident proved that syncing only at session boundaries strands
memories for hours in long-lived sessions. The fix is a per-turn detached flush,
but naive spawn-on-every-Stop wastes a uv cold-start per turn and lets two tools
on one machine (Claude Code + Codex share one cache) stampede each other. So:

  • should_flush()  — the capture hook asks this before spawning a detached sync:
      outbox non-empty AND no fresh sync lease AND (debounce window elapsed OR
      the queue is getting big/stale enough to force it).
  • lease()         — the sync entrypoint wraps sync_once() in this: a fresh
      lease file means another sync is already in flight → skip. Stale leases
      (crashed sync) expire on TTL.

All file-based (no daemon), so short-lived hook processes coordinate safely.
"""
from __future__ import annotations

import contextlib
import os
import time
from pathlib import Path

from . import config

LEASE_TTL = 60      # s — a sync older than this is presumed dead; lease ignored
DEBOUNCE = 30       # s — min gap between routine flushes
FORCE_AGE = 120     # s — flush regardless of debounce when the oldest item is older
FORCE_COUNT = 10    # items — flush regardless of debounce at this queue depth


def _lease_path() -> Path:
    return config.atlaso_dir() / ".syncing"


def _marker_path() -> Path:
    return config.atlaso_dir() / ".last_flush"


def _age(p: Path) -> float:
    try:
        return time.time() - p.stat().st_mtime
    except OSError:
        return float("inf")


def _parse_iso_utc(ts: str | None) -> float | None:
    """Epoch seconds for a cache timestamp ('%Y-%m-%dT%H:%M:%SZ', UTC)."""
    if not ts:
        return None
    try:
        import calendar
        return calendar.timegm(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, OverflowError):
        return None


def should_flush(cache) -> bool:
    """Decide whether the capture hook should spawn a detached sync now. Touches
    the last-flush marker when it says yes (so the debounce window starts at the
    decision, not at sync completion). Never raises."""
    try:
        counts = cache.counts()
        pending = int(counts.get("pending") or 0)
        if pending <= 0:
            return False
        if _age(_lease_path()) < LEASE_TTL:
            return False  # a sync is already in flight
        force = pending >= FORCE_COUNT
        if not force:
            oldest = _parse_iso_utc(cache.oldest_pending_at())
            if oldest is not None and (time.time() - oldest) > FORCE_AGE:
                force = True
        if not force and _age(_marker_path()) < DEBOUNCE:
            return False
        with contextlib.suppress(OSError):
            _marker_path().parent.mkdir(parents=True, exist_ok=True)
            _marker_path().touch()
        return True
    except Exception:
        return False  # never let flush heuristics break a turn


def _try_acquire(p: Path) -> bool:
    """ATOMIC lease acquisition (O_CREAT|O_EXCL — no check-then-write window, so
    two hook processes can never both win). A stale lease (crashed sync, older
    than LEASE_TTL) is unlinked once and acquisition retried."""
    for _ in range(2):
        try:
            fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(fd, str(os.getpid()).encode())
            finally:
                os.close(fd)
            return True
        except FileExistsError:
            if _age(p) < LEASE_TTL:
                return False  # a live sync holds it
            with contextlib.suppress(OSError):
                p.unlink()  # stale — remove and retry once
        except OSError:
            return True  # can't lease at all → proceed (worst case: double sync, idempotent)
    return False


@contextlib.contextmanager
def lease():
    """Context manager for the sync entrypoint. Yields False (skip the sync) when
    another sync holds a fresh lease; otherwise takes the lease atomically and
    releases it on exit. Crash-safe: an orphaned lease expires via LEASE_TTL."""
    p = _lease_path()
    with contextlib.suppress(OSError):
        p.parent.mkdir(parents=True, exist_ok=True)
    if not _try_acquire(p):
        yield False
        return
    try:
        yield True
    finally:
        with contextlib.suppress(OSError):
            p.unlink()
