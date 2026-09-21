"""Track recall degradation: cloud-linked but server recall keeps failing.

The recall path fails OPEN — a timeout/edge-block falls back to the local
keyword floor and the turn proceeds. Correct for the turn, but invisible: a
persistent server-side problem silently downgrades every recall to commodity
keyword search with nobody told (Sep 2026 audit: weeks of degraded recall,
zero surfacing). This module keeps a tiny content-free episode file so the
SessionStart notice can tell the user once per episode.

File: ``<atlaso_dir>/recall_fallbacks.json`` — {count, first_ts, last_ts}.
A successful server recall clears it (self-healing). All best-effort: any
error is swallowed — surfacing must never break recall itself.
"""
from __future__ import annotations

import json
import secrets
import time

from . import config

# A banner-worthy episode: at least this many consecutive server-recall
# failures, the latest within this window.
EPISODE_MIN_COUNT = 3
EPISODE_FRESH_SECS = 24 * 3600


def _path():
    return config.atlaso_dir() / "recall_fallbacks.json"


def record_server_ok() -> None:
    """A server recall succeeded — the episode (if any) is over."""
    try:
        _path().unlink(missing_ok=True)
    except OSError:
        pass


def record_fallback() -> None:
    """An ONLINE recall attempt failed and we served the local floor."""
    try:
        now = int(time.time())
        try:
            d = json.loads(_path().read_text())
            existing = isinstance(d, dict) and "first_ts" in d
        except (OSError, ValueError):
            d, existing = {}, False
        # episode_id: a per-episode nonce. Identity used to be first_ts (second resolution), so an
        # episode that cleared and re-formed inside the same second inherited the previous marker key
        # and the connectors stayed silent on a genuinely new episode — exactly the flapping-edge regime
        # the notice exists for (CodeRedTeam, LabDirector cc61a3cf, deposit 525a0c84). The nonce is
        # minted ONLY when a genuinely new episode file is created, and carried unchanged for the
        # episode's life. Upgrade invariant (CodeRedTeam 5f5c9e6d / LabDirector 5a313477): a LEGACY
        # episode written by a pre-nonce client keeps its already-used first_ts identity until
        # record_server_ok() ends it — minting a nonce mid-episode changed the key under a notice that
        # had already been shown, and every connector showed it twice.
        new_d = {
            "count": int(d.get("count", 0)) + 1,
            "first_ts": int(d.get("first_ts", now)),
            "last_ts": now,
        }
        if not existing:
            new_d["episode_id"] = secrets.token_hex(8)          # genuinely new episode
        elif d.get("episode_id"):
            new_d["episode_id"] = str(d["episode_id"])           # carried unchanged
        # else: legacy episode in flight — no episode_id; episode_key() falls back to first_ts
        d = new_d
        p = _path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(d))
    except Exception:
        pass


def episode() -> dict | None:
    """The current degradation episode, when it clears the banner bar."""
    try:
        d = json.loads(_path().read_text())
        if (int(d.get("count", 0)) >= EPISODE_MIN_COUNT
                and time.time() - int(d.get("last_ts", 0)) <= EPISODE_FRESH_SECS):
            return d
    except Exception:
        pass
    return None


def episode_key(ep: dict) -> str:
    """The dedupe key every connector must use for the degraded-recall notice. One key per episode:
    the nonce when present, first_ts only for files written by pre-nonce clients."""
    return f"fallback:{ep.get('episode_id') or ep.get('first_ts')}"
