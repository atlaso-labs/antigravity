"""Client-side half of the retrieval_event block_emitted echo (spec 3440342a §c).

The server mints an event id per logged recall (X-Atlaso-Recall-Event); the
client remembers it plus whether the block was actually emitted, and sends
`<event_id>:<0|1>` on the NEXT recall (X-Atlaso-Recall-Prev) — no extra round
trip, best-effort both ways. State file: ``<atlaso_dir>/retrieval_prev_event.json``.

Everything here is content-free: a server-minted uuid and one bit. Never store
or send query text, memory content, or session ids. All failures are silent —
a lost echo just leaves block_emitted NULL server-side ("unknown", by design
never a negative label).
"""
from __future__ import annotations

import json
import re

from . import config

_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _path():
    return config.atlaso_dir() / "retrieval_prev_event.json"


def store(event_id: str | None, emitted: bool) -> None:
    if not event_id or not _ID_RE.match(event_id):
        return
    try:
        _path().write_text(json.dumps({"id": event_id, "emitted": 1 if emitted else 0}))
    except Exception:
        pass


def take_pending() -> str | None:
    """Return '<event_id>:<0|1>' for the previous recall (and consume it), or
    None. Consumed on read so a settled echo is never re-sent."""
    p = _path()
    try:
        data = json.loads(p.read_text())
        p.unlink()
        eid = data.get("id", "")
        bit = 1 if data.get("emitted") else 0
        if _ID_RE.match(eid):
            return f"{eid}:{bit}"
    except Exception:
        pass
    return None
