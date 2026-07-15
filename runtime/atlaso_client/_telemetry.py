"""Always-on, content-free failure telemetry for the thin client.

The WAF incident proved that ATLASO_DEBUG-gated logging is not enough: sync died
silently for hours and only a forensic dig found why. This module writes ONE small
JSON line per notable transport event to ``atlaso_dir()/telemetry.log`` — always
on, no opt-in.

STRICT RULE: never any memory content, queries, tokens, or user text. Only
transport facts: timestamp, endpoint, classifier, HTTP status, Cf-Ray (Cloudflare
request id — the single most useful fact when diagnosing an edge block),
content-type, item client_id (an opaque uuid), and queue counts.

Best-effort: any failure here is swallowed — telemetry must never break a turn.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from . import config

_MAX_BYTES = 1_000_000   # rotate when the log exceeds ~1 MB
_KEEP_LINES = 300        # keep the newest lines on rotation


def _path() -> Path:
    override = os.environ.get("ATLASO_TELEMETRY")
    return Path(override).expanduser() if override else config.atlaso_dir() / "telemetry.log"


def log(endpoint: str, kind: str, **facts: object) -> None:
    """Append one event line. `kind` is the classifier: e.g. "edge_block",
    "auth_rejected", "not_entitled", "transient", "quarantined", "push_ok".
    Extra facts (status, cf_ray, content_type, client_id, pending, ...) ride along
    verbatim — callers must pass only content-free values."""
    try:
        line = json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ep": endpoint,
            "kind": kind,
            **{k: v for k, v in facts.items() if v is not None},
        }, separators=(",", ":"))
    except (TypeError, ValueError):
        return
    try:
        p = _path()
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            if p.stat().st_size > _MAX_BYTES:
                tail = p.read_text(errors="replace").splitlines()[-_KEEP_LINES:]
                p.write_text("\n".join(tail) + "\n")
        except OSError:
            pass
        with p.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass  # telemetry is best-effort, never a failure source itself
