"""Render the recalled-memory injection block — shared by every connector.

A plain, branded block: the brand fence top and bottom, a short "whose notes,
from when" line, then one bullet per note. No "untrusted data" warning and no
instructions — the model decides how to use it. Driven by the server's /v1/recall
response (which carries per-result scope + conflict info). Recall is queried
EVIDENCE (distinct from the ambient "back of your mind" orientation block);
conflict peers are summarized as a COUNT so internal deposit ids never leak.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

_YEAR_AFTER_DAYS = 335  # ~11 months: older notes carry the year, recent ones do not
# Fixed English abbreviations (never strftime('%b'), which follows the process locale);
# the TypeScript mirrors (tools/cursor, tools/opencode lib/render.ts) use the same table.
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_FENCE_RE = re.compile(r"(?i)=*\s*(?:END\s+)?ATLASO\s+(?:MEMORY|ORIENTATION)[^\n]*")


def _sanitize(s: str) -> str:
    return _FENCE_RE.sub("[fence]", " ".join((s or "").split()))


def _date_label(created_at: object, now: datetime) -> str | None:
    """'Aug 14' (UTC calendar day, English month, no zero pad); 'Aug 14 2025' when the
    note is more than ~11 months older than ``now``. None when the server sent no or a
    malformed created_at (an older brain): the line renders undated, never an error.
    A timestamp without an offset is read as UTC (the server always sends UTC)."""
    if not isinstance(created_at, str) or not created_at:
        return None
    try:
        dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    dt = (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    now = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    label = f"{_MONTHS[dt.month - 1]} {dt.day}"
    if (now - dt).days > _YEAR_AFTER_DAYS:
        label += f" {dt.year}"
    return label


def undated_first(lines: list[tuple[bool, str]]) -> list[str]:
    """Stable partition of rendered ``(dated, line)`` pairs: UNDATED lines first,
    then dated lines, each group in recall order. A line is undated when the
    server could not justify an original statement time (null ``created_at``), so
    it is never placed where a reader would read it as the newest note."""
    return [line for dated, line in lines if not dated] + [line for dated, line in lines if dated]


def recall_block(result: dict, *, uid: str = "you", show_scope: bool = True,
                 now: datetime | None = None) -> str | None:
    """Build the recall block from a /v1/recall response dict, or None if no
    results. Each line carries the note's date when the server sent created_at
    (rung 85bcf262 card B1); ``now`` decides whether the year is shown. Undated
    lines come first (``undated_first``)."""
    now = now or datetime.now(timezone.utc)
    results = (result or {}).get("results") or []
    if not results:
        return None
    lines: list[tuple[bool, str]] = []
    for r in results:
        hd = bool(r.get("has_disagreement"))
        date = _date_label(r.get("created_at"), now)
        line = ("- " + (f"[{date}] " if date else "") + ("[conflict] " if hd else "")
                + _sanitize(r.get("content", "")))
        peers = r.get("conflict_peers") or []
        if hd and peers:
            n = len(peers)
            line += f" (conflicts with {n} other note{'s' if n != 1 else ''})"
        scope = r.get("scope")
        if show_scope and scope:
            line += f"  [{scope}]"
        lines.append((date is not None, line))
    return (
        "=== ATLASO MEMORY ===\n"
        f"Recalled notes from prior sessions for user \"{_sanitize(uid)}\".\n"
        + "\n".join(undated_first(lines))
        + "\n=== END ATLASO MEMORY ==="
    )
