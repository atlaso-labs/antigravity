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

_FENCE_RE = re.compile(r"(?i)=*\s*(?:END\s+)?ATLASO\s+(?:MEMORY|ORIENTATION)[^\n]*")


def _sanitize(s: str) -> str:
    return _FENCE_RE.sub("[fence]", " ".join((s or "").split()))


def recall_block(result: dict, *, uid: str = "you", show_scope: bool = True) -> str | None:
    """Build the recall block from a /v1/recall response dict, or None if no
    results."""
    results = (result or {}).get("results") or []
    if not results:
        return None
    lines: list[str] = []
    for r in results:
        hd = bool(r.get("has_disagreement"))
        line = "- " + ("[conflict] " if hd else "") + _sanitize(r.get("content", ""))
        peers = r.get("conflict_peers") or []
        if hd and peers:
            n = len(peers)
            line += f" (conflicts with {n} other note{'s' if n != 1 else ''})"
        scope = r.get("scope")
        if show_scope and scope:
            line += f"  [{scope}]"
        lines.append(line)
    return (
        "=== ATLASO MEMORY ===\n"
        f"Recalled notes from prior sessions for user \"{_sanitize(uid)}\".\n"
        + "\n".join(lines)
        + "\n=== END ATLASO MEMORY ==="
    )
