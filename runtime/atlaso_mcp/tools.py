"""Tool logic for the Atlaso memory MCP server.

Pure functions that take a memory client (``atlaso_client.Client`` or any object
with the same methods) — so they're unit-testable with a fake. ``server.py`` wraps
each with FastMCP. Keep ALL behaviour here; keep server.py to wiring only.

These tools are the universal memory surface every tool reuses: look something up
(recall), save a fact (remember), fix/forget one, check health. In some tools
(e.g. Claude Code) memory is ALSO surfaced automatically via hooks, but these
tools never assume that — they work the same whether or not auto-surfacing exists.
"""
from __future__ import annotations

from typing import Any


def do_recall(client, query: str, limit: int = 5) -> dict[str, Any]:
    res = client.recall(query, limit=limit)
    return {
        "results": [
            {"id": r.get("id"), "content": r.get("content")}
            for r in res.get("results", [])
        ],
        "source": res.get("source"),
        "is_confident": res.get("is_confident"),
        "has_disagreement": res.get("has_disagreement"),
    }


def do_remember(client, text: str) -> dict[str, Any]:
    text = (text or "").strip()
    if not text:
        return {"saved": False, "error": "empty text"}
    # `manual` = explicit user remember → UNTOUCHABLE by L2 enrichment (the
    # server enricher's manual guard keys on this tag). Also tag the canonical
    # tool id for attribution when the client knows it.
    tags = ["manual"]
    tool = getattr(client, "tool", None)
    if tool:
        tags.insert(0, str(tool))
    cid = client.remember(text, tags=tags)
    return {"saved": True, "id": cid}


def do_forget(client, id: str) -> dict[str, Any]:
    ok = client.forget(id)
    if ok:
        return {"forgotten": True, "id": id}
    return {
        "forgotten": False,
        "id": id,
        "note": "not forgotten — the server was unreachable (offline). Try again when connected.",
    }


def do_recent(client, limit: int = 10) -> dict[str, Any]:
    return {"memories": client.recent(limit=limit)}


def do_status(client) -> dict[str, Any]:
    return client.status()
