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

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atlaso_client import _project

from .ambient_tool_core import PATH_SHAPE, auth_notice, normalize_remote, shape_ambient, valid_project_key

# The polarities a MODEL may assign on remember (Week-1 Step 4). 'pending'
# ("captured, not yet classified") is deliberately excluded — it belongs to
# the auto-capture pipeline, never to a deliberate remember.
REMEMBER_POLARITIES = ("positive", "negative", "cautionary", "open")


def _local_project_hint(raw: str | None) -> tuple[str, str | None]:
    if raw is None:
        return "not_supplied", None
    if not isinstance(raw, str) or not raw.strip():
        return "invalid", None
    if PATH_SHAPE.match(raw):
        status, key = _project.project_resolution(Path(raw))
        if status == "none":
            return "no_project_folder", None
        if status != "ok" or not valid_project_key(key):
            return "unresolved", None
        return "exact", key
    key = normalize_remote(raw)
    return ("exact", key) if valid_project_key(key) else ("invalid", None)


def do_ambient(client, project: str | None = None) -> dict[str, Any]:
    """Use this MCP server's tool identity; never fall back to another bearer."""
    match, key = _local_project_hint(project)
    wire = client.ambient_result(project=key)
    if not isinstance(wire, dict):
        return shape_ambient("upstream", None, None, match, key)
    state = wire.get("state")
    reason = wire.get("reason")
    if not isinstance(state, str) or (reason is not None and not isinstance(reason, str)):
        return shape_ambient("upstream", None, None, match, key)
    if state == "not_entitled":
        return shape_ambient(402, None, None, match, key)
    if state == "auth_error":
        return shape_ambient(401, None, None, match, key,
                             auth_text=auth_notice(wire.get("auth_cause")))
    if state == "degraded" and reason == "rate_limited":
        return shape_ambient(429, None, None, match, key)
    if state == "degraded" and reason in {"timeout", "upstream"}:
        return shape_ambient(reason, None, None, match, key)
    body = {**wire, "scope_version": 1}
    return shape_ambient(200, body, None, match, key)

# The lab's polarity guide — surfaced VERBATIM in the tool description so the
# model picks the right bucket (see server.py + server/mcp_app.py wrappers).
POLARITY_GUIDE = (
    "polarity (required) — which bucket this memory belongs to:\n"
    '  · positive — "an affirmed preference, adopted tool, active decision, or standing fact"\n'
    '  · open — "genuinely tentative/undecided"\n'
    '  · cautionary — "avoid / known footgun / works-but-with-caveats"\n'
    '  · negative — "rejected, disliked, deprecated"'
)


# A full ISO-8601 timestamp (the brain always sends one). Fractions of 3 or 6 digits
# only, so Python 3.10's fromisoformat and the TypeScript mirrors accept the same set.
_STATED_RE = re.compile(
    r"^[1-9]\d{3}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.(?:\d{3}|\d{6}))?)?(?:Z|[+-]\d{2}:\d{2})?$")


def stated_on(value: object) -> str | None:
    """The UTC calendar day ("2026-08-14") the user stated a note, or None when unknown.

    ``value`` is the brain's statement time for the note: ``created_at`` on a
    ``/v1/recall`` hit and ``stated_at`` on a ``/v1/memories`` row, both resolved by
    server/enrich/statement_time.py (rung 85bcf262 B1). It is never a processing
    time (import, sync, L2 rewrite, insertion); an unknown or malformed value stays
    None, so a date is never manufactured. A timestamp without an offset is UTC.
    Mirrors: server/mcp_app.py, tools/{cursor,opencode}/lib/mcp.ts; all four are
    tested against mcp/tests/stated_on_vectors.json."""
    if not isinstance(value, str) or not _STATED_RE.match(value):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).date().isoformat()


def do_recall(client, query: str, limit: int = 5) -> dict[str, Any]:
    res = client.recall(query, limit=limit)
    # The offline (source "local") path carries no created_at (atlaso_client drops the
    # cache's insertion time), so those results come back with stated_on null.
    return {
        "results": [
            {"id": r.get("id"), "content": r.get("content"),
             "stated_on": stated_on(r.get("created_at"))}
            for r in res.get("results", [])
        ],
        "source": res.get("source"),
        "is_confident": res.get("is_confident"),
        "has_disagreement": res.get("has_disagreement"),
    }


def do_remember(client, text: str, polarity: str) -> dict[str, Any]:
    text = (text or "").strip()
    if not text:
        return {"saved": False, "error": "empty text"}
    # polarity is REQUIRED (Week-1 Step 4): the model calling remember is the
    # only party that saw the conversation, so it must pick the bucket. The
    # FastMCP wrapper enforces the enum at schema level; this re-check keeps
    # the logic safe for direct callers/fakes.
    if polarity not in REMEMBER_POLARITIES:
        return {
            "saved": False,
            "error": f"polarity must be one of {list(REMEMBER_POLARITIES)}, got {polarity!r}",
        }
    # `manual` = explicit user remember → UNTOUCHABLE by L2 enrichment (the
    # server enricher's manual guard keys on this tag). Also tag the canonical
    # tool id for attribution when the client knows it.
    tags = ["manual"]
    tool = getattr(client, "tool", None)
    if tool:
        tags.insert(0, str(tool))
    cid = client.remember(text, polarity=polarity, tags=tags)
    return {"saved": True, "id": cid}


# Shown when a forget succeeded but this device's cache file still holds the text
# (another process's open read snapshot). Wording ruled by LabDirector fed79d00 R3.
PENDING_CLEANUP_NOTE = (
    "Atlaso will no longer recall or export this memory. Its text may still be in "
    "this device's cache; Atlaso will retry cleanup when the cache is next opened or "
    "synced. No action is needed from you."
)
# The forget scope disclosure, in its three approved sentences (fed79d00 R2/R3).
# Without the recall and in-flight sentences a forget result overstates the
# guarantee: an Ambient response already loading when the forget landed can still
# carry the text (fence: rung 56c93359, DEBT-FS-13). That applies whatever the
# cache cleanup outcome, so every successful forget that reports cleanup carries
# it (DEBT-FS-23, LabDirector d630cbea).
FORGET_RECALL_SCOPE = (
    "Atlaso stops recalling and exporting a forgotten memory through its memory "
    "tools."
)
FORGET_CACHE_MAY_LAG = "Cleanup of this device's cache may finish later."
FORGET_INFLIGHT_DISCLOSURE = (
    "If Atlaso context was loading when you forgot, the response may still contain "
    "it and may be reused in new sessions for up to 15 minutes after it finishes "
    "loading."
)
# Pending: the cache sentence is true, so all three sentences are shown.
FORGET_SCOPE_DISCLOSURE = " ".join(
    (FORGET_RECALL_SCOPE, FORGET_CACHE_MAY_LAG, FORGET_INFLIGHT_DISCLOSURE))
# Done: the cache is already clean, so the cache sentence would be false; the
# recall and in-flight sentences are shown unchanged.
DONE_CLEANUP_NOTE = FORGET_RECALL_SCOPE + " " + FORGET_INFLIGHT_DISCLOSURE


def do_forget(client, id: str) -> dict[str, Any]:
    detail = getattr(client, "forget_detail", None)
    res = detail(id) if callable(detail) else {"forgotten": client.forget(id)}
    if res.get("forgotten"):
        out: dict[str, Any] = {"forgotten": True, "id": id}
        if res.get("local_cache_cleanup") in ("done", "pending"):
            out["local_cache_cleanup"] = res["local_cache_cleanup"]
        if res.get("local_cache_cleanup") == "pending":
            out["note"] = PENDING_CLEANUP_NOTE + " " + FORGET_SCOPE_DISCLOSURE
        elif res.get("local_cache_cleanup") == "done":
            out["note"] = DONE_CLEANUP_NOTE
        return out
    return {
        "forgotten": False,
        "id": id,
        "note": "not forgotten — the server was unreachable (offline). Try again when connected.",
    }


def do_recent(client, limit: int = 10) -> dict[str, Any]:
    """Latest memories, each dated by ``stated_on`` from the brain's ``stated_at``.
    The row's ``created_at`` is its INSERTION time (an L2 rewrite's rewrite day, an
    import's import day), not when the user said it, so it is never passed on."""
    rows = client.recent(limit=limit)
    return {"memories": [
        {**{k: v for k, v in r.items() if k not in ("created_at", "stated_at")},
         "stated_on": stated_on(r.get("stated_at"))}
        for r in rows if isinstance(r, dict)
    ]}


def do_status(client) -> dict[str, Any]:
    return client.status()
