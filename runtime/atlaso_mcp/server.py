"""Atlaso memory MCP server (the `Atlaso` server in the `atlaso` plugin).

Exposes a lean set of DELIBERATE memory tools over MCP, backed by the shared thin
client (``atlaso_client.Client``). The smart engine stays server-side; this just
calls it. Cross-tool by design — the same server works for Claude Code, Claude
Desktop, Codex, Cursor, etc.

Run:  python -m atlaso_mcp        (stdio)
"""
from __future__ import annotations

import os
from typing import Literal

from mcp.server.fastmcp import FastMCP

from atlaso_client import Client

from . import tools

# Server instructions (≤2KB): tell the model WHEN to reach for these tools vs the
# automatic recall hook. Shown to the model when it considers this server.
INSTRUCTIONS = (
    "Atlaso is the user's long-term memory across their tools. Use these tools to "
    "give continuity:\n"
    "- recall: search memory for what's relevant BEFORE answering — past decisions, "
    "preferences, gotchas, project facts. Call it whenever prior context would help "
    "(e.g. the user references something earlier, or asks 'what did we decide about X').\n"
    "- remember: save a specific durable fact, decision, preference, or gotcha worth "
    "keeping for next time.\n"
    "- forget: delete a memory by id (ids come from recall/recent). Only when asked.\n"
    "- recent: list the latest memories.\n"
    "- status: memory health (FMI) + counts.\n"
    "(In some tools relevant memories are also surfaced automatically, but don't rely "
    "on that — call recall when in doubt.) Memory is the user's own data; you decide "
    "how to use it."
)

# serverInfo.name — the server's self-reported identity. "Atlaso" is on-brand and matches
# the config-key each connector registers ("Atlaso" for Codex/Antigravity). Claude Code
# still keys its tool namespace + allowlist off ITS config key ("memory" → plugin:atlaso:memory),
# which is independent of this — so this rename doesn't touch CC's tool ids.
mcp = FastMCP("Atlaso", instructions=INSTRUCTIONS)

_client: Client | None = None


def client() -> Client:
    """Lazily build one shared client (warm keep-alive connection + cache).

    Tag it with this connector's tool id (from ATLASO_TOOL, set by the launcher — e.g.
    Antigravity's bin exports ATLASO_TOOL=antigravity) so the DELIBERATE MCP tools go
    through the SAME per-tool entitlement/tombstone gate the hooks use. Without a tool,
    the client resolves the shared bearer and skips per-tool gating — so a revoked or
    free-plan-gated tool could recall/remember via MCP when its hooks can't. None (env
    unset, e.g. older launchers) preserves the previous tool-agnostic behavior."""
    global _client
    if _client is None:
        _client = Client(tool=os.environ.get("ATLASO_TOOL") or None)
    return _client


@mcp.tool()
def recall(query: str, limit: int = 5) -> dict:
    """Search the user's Atlaso memory for notes relevant to `query`.

    Call this to look up relevant memory before answering — past decisions,
    preferences, project facts. Returns a ranked list of {id, content}. Read-only.
    """
    return tools.do_recall(client(), query, limit)


@mcp.tool()
def remember(
    text: str,
    polarity: Literal["positive", "negative", "cautionary", "open"],
) -> dict:
    """Save a note to the user's Atlaso memory.

    Use this when something specifically should be remembered — a decision,
    preference, or gotcha worth keeping for next time. Returns the new id.

    polarity (required) — which bucket this memory belongs to:
      · positive — "an affirmed preference, adopted tool, active decision, or standing fact"
      · open — "genuinely tentative/undecided"
      · cautionary — "avoid / known footgun / works-but-with-caveats"
      · negative — "rejected, disliked, deprecated"
    """
    return tools.do_remember(client(), text, polarity)


@mcp.tool()
def forget(id: str) -> dict:
    """Permanently delete a memory by its id (get ids from recall/recent).

    Destructive and not undoable — use only when the user asks to forget something.
    """
    return tools.do_forget(client(), id)


@mcp.tool()
def recent(limit: int = 10) -> dict:
    """List the most recent memories (newest first). Read-only."""
    return tools.do_recent(client(), limit)


@mcp.tool()
def status() -> dict:
    """Memory status: connected?, how many stored/pending, and the health score
    (FMI). Read-only."""
    return tools.do_status(client())


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
