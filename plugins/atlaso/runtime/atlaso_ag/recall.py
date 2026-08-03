"""recall hook (Antigravity PreInvocation): inject recalled memory.

PreInvocation fires before the model call. No event field carries the raw prompt,
so we recover the user's latest message from ``transcriptPath`` (defensively
parsed). We query the memory client and, if there are hits, print a single JSON
object to STDOUT asking Antigravity to inject an ephemeral context step:

    {"injectSteps": [{"ephemeralMessage": "=== Atlaso Memory === ..."}]}

The injected block is plain + branded (no instructions, no warnings) — the model
decides how to use it. Synchronous + cheap (server recall, or local cache offline).

Fails open: any error, or nothing worth injecting → print nothing (or ``{}``) and
exit 0. The turn always proceeds.

CONTRACT (verified live on agy v1.0.x): the PreInvocation payload carries
``conversationId``, ``invocationNum``, ``transcriptPath`` and ``workspacePaths`` —
NO raw prompt (it lives in the transcript) — and Antigravity injects an
``injectSteps`` array of ``{"ephemeralMessage": …}`` before the model call.
"""
from __future__ import annotations

import json
import os
import re
import sys

from . import _shim
from .transcript import last_prompt

_BANNER = "Atlaso Memory"
# Stop stored content from forging our own banner line.
_FENCE_RE = re.compile(r"(?i)=+\s*Atlaso Memory\s*=+")


def _clean(text: str) -> str:
    return _FENCE_RE.sub("[atlaso]", (text or "").strip())


def render(results: list[dict]) -> str | None:
    """Build the injection block from recall results, or None if nothing usable."""
    lines = []
    for r in results or []:
        content = _clean(r.get("content", ""))
        if content:
            lines.append("- " + content)
    if not lines:
        return None
    return f"=== {_BANNER} ===\n" + "\n".join(lines) + f"\n=== {_BANNER} ==="


def _prompt_from(payload: dict) -> str:
    """Best-effort: a direct prompt-ish field if Antigravity ever supplies one,
    else the last user message in the transcript, else ''."""
    for k in ("prompt", "userMessage", "message", "userPrompt", "input"):
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return last_prompt(payload.get("transcriptPath") or "")


def run(payload: dict, client) -> dict | None:
    """Pure logic (testable): payload + client → the injectSteps dict or None."""
    # PreInvocation fires before EVERY model call; only recall on the FIRST one of a
    # turn (invocationNum == 0) so an agentic loop doesn't re-recall on each step.
    inv = payload.get("invocationNum")
    if isinstance(inv, (int, float)) and int(inv) != 0:
        return None
    prompt = _prompt_from(payload)
    if not prompt:
        return None
    try:
        limit = int(os.environ.get("ATLASO_RECALL_LIMIT", "5"))
    except ValueError:
        limit = 5
    # Per-project scope from the workspace (hooks' cwd is the plugin dir, so project
    # must come from workspacePaths, NOT cwd) + thread the conversation id so the
    # server can grade which memories were injected (recall-usefulness loop).
    project = _shim.workspace_project(payload)
    session = payload.get("conversationId") or payload.get("conversation_id")
    res = client.recall(prompt, limit=limit, project=project, session=session)
    block = render(res.get("results", []))
    if not block:
        return None
    return {"injectSteps": [{"ephemeralMessage": block}]}


def main() -> int:
    if _shim.is_recursive():
        return 0
    # If not connected yet, kick off the (detached) browser-authorize in the
    # background — so the next PreInvocation after install triggers it automatically.
    # Recall still proceeds (local) meanwhile.
    _shim.maybe_autoconnect()
    payload = _shim.read_payload()
    try:
        client = _shim.make_client()
    except Exception:
        return 0
    out = None
    try:
        out = run(payload, client)
    except Exception as e:
        _shim.log("recall", f"error {e!r}")
    finally:
        try:
            client.close()
        except Exception:
            pass
    if out:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
