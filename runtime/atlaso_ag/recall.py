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

import hashlib
import json
import os
import time
import sys
from datetime import datetime, timezone

from . import _shim
from .transcript import last_prompt

_BANNER = "Atlaso Memory"


def _clean(text: str) -> str:
    """Stored text → one safe line: the shared renderer contract
    (atlaso_client._render.sanitize_line) in this connector's pre-B1 spacing mode
    ("join_lines": a line break becomes one space, tabs are kept), so a saved note can
    never add a line, forge a fence or carry invisible/bidi characters into the
    injected block, and ordinary one-line notes keep their exact bytes."""
    from atlaso_client import _render  # lazy, like _shim: importing this module stays dependency-free

    return _render.sanitize_line(text, "join_lines")


def render(results: list[dict], now: datetime | None = None) -> str | None:
    """Build the injection block from recall results, or None if nothing usable.
    Each line carries its note's UTC day when the server sent created_at (rung
    85bcf262 card B1; the shared label is atlaso_client._render._date_label).
    Undated lines come first (``_render.undated_first``)."""
    from atlaso_client import _render  # lazy, like _shim: importing this module stays dependency-free

    now = now or datetime.now(timezone.utc)
    lines = []
    for r in results or []:
        content = _clean(r.get("content", ""))
        if content:
            date = _render._date_label(r.get("created_at"), now)
            lines.append((date is not None, "- " + (f"[{date}] " if date else "") + content))
    if not lines:
        return None
    return f"=== {_BANNER} ===\n" + "\n".join(_render.undated_first(lines)) + f"\n=== {_BANNER} ==="


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
    _log_fired(prompt, res, block, session)
    notice = _degraded_notice(res, client)
    steps = []
    if notice:
        steps.append({"ephemeralMessage": notice})
    if block:
        steps.append({"ephemeralMessage": block})
    if not steps:
        return None
    return {"injectSteps": steps}


def _log_fired(prompt: str, res, block, session) -> None:
    """Debug-only proof the per-turn recall fired (ATLASO_DEBUG=1; AG-12), in the
    shape of the Codex and Grok hook lines: where the answer came from (server, or
    the local-cache floor), how many notes, whether a block was made, a short hash of
    the query so a check can tie the line to one prompt, and the conversation id so
    it can be tied to one agy session. Counts only: never the prompt or any memory
    text."""
    res = res if isinstance(res, dict) else {}
    n = len(res.get("results") or [])
    q_sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]
    _shim.log("recall", f"fired tool={_shim.TOOL} source={res.get('source')} results={n} "
                        f"injected={bool(block)} q_sha={q_sha} conv={session or ''}")


_DEGRADED_TEXT = ("Atlaso · cloud recall isn't responding — memory is running from this device's local cache "
                  "(results may be shallower). Capture and sync are unaffected; this clears on its own once the service responds.")


def _degraded_notice(res: dict, client) -> str | None:
    """Production audit E6 / C15 (LabDirector 160ff6e9 interventional falsifier): Antigravity had NO surface that told the
    user when a LINKED device silently fell back to the local keyword floor. Keyed on the EXISTING `source:"local"` field of
    the recall result plus the client's fallback episode (no emitter changed); shown once per episode via a marker file,
    clears itself when the episode clears. Never raises; never fires in local-only / not-connected modes (those are the
    autoconnect flow's concern, not a degradation)."""
    try:
        if res.get("source") != "local":
            return None
        mode = client.cloud_mode() if hasattr(client, "cloud_mode") else {}
        if (mode or {}).get("mode") != "linked":
            return None
        from atlaso_client import _fallback
        ep = _fallback.episode()
        if not ep:
            return None
        key = _fallback.episode_key(ep)   # nonce-keyed: same-second reform is a new episode (cc61a3cf)
        marker = _marker_path(key)
        marker.parent.mkdir(parents=True, exist_ok=True)
        try:
            # exclusive create: two concurrent first turns cannot both win (exists()/write_text was a TOCTOU race)
            with open(marker, "x") as fh:
                fh.write(str(int(time.time())))
        except FileExistsError:
            return None
        return _DEGRADED_TEXT
    except Exception:
        return None


def _marker_path(key: str):
    from pathlib import Path
    base = os.environ.get("ATLASO_GLOBAL_PATH") or os.path.join(os.path.expanduser("~"), ".atlaso")
    return Path(base) / "notice_shown" / ("ag_" + key.replace(":", "_"))


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
    steps = len((out or {}).get("injectSteps") or [])
    _shim.log("recall", f"inv={payload.get('invocationNum')} ws={_shim.workspace_dir(payload)} steps={steps}")
    if out:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    from atlaso_client import _deadline

    from atlaso_ag import STARTED

    sys.exit(_deadline.run_hook(main, tool=_shim.TOOL, event="recall", started=STARTED))
