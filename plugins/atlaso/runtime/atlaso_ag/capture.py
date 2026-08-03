"""capture hook (Antigravity Stop): save the just-finished exchange to memory.

The Stop hook fires when the agent loop terminates. No event field carries the
conversation text, but every hook gets ``transcriptPath`` (the session log); we
read the last user/assistant exchange and hand it to the shared commodity capture
pipeline (``client.capture`` → worth-keeping gate + secret scrub + scope route +
near-dup), as an INSTANT LOCAL write (``push=False``, no network on the hot path).
Then a best-effort ``sync_once`` flushes to the cloud (Antigravity has no
SessionEnd, so the Stop hook doubles as the sync tick). Never breaks the turn.

CONTRACT (verified live on agy v1.0.x): the Stop payload carries ``conversationId``,
``terminationReason``, ``transcriptPath`` and ``workspacePaths``.
"""
from __future__ import annotations

import sys

from . import _shim
from .transcript import last_exchange


def run(payload: dict, client) -> bool:
    """Pure logic (testable): returns True if a memory was queued."""
    transcript = payload.get("transcriptPath") or payload.get("transcript_path") or ""
    user_text, asst_text = last_exchange(transcript) if transcript else ("", "")
    if not (user_text or "").strip():
        return False
    # Route through the shared commodity pipeline (gate / scrub / scope / near-dup).
    # Project comes from the workspace, NOT cwd (cwd is the plugin dir). push=False =
    # instant local write; the flush below syncs it.
    ws = _shim.workspace_dir(payload)
    if ws:
        res = client.capture(user_text, asst_text,
                             source_tag=_shim.TOOL, push=False, project_dir=ws)
    else:
        # No workspace = a scratch session: explicitly NO project (personal).
        # Passing None (not omitting) keeps the client from deriving a key
        # off the junk plugin-dir cwd.
        res = client.capture(user_text, asst_text,
                             source_tag=_shim.TOOL, push=False, project=None)
    return bool(res.get("saved"))


def main() -> int:
    if _shim.is_recursive():
        return 0
    payload = _shim.read_payload()
    try:
        client = _shim.make_client()
    except Exception:
        return 0
    try:
        saved = run(payload, client)
        _shim.log("capture", f"saved={saved}")
        # Best-effort flush to the cloud (no SessionEnd in Antigravity → the Stop
        # hook doubles as the sync tick). Never raises.
        try:
            client.sync_once()
        except Exception as e:
            _shim.log("capture", f"sync error {e!r}")
    except Exception as e:
        _shim.log("capture", f"error {e!r}")
    finally:
        try:
            client.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
