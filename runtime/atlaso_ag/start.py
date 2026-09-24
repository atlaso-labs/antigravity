"""start hook (Antigravity SessionStart): deliver the Ambient Memory brief.

agy 1.2.9 fires a SessionStart hook once per session, before the first model call.
It is not on the public hooks page (https://antigravity.google/docs/hooks lists five
events), but the binary carries it (hooks/session_start.go, CallSessionStartHook,
SessionStartHookResult.GetInjectSteps) and a plugin hooks.json `SessionStart` key
fires under `agy -p` (AG-5, AG-13). Its payload has conversationId, workspacePaths,
transcriptPath, artifactDirectoryPath and modelName (no invocationNum, no prompt), and
it takes the same output as PreInvocation:

    {"injectSteps": [{"ephemeralMessage": "<the brief>"}]}

The brief is the same ambient_start call the SessionStart hooks of the other tools
make, scoped to the workspace (workspacePaths, else the agy host cwd). Per-turn recall
stays in the PreInvocation hook (recall.py). Bounded and fail-open: any error, or no
brief, prints nothing and exits 0.
"""
from __future__ import annotations

import hashlib
import json
import sys

from . import _shim


def brief(payload: dict, client) -> str | None:
    """The ambient brief for this session's workspace, or None."""
    d = _shim.workspace_dir(payload)
    try:
        block = client.ambient_start(project_dir=d) if d else client.ambient_start(project=None)
    except Exception:
        return None
    return block if isinstance(block, str) and block.strip() else None


def run(payload: dict, client) -> dict | None:
    """Pure logic (testable): payload + client -> the injectSteps dict or None."""
    block = brief(payload, client)
    _log_fired(payload, block)
    return {"injectSteps": [{"ephemeralMessage": block}]} if block else None


def _log_fired(payload: dict, block) -> None:
    """Debug-only proof the SessionStart hook fired (ATLASO_DEBUG=1; AG-5): whether a
    brief was made, its size and a short hash of it (so a check can find the exact
    transcript step it became), and the conversation id. Never the brief text."""
    text = (block or "").strip()
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16] if text else "-"
    conv = payload.get("conversationId") or payload.get("conversation_id") or ""
    _shim.log("start", f"fired tool={_shim.TOOL} ambient={bool(text)} bytes={len(text.encode('utf-8'))} "
                       f"block_sha={sha} conv={conv}")


def _main() -> int:
    if _shim.is_recursive():
        return 0
    payload = _shim.read_payload()
    try:
        client = _shim.make_client()
    except Exception:
        return 0
    out = None
    try:
        out = run(payload, client)
    except Exception as e:
        _shim.log("start", f"error {e!r}")
    finally:
        try:
            client.close()
        except Exception:
            pass
    if out:
        print(json.dumps(out))
    return 0


def main() -> int:
    # Bound credential bootstrap, the ambient call and cleanup as one operation; the
    # hooks.json timeout is the process fuse.
    try:
        from atlaso_client._budget import HookTimeout, hook_budget
    except Exception:
        return _main()
    try:
        with hook_budget(seconds=8.0):
            return _main()
    except HookTimeout:
        return 0


if __name__ == "__main__":
    sys.exit(main())
