"""Shared plumbing for the Atlaso Antigravity hooks.

Every hook is a thin shim: read the event payload from stdin (JSON, camelCase
fields), build the tool-agnostic ``atlaso_client.Client``, do one small thing, and
NEVER break the turn (all failures swallow → exit 0).

Mirrors ``atlaso_cc/_shim.py`` (the Claude Code connector) so the two connectors
stay structurally identical; only the TOOL id and a couple of field names differ.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def read_payload() -> dict:
    """Parse the hook's stdin JSON; {} on anything malformed/empty.

    Antigravity delivers the hook event as a single JSON object on STDIN with
    camelCase fields (conversationId, workspacePaths, transcriptPath, …)."""
    try:
        raw = sys.stdin.read()
        obj = json.loads(raw) if raw.strip() else {}
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def is_recursive() -> bool:
    """True inside our own nested model calls (future server/L2 enrichment), so
    memory never recalls/captures itself into a loop."""
    return bool(os.environ.get("ATLASO_EXTRACTING"))


# This connector's tool id — must match the agent id the web app / brain use.
# Overridable via ATLASO_TOOL for testing/forward-compat (mirrors the codex shim).
TOOL = os.environ.get("ATLASO_TOOL") or "antigravity"


def make_client():
    """Build the memory client (reads ~/.atlaso/auth.json; offline-safe).
    Imported lazily so the hook modules stay importable without the client dep
    (tests inject a fake client). Tagged with this tool id so the client's plan
    entitlement knows which tool is asking (free = only the active tool is
    cloud-linked; others run local-only)."""
    from atlaso_client import Client

    return Client(tool=TOOL)


def maybe_autoconnect() -> bool:
    """If this machine isn't connected yet, spawn the (detached) browser-authorize
    flow. Fast + best-effort — never blocks the hook, never raises."""
    try:
        from atlaso_client.connect import maybe_autoconnect as _mc

        return _mc(TOOL)
    except Exception:
        return False


def workspace_dir(payload: dict) -> str | None:
    """The workspace that scopes recall and capture, or None for personal scope.

    Order: the FIRST workspacePaths entry; else ATLASO_AG_HOST_CWD, which
    hooks/_resolve.sh sets to the cwd of the hook's parent only when that parent
    is agy (it is empty otherwise, and an inherited value is overwritten); else
    None. The hook's own cwd is never used, because Antigravity runs hooks with
    cwd = the plugin dir. Callers pass an explicit project=None for the None
    case so the client does not fall back to that cwd."""
    ws = payload.get("workspacePaths") or payload.get("workspace_paths") or []
    if isinstance(ws, str):
        ws = [ws]
    if ws:
        return ws[0]
    # `agy -p` sends workspacePaths [] while the host itself uses its cwd as the
    # workspace; _resolve.sh records that cwd after checking the parent is agy.
    return os.environ.get("ATLASO_AG_HOST_CWD") or None


def workspace_project(payload: dict) -> str | None:
    """Per-project recall key from the workspace. None → personal-only."""
    d = workspace_dir(payload)
    if not d:
        return None
    try:
        from pathlib import Path

        from atlaso_client import _project

        return _project.project_key(Path(d))
    except Exception:
        return None


def log(name: str, msg: str) -> None:
    """Opt-in debug log (set ATLASO_DEBUG=1). Off by default — hooks stay quiet."""
    if not os.environ.get("ATLASO_DEBUG"):
        return
    try:
        base = (
            os.environ.get("ATLASO_GLOBAL_PATH")
            or os.environ.get("ATLASO_PATH")
            or str(Path.home() / ".atlaso")
        )
        d = Path(base)
        d.mkdir(parents=True, exist_ok=True)
        with open(d / f"atlaso-ag-{name}.log", "a", encoding="utf-8") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat()} {msg}\n")
    except Exception:
        pass
