"""Install-completeness attestation — the CLIENT half of the capabilities handshake.

WHY THIS FILE EXISTS. The install surface certifies success from two signals —
device authorized, and a memory write landed — that are STRUCTURALLY BLIND to a
partial install: MCP registers, hooks silently fail, and both signals still fire,
because the MCP path can write memory on its own. The surface says SUCCESS while
session capture is dead and Atlaso never sees another session.

So each component proves ITSELF. This module holds the two rules that make those
proofs mean anything, and both of them are easy to lose in a refactor:

  RULE 1 — PROVE AT THE CAPABILITY BOUNDARY, NOT AT LAUNCH.
    Emitting a proof when a process STARTS attests nothing: a hook can be
    registered, execute, and have its Python shim throw on import; an MCP server
    can be spawned by the host and never complete negotiation or surface a single
    tool. Both are ordinary partial installs, and a launch-time proof reports them
    green. `prove()` is therefore only ever called AFTER the substantive work has
    already succeeded — see the call sites, and do not move them earlier.

  RULE 2 — EACH COMPONENT HOLDS ONLY ITS OWN SECRET.
    The server mints a separate secret per component and each is delivered only
    through that component's own channel. If a component could read another's
    secret, a working component could vouch for a dead one and we are back to the
    original bug. Never write these into one shared file, never pass one to code
    that handles another.

WHAT THIS IS NOT. These are DEVICE-LOCAL SELF-REPORTS. They are strong evidence
against a silent partial install. They are NOT a defense against a hostile process
on the same machine — anything that can read one plugin root can read another, and
both run as the same user. Nothing may ever gate capability, entitlement, or plan
on them.

THE SECRET NEVER TRAVELS IN argv OR AN ENVIRONMENT VARIABLE. These hosts are AI
coding agents that read and print their own environment into transcripts — which is
why scrub.py exists at all. File only, 0600, and always in a POST body: request
bodies are never captured by observability, but URLs are, so it must never appear
in a query string.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

# The component vocabulary. Each name describes a capability boundary that was
# CROSSED, never "a process started" — see RULE 1.
HOOK_CAPTURE = "hook_capture"      # the hook ran to completion AND round-tripped to the brain
MCP_TOOL_CALL = "mcp_tool_call"    # an Atlaso MCP tool was actually invoked and returned
SKILL_PRESENT = "skill_present"    # the skill file is on disk (deliberately the weakest)

_TIMEOUT_S = 5.0


def _state_dir() -> Path:
    """~/.atlaso/install — a SEPARATE directory from the credential of record.

    Not co-located in auth.json, and the reason is integrity rather than secrecy:
    anything that can read auth.json already holds the bearer, which is strictly
    more powerful than any of these secrets. But rewriting auth.json on every
    install attempt reintroduces the read-modify-write race that per-tool credential
    files were split out to avoid. A torn auth.json is a bricked integration; a torn
    attestation file is a retry.
    """
    home = Path(os.environ.get("ATLASO_HOME") or (Path.home() / ".atlaso"))
    d = home / "install"
    d.mkdir(parents=True, exist_ok=True)
    # mkdir's mode is umask-masked and does not apply to an existing directory, so
    # set it explicitly: file contents are 0600, but a world-traversable directory
    # leaks which tools are installed via the filenames.
    for p in (home, d):
        try:
            os.chmod(p, 0o700)
        except OSError:
            pass
    return d


def secret_path(tool: str, component: str) -> Path:
    safe_tool = "".join(ch for ch in tool if ch.isalnum() or ch in "-_")[:40]
    safe_comp = "".join(ch for ch in component if ch.isalnum() or ch == "_")[:40]
    return _state_dir() / f"{safe_tool}.{safe_comp}.json"


def write_secret(tool: str, component: str, attempt_id: str, secret: str) -> None:
    """Deliver ONE component's secret to ONE component. Atomic, 0600.

    Called by the installer, once per component, into the location only that
    component reads. See RULE 2 — never widen this to write several at once.
    """
    p = secret_path(tool, component)
    tmp = p.with_suffix(f".{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"attempt_id": attempt_id, "secret": secret, "tool_id": tool}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def read_secret(tool: str, component: str) -> Optional[dict]:
    try:
        obj = json.loads(secret_path(tool, component).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(obj, dict) or not obj.get("secret") or not obj.get("attempt_id"):
        return None
    return obj


def clear_secret(tool: str, component: str) -> None:
    try:
        secret_path(tool, component).unlink()
    except OSError:
        pass


def prove(component: str, *, tool: str, server: str, token: str) -> bool:
    """Report that `component` crossed its capability boundary. Returns True if the
    brain recorded it. NEVER raises — attestation is observability, and a health
    signal that can break the thing it observes is worse than no signal.

    ONLY CALL THIS AFTER THE REAL WORK SUCCEEDED. See RULE 1.

    On the delete-the-secret decision, which is the subtle part: the secret file is
    removed ONLY on a verified terminal outcome — a 2xx, or a 4xx that is POSITIVELY
    ours (it carries the X-Atlaso-Response marker). A bare 403 without that marker is
    a Cloudflare/edge block, i.e. TRANSIENT, and deleting on it would burn a good
    install's only proof and leave the health surface permanently red — the same
    class of bug as the edge-block-mistaken-for-revocation that once killed all sync.
    """
    rec = read_secret(tool, component)
    if not rec:
        return False
    try:
        import httpx

        r = httpx.post(
            f"{server.rstrip('/')}/v1/install/attest",
            headers={"Authorization": f"Bearer {token}"},
            # POST body, never a query string: bodies are not captured by
            # observability, URLs are.
            json={
                "attempt_id": rec["attempt_id"],
                "tool_id": rec.get("tool_id") or tool,
                "component": component,
                "secret": rec["secret"],
            },
            timeout=_TIMEOUT_S,
        )
    except Exception:
        return False  # transient: keep the secret, try again next session

    if r.status_code == 200:
        clear_secret(tool, component)  # proved; the window is done with
        return True
    # Verifiably ours AND terminal -> the window is genuinely gone; stop retrying.
    if 400 <= r.status_code < 500 and r.headers.get("x-atlaso-response") == "1":
        clear_secret(tool, component)
    return False


def open_attempt(*, server: str, token: str, tool: str) -> Optional[dict]:
    """Open an attestation window and deliver each secret to its own component.

    Returns the attempt dict, or None on any failure — an install must never fail
    because the health signal could not be set up.
    """
    try:
        import httpx

        r = httpx.post(
            f"{server.rstrip('/')}/v1/install/attempt",
            headers={"Authorization": f"Bearer {token}"},
            json={"tool_id": tool},
            timeout=_TIMEOUT_S,
        )
        if r.status_code != 200:
            return None
        data = r.json()
    except Exception:
        return None
    for component, secret in (data.get("components") or {}).items():
        try:
            write_secret(tool, component, data["attempt_id"], secret)
        except OSError:
            pass
    return data
