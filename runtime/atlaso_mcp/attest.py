"""Install-completeness attestation — the MCP half of the capabilities handshake.

`atlaso_client.attest` holds the contract and the two rules; this module is the
one CALL SITE that can honestly report `mcp_tool_call`, and everything here exists
to keep that report honest and free.

WHY NOT AT SPAWN. The agent host starts this process; that is the ONLY thing a
launch-time proof would attest. A server can be spawned, fail MCP negotiation,
never surface a tool, and never be called by the model — three ordinary partial
installs, all of them reported green by a proof emitted in `main()`. So nothing
here runs at import or at `mcp.run()`. `note_tool_call()` is invoked from the tail
of each tool body in server.py, AFTER the tool's real work has already produced a
return value. That ordering is RULE 1 and it is the whole point of the component.

WHY FIRE-AND-FORGET. This is observability on the hot path of a user-visible tool
call, so it gets exactly one budget: the cost of starting a thread (tens of
microseconds), paid once per attempt. Every byte of I/O — the secret-file read, the
credential read, the HTTPS POST and its 5s timeout — happens on a daemon thread
that the tool call does not wait for and cannot be affected by. A missing secret, an
unreadable credential, a 500, a hang, a DNS failure: all of them are silent, and
none of them can change the tool's result, its latency, or whether it raises.
A health signal that can break the thing it observes is worse than no signal.

WHY THE IN-FLIGHT LATCH. `_inflight` bounds the emitter to ONE proof POST in flight
at a time, so a burst of tool calls cannot fan out into a burst of POSTs, and a
single tool call can never produce two. `_proved` then latches the process shut
after the brain has recorded it, so a long-lived server with hundreds of tool calls
costs exactly one POST. Anything short of a recorded proof leaves the latch open:
the secret file survives a failed POST (see `attest.prove`), so the NEXT tool call
retries, and a re-arm that lands mid-session is picked up without a restart.
Re-proof is idempotent server-side (replay counter, not an error), so the latch is
an economy, never a correctness requirement.

NOTHING MAY GATE ON THIS. `note_tool_call()` returns None and swallows everything.
It cannot reach the tool's return value, an exception path, entitlement, plan, or
billing. Kill-condition K4.
"""
from __future__ import annotations

import os
import threading
from typing import Optional

# Guards both flags. Held only around flag reads/writes — never across I/O.
_lock = threading.Lock()
_inflight = False
_proved = False
# Test-only handle; see `_join_for_tests`.
_thread: Optional[threading.Thread] = None


def _tool() -> Optional[str]:
    """This connector's tool id, set by the launcher that spawned us (e.g.
    tools/claude-code/bin/atlaso-memory-mcp exports ATLASO_TOOL=claude-code).

    None is the honest answer for an older launcher that does not export it, and
    it is terminal for the process: the secret file is NAMED for the tool, so
    without one there is no file to read and nothing that could be proved. We
    report nothing rather than guessing a slug — a guessed tool id would either
    find no secret (silent no-op, but confusing) or, worse, arrive at the brain
    as a claim about a tool this process is not.
    """
    return os.environ.get("ATLASO_TOOL") or None


def _prove() -> None:
    """The off-thread body. Never raises — this thread has no one to raise to."""
    global _inflight, _proved
    proved = False
    try:
        from atlaso_client import attest, config

        tool = _tool()
        if not tool:
            return
        # Cheapest terminal check first, and the one the done-criterion names: with
        # no secret file there is NOTHING TO PROVE, so we must not POST at all. An
        # unarmed machine (never ran `atlaso setup`, or already proved and the
        # secret was consumed) therefore costs one stat and zero network.
        if attest.read_secret(tool, attest.MCP_TOOL_CALL) is None:
            return
        auth = config.load_tool_auth(tool) or config.load_auth() or {}
        token, server = auth.get("token"), auth.get("server")
        if not token or not server:
            return
        proved = bool(attest.prove(attest.MCP_TOOL_CALL, tool=tool, server=server, token=token))
    except Exception:
        # Import error, unreadable home, anything. Attestation is observability.
        pass
    finally:
        with _lock:
            _inflight = False
            if proved:
                _proved = True


def note_tool_call() -> None:
    """Report that an Atlaso MCP tool was actually INVOKED AND RETURNED.

    CALL THIS ONLY FROM THE TAIL OF A TOOL BODY, after the return value exists.
    Never from `main()`, never at import, never in an `except` — see the module
    docstring. Returns None, and never raises, on every path.
    """
    global _inflight, _thread
    try:
        with _lock:
            if _proved or _inflight:
                return
            _inflight = True
        t = threading.Thread(target=_prove, name="atlaso-attest", daemon=True)
        _thread = t
        # daemon=True: a proof in flight must never hold the process open at
        # shutdown. Losing an unsent proof costs one neutral square on a health
        # surface; hanging the agent host's MCP server costs the user their tool.
        t.start()
    except Exception:
        # Thread creation can fail (RLIMIT_NPROC). Unlatch so a later call retries.
        with _lock:
            _inflight = False


def _join_for_tests(timeout: float = 5.0) -> None:
    """TEST ONLY. Wait for an in-flight proof so a test can assert on POST counts
    deterministically instead of sleeping. Production code must never call this —
    the entire design is that nobody waits for this thread."""
    t = _thread
    if t is not None:
        t.join(timeout)


def _reset_for_tests() -> None:
    """TEST ONLY. Clear the process latches between cases."""
    global _inflight, _proved, _thread
    _join_for_tests()
    with _lock:
        _inflight = False
        _proved = False
    _thread = None
