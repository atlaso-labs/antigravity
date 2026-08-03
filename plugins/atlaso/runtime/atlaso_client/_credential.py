"""Which credential does THIS tool present to the brain?

Every Atlaso integration on a machine used to read the same ``~/.atlaso/auth.json``
bearer. The brain derives which tool is calling from the credential alone — there is
no per-request tool identity — so it could not tell two tools on one machine apart,
and "remove this tool" could not actually stop the tool. This module is the client
half of the fix: a tool trades the shared bearer for a credential of its OWN
(``~/.atlaso/tools/<tool>.json``) and uses that from then on.

THE RESOLUTION ORDER
    1. this tool's own credential, if it has one            → use it
    2. otherwise bootstrap: exchange the shared bearer for one → save → use it
    3. exchange refused because the user REMOVED this tool   → dormant (no traffic)
    4. exchange failed for any UNVERIFIED reason (network, WAF, 5xx)
                                                            → fall back to the shared
                                                              bearer, stay working

NEVER BRICK. Step 4 is not a detail. A Cloudflare 403 was once read as "token
revoked" and silently killed all capture for every user; the rule that came out of
that incident is that only a VERIFIED verdict from our own server may take a client
offline. A failed exchange is not a verdict — it is a bad afternoon on the network.
The shared bearer still works, so we keep working, and try again next run.

The one refusal we DO honour is ``tool_revoked``: the user removed this tool from
this device. Falling back to the shared bearer there would resurrect the tool the
user just removed — which is the exact bug per-tool credentials exist to kill.
"""
from __future__ import annotations

import contextlib
import os
from typing import Any, Iterator, Optional

from . import config

# Set on the auth dict we hand back so callers know which file to retire on a 401.
SHARED = "shared"
OWN = "own"

# How long to wait for another plugin to finish its exchange. Short on purpose: this
# runs inside a hook, and a hook that hangs is worse than a delayed credential.
_LOCK_TIMEOUT = 5.0

# A KERNEL-HELD lock, not a lockfile we manage ourselves.
#
# This matters, and I got it wrong twice before landing here. A lockfile you create and
# delete needs a staleness rule (or a crashed process wedges the tool forever), and
# every staleness rule I wrote was a TOCTOU: two contenders both observe the lock as
# stale, and the second one's "steal" removes the FRESH lock the first just created —
# so both walk away believing they hold it. Moving the check into an atomic rename
# didn't fix it either: the OBSERVATION and the rename are still two steps.
#
# flock/msvcrt have no such problem. The kernel owns the lock and drops it when the
# process dies, so there is no staleness to reason about and nothing to steal. We also
# never unlink the lock file — deleting a file another process holds an fd to is its own
# race, and a 0-byte file is not worth it.
try:  # POSIX (macOS, Linux) — where essentially every user is
    import fcntl as _fcntl
except ImportError:  # pragma: no cover
    _fcntl = None  # type: ignore[assignment]
try:  # Windows
    import msvcrt as _msvcrt
except ImportError:
    _msvcrt = None  # type: ignore[assignment]


def _try_lock(fd: int) -> bool:
    """Non-blocking exclusive lock on an open fd. False = someone else holds it."""
    if _fcntl is not None:
        try:
            _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
            return True
        except OSError:
            return False
    if _msvcrt is not None:  # pragma: no cover — not exercised on CI
        try:
            _msvcrt.locking(fd, _msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    return False  # no lock primitive → we must NOT exchange (caller falls back)


@contextlib.contextmanager
def _lock(tool: str) -> Iterator[bool]:
    """Cross-process lock around one tool's credential file. Yields whether we got it.

    NEVER BLOCKS A HOOK: we wait a few seconds, then give up. But giving up means NOT
    EXCHANGING — it does not mean barging ahead. The lock timeout is necessarily shorter
    than the exchange it guards, so "proceed unlocked" would simply re-create the race
    it exists to prevent: the holder is still mid-exchange, we mint a second credential,
    one of the two is superseded the moment it is written, and whichever process holds
    the loser spends its whole run on a dead bearer.

    So the caller falls back to the shared bearer instead. That keeps capture working
    (the only thing that actually matters here) and costs nothing: the next run finds
    the winner's credential already on disk.
    """
    import time

    path = config.tool_auth_path(tool).with_suffix(".lock")
    fd: Optional[int] = None
    held = False
    # ONE try/finally around acquisition AND the yield. If these were separate, a
    # BaseException between them (KeyboardInterrupt, SystemExit — neither of which
    # `except Exception` catches) would skip the release, and a caller that swallowed it
    # and kept running would hold the lock and the fd for the life of the process.
    try:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            deadline = time.monotonic() + _LOCK_TIMEOUT
            while True:
                if _try_lock(fd):
                    held = True
                    break
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.05)
        except Exception:
            held = False  # unwritable dir, no primitive — never go offline over it
        yield held
    finally:
        if fd is not None:
            # Closing the fd releases the lock on both platforms; be explicit anyway.
            if held and _fcntl is not None:
                with contextlib.suppress(OSError):
                    _fcntl.flock(fd, _fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                os.close(fd)


class ToolRemoved(Exception):
    """The user removed this tool from this device. Stay down; do not retry, do not
    fall back to the shared bearer. Only an explicit `atlaso setup` brings it back."""


class ToolNotEntitled(Exception):
    """Free plan, and a DIFFERENT tool holds the device's one slot. This tool gets no
    credential — and must NOT fall back to the shared bearer, because doing so would
    let it masquerade as the entitled tool. That masquerade is precisely the hole
    per-tool credentials close. Run local-only."""


def _exchange(server: str, token: str, tool: str, *, timeout: float = 8.0) -> Optional[dict]:
    """Trade a live credential of this device for one belonging to `tool`.

    Returns the new credential dict, or None if the exchange did not VERIFIABLY
    succeed or fail (→ caller falls back to the shared bearer). Raises ToolRemoved
    only on our server's explicit tool_revoked verdict.
    """
    import httpx

    try:
        r = httpx.post(
            f"{server.rstrip('/')}/v1/device/exchange",
            json={"tool": tool},
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )
    except Exception:
        return None  # network/DNS/TLS — unverified, keep the shared bearer

    if r.status_code == 200:
        try:
            body = r.json()
        except ValueError:
            return None
        return body if body.get("token") else None

    # A verdict counts only if it is verifiably OURS. An edge/WAF page can wear any
    # status code it likes; it cannot set this header.
    verified = r.headers.get("x-atlaso-response") == "1"
    code = r.headers.get("x-atlaso-error", "")
    if verified and r.status_code == 403 and code == "tool_revoked":
        raise ToolRemoved(tool)
    if verified and r.status_code == 409:
        raise ToolNotEntitled(tool)
    return None  # unverified → caller keeps the shared bearer and retries next run


def _same_identity(cred: dict, shared: dict) -> bool:
    """Does this credential belong to the account/device that is signed in RIGHT NOW?

    THE LEAK THIS CLOSES: `atlaso connect` into a different account (or a re-linked
    device) rewrites auth.json but leaves the old per-tool files sitting there. Trusting
    one blindly would have the plugin recall the PREVIOUS user's private memories and
    deposit this user's work into their brain.

    STRICT: every field must be PRESENT and EQUAL. A credential we cannot attribute is
    a credential we do not use — "missing" must never read as "matches", or the check
    is bypassed by the very files it is meant to catch.
    """
    for k in ("server", "user_id", "device_id"):
        want, got = shared.get(k), cred.get(k)
        if not want or not got or want != got:
            return False
    return True


def resolve(tool: Optional[str]) -> Optional[dict]:
    """The credential this tool should present, or None if it has none (offline).

    `tool=None` (generic client / tests) keeps the old behaviour: the shared bearer.
    """
    shared = config.load_auth() or {}
    if not tool:
        return {**shared, "source": SHARED} if shared.get("token") else None

    own = config.load_tool_auth(tool)
    if own and _same_identity(own, shared):
        return {**own, "source": OWN}  # fast path: no lock, no round trip

    if not (shared.get("token") and shared.get("server")):
        return None  # not connected at all

    # Serialize load→quarantine→exchange→save across the plugins that may be starting at
    # the same moment on this machine. Two processes that both see no file would both
    # exchange, and the second mint kills the first's token — leaving one of them to run
    # its whole session on a bearer the server has already deleted.
    with _lock(tool) as held:
        if not held:
            # Someone else is exchanging right now (or we can't lock at all). Do NOT
            # race them — the shared bearer still works, so capture keeps working, and
            # the next run simply finds the winner's credential on disk.
            return {**shared, "source": SHARED}

        own = config.load_tool_auth(tool)  # the winner may have written it while we waited
        if own:
            if _same_identity(own, shared):
                return {**own, "source": OWN}
            # Belongs to a previous account/device. Never present it, never fall back to
            # it — quarantine it BEFORE the exchange, so it is gone even if the mint
            # then fails.
            config.clear_tool_auth(tool)

        minted = _exchange(shared["server"], shared["token"], tool)  # may raise

        if minted:
            cred = {
                "server": shared["server"],
                "user_id": shared.get("user_id"),
                "device_id": shared.get("device_id"),
                "tool": tool,
                "token": minted["token"],
                "version": 1,
            }
            try:
                config.save_tool_auth(tool, cred)
            except OSError:
                pass  # couldn't persist → still usable this run; retry next time
            # `minted` tells the caller this credential is BRAND NEW, so any local-only
            # verdict left behind by the credential it replaces is stale and must go.
            return {**cred, "source": OWN, "minted": True}

    # Unverified failure → the shared bearer still works. Keep capturing.
    return {**shared, "source": SHARED}


def retire(tool: Optional[str], source: str, token: Optional[str] = None) -> None:
    """A credential was rejected (verified 401/403). Drop the one that failed, so the
    next run re-bootstraps — and, if the tool was revoked, is told to stay down.

    Deletes ONLY the exact credential that was rejected. Two guards, both load-bearing:
      • source must be OWN — a rejected shared bearer is not ours to delete; every other
        integration on this machine is still riding it.
      • the file must still hold the SAME token we presented — otherwise a slow process
        holding a superseded token would delete the fresh, working credential another
        process just minted, and the two would fight forever.
    """
    if not (tool and source == OWN):
        return
    with _lock(tool) as held:
        if not held:
            # Another process is mid-rotation. Deleting now is a TOCTOU: we'd read the
            # old token, it would write the new one, and we'd delete THAT — destroying a
            # perfectly good credential someone else just minted. Leave it; if ours is
            # really dead we'll get another 401 next run and retire it then.
            return
        if token is not None:
            cur = config.load_tool_auth(tool)
            if cur and cur.get("token") != token:
                return  # someone already replaced it with a newer one — leave it alone
        config.clear_tool_auth(tool)
