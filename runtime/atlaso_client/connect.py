"""Device connect — the client half of the link-only auth handshake.

Gets a token onto this machine and writes ~/.atlaso/auth.json, so the (otherwise
read-only) client can talk to the user's cloud brain. Engine-free, stdlib + httpx.

The flow (PKCE + loopback, RFC 8252; the brain implements the server side):
  1. start a one-shot HTTP listener on 127.0.0.1:<ephemeral>
  2. POST /v1/device/start          → send a PKCE challenge + that loopback redirect_uri,
                                       get back a verification link (with a ticket)
  3. open the link in the browser   → the user clicks "Authorize" in the dashboard;
                                       the browser is redirected to our loopback with a
                                       one-time code (machine-local — a phished link
                                       lands on the victim's own 127.0.0.1, not ours)
  4. POST /v1/device/token          → redeem {code, code_verifier} for the token (one-time)
  5. write auth.json

`maybe_autoconnect()` makes step 1-2 AUTOMATIC: a hook calls it, and if this
machine isn't connected yet it spawns this connect in the background (which opens
the browser). The only manual actions for the user are pasting the plugin command
and clicking Authorize.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

from . import config

_LOCK_NAME = ".connecting"
# A spawned connect polls until the device ticket expires (~10 min). Don't spawn a
# second one while one is plausibly in flight.
_LOCK_TTL = 15 * 60


def save_auth(server: str, token: str, user_id: str, device_id: str | None) -> Path:
    """Atomically + durably write {server, token, user_id, device_id} to auth.json
    at 0600. Uses an unpredictable temp name (no symlink/TOCTOU), a full-write loop,
    and fsync of both the file and the directory."""
    import tempfile

    p = config.auth_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p.parent, 0o700)  # owner-only dir
    except OSError:
        pass
    data = json.dumps(
        {"server": server, "token": token, "user_id": user_id, "device_id": device_id},
        indent=2,
    ).encode("utf-8")
    # mkstemp: O_EXCL + 0600 + random name in the same dir → atomic, no symlink follow.
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".auth.", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        mv = memoryview(data)
        while mv:
            mv = mv[os.write(fd, mv):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, p)
    try:  # fsync the directory so the rename is durable
        dfd = os.open(str(p.parent), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass
    # A fresh token means the link changed — INVALIDATE any persisted verdict so
    # the next op re-verifies entitlement from scratch (no stale free pass to the
    # new credential). Cloud sync resumes + the outbox drains once re-verified.
    try:
        from . import state
        state.invalidate()
    except Exception:
        pass
    return p


def has_token() -> bool:
    auth = config.load_auth()
    return bool(auth and auth.get("token"))


def _lock_path() -> Path:
    return config.atlaso_dir() / _LOCK_NAME


def _pkce_pair() -> tuple[str, str]:
    """(code_verifier, code_challenge) — RFC 7636 S256. The verifier never leaves
    this process; only its sha256 challenge is sent at /device/start, and the
    verifier is presented at /device/token to redeem the loopback code."""
    import base64
    import hashlib
    verifier = secrets.token_urlsafe(48)  # 64 chars, within RFC's 43..128
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return verifier, challenge


def connect(server: str | None = None, *, open_browser: bool = True,
            tool: str | None = None, log: Callable[[str], None] = print) -> int:
    """Run the connect handshake to completion. Returns 0 on success.

    PKCE + loopback (RFC 8252): we start a one-shot HTTP listener on 127.0.0.1,
    send its loopback redirect_uri + a PKCE challenge to /device/start, open the
    browser to the consent page, and the approved one-time code is delivered to
    OUR loopback (machine-local). We then redeem it with the PKCE verifier. A
    forwarded/phished approval link can't reach an attacker's listener and can't
    be redeemed without the verifier."""
    import http.server
    from urllib.parse import parse_qs, urlparse

    import httpx

    base = (server or os.environ.get("ATLASO_SERVER") or config.DEFAULT_SERVER).rstrip("/")
    label = socket.gethostname()[:80] or "this device"
    # The originating tool (e.g. "claude-code") so the authorize screen can show
    # "<Tool> wants to connect". Passed by the connector, else read from env.
    tool = tool or os.environ.get("ATLASO_TOOL")
    existing = config.load_auth() or {}

    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(16)
    result: dict[str, str] = {}

    class _Callback(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (stdlib name)
            q = parse_qs(urlparse(self.path).query)
            code = (q.get("code") or [""])[0]
            st = (q.get("state") or [""])[0]
            ok = bool(code) and secrets.compare_digest(st, state)
            if ok and "code" not in result:
                result["code"] = code
            msg = ("<h2>Atlaso connected ✓</h2><p>You can close this tab and "
                   "return to your terminal.</p>") if ok else \
                  ("<h2>Atlaso: connection failed</h2><p>Return to your terminal "
                   "and run connect again.</p>")
            body = (f"<html><body style='font-family:system-ui;max-width:30rem;"
                    f"margin:4rem auto;text-align:center'>{msg}</body></html>").encode("utf-8")
            self.send_response(200 if ok else 400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a: Any) -> None:  # silence the default stderr logging
            pass

    # Bind to loopback only (NOT 0.0.0.0) on an ephemeral port — RFC 8252 §7.3.
    try:
        httpd = http.server.HTTPServer(("127.0.0.1", 0), _Callback)
    except OSError as e:
        log(f"  Error: couldn't open a local callback port ({e}).")
        return 1
    port = httpd.server_address[1]
    redirect_uri = f"http://127.0.0.1:{port}/cb"

    start_body: dict[str, Any] = {
        "label": label, "code_challenge": challenge,
        "redirect_uri": redirect_uri, "state": state,
    }
    if tool:
        start_body["tool"] = tool[:40]
    if existing.get("device_id"):
        start_body["device_id"] = existing["device_id"]  # reconnect rotates in place

    try:
        with httpx.Client(timeout=30.0) as client:
            r = client.post(f"{base}/v1/device/start", json=start_body)
            r.raise_for_status()
            try:
                d = r.json()
                verify_url = d.get("verification_uri_complete") or d.get("verification_uri", base)
                expires_in = int(d.get("expires_in", 600))
            except (ValueError, KeyError, TypeError) as e:
                log(f"  Error: unexpected response from {base} ({e}).")
                return 1

            if open_browser and not os.environ.get("ATLASO_NO_BROWSER"):
                try:
                    import webbrowser
                    webbrowser.open(verify_url)
                except Exception:
                    pass
            log("")
            log("  Atlaso — authorize this device:")
            log(f"      {verify_url}")
            log("  (We tried to open it in your browser.) Waiting for approval…")

            # Serve loopback requests until the approved code arrives or we time out.
            deadline = time.monotonic() + expires_in
            while time.monotonic() < deadline and "code" not in result:
                httpd.timeout = min(1.0, max(0.2, deadline - time.monotonic()))
                httpd.handle_request()  # one request per loop (favicon etc. just 400)
            code = result.get("code")
            if not code:
                log("\n  Timed out waiting for approval — reconnect to try again.")
                return 1

            tr = client.post(
                f"{base}/v1/device/token",
                json={"code": code, "code_verifier": verifier},
            )
            if tr.status_code != 200:
                log(f"  Error: token exchange failed ({tr.status_code}).")
                return 1
            try:
                t = tr.json()
            except ValueError:
                log("  Error: unexpected token response.")
                return 1
            status = t.get("status")
            if status == "approved":
                tok, uid = t.get("token"), t.get("user_id")
                if not tok or not uid:
                    log("  Error: malformed approval from the server.")
                    return 1
                p = save_auth(base, tok, uid, t.get("device_id"))
                log(f"\n  Connected as {uid}. Saved to {p}")
                return 0
            if status == "denied":
                log("\n  Authorization could not be verified — reconnect to try again.")
                return 1
            log("\n  That link expired — reconnect to try again.")
            return 1
    except httpx.HTTPStatusError as e:
        log(f"  Error: server returned {e.response.status_code} from {base}.")
        return 1
    except httpx.HTTPError as e:
        log(f"  Error: couldn't reach the Atlaso server at {base} ({e}).")
        return 1
    finally:
        httpd.server_close()


def _acquire_lock(lock: Path, now: float) -> bool:
    """Atomically claim the connect lock (O_EXCL — race-safe vs two near-simultaneous
    hooks). False if a fresh lock already exists; a stale lock (> _LOCK_TTL) is reclaimed."""
    for _ in range(2):
        try:
            fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            try:
                if (now - lock.stat().st_mtime) >= _LOCK_TTL:
                    lock.unlink()  # stale → reclaim and retry
                    continue
            except OSError:
                pass
            return False
        else:
            try:
                os.write(fd, str(int(now)).encode())
            finally:
                os.close(fd)
            return True
    return False


def maybe_autoconnect(tool: str | None = None) -> bool:
    """Auto-trigger (called by hooks): if this machine isn't connected, spawn a
    DETACHED connect (which opens the browser) and return True. No-op + False if
    already connected, opted out, in CI, or a connect is already in flight. Fast:
    never blocks, never touches the network itself. `tool` (e.g. "claude-code")
    is propagated to the detached process so the authorize screen can name it."""
    if has_token():
        return False
    if os.environ.get("ATLASO_NO_CONNECT") or os.environ.get("ATLASO_EXTRACTING"):
        return False
    if os.environ.get("CI"):
        return False  # don't pop a browser / spawn a poller in CI or scripted runs
    d = config.atlaso_dir()
    try:
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
    except OSError:
        pass
    lock = _lock_path()
    if not _acquire_lock(lock, time.time()):
        return False
    try:  # connect.log holds the (short-lived) verification ticket — keep it 0600
        lfd = os.open(str(d / "connect.log"), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        log_f: Any = os.fdopen(lfd, "a")
    except OSError:
        log_f = subprocess.DEVNULL
    child_env = os.environ.copy()
    if tool:
        child_env["ATLASO_TOOL"] = tool  # detached connect reads this for /device/start
    try:
        subprocess.Popen(
            [sys.executable, "-m", "atlaso_client.connect"],
            stdin=subprocess.DEVNULL, stdout=log_f, stderr=log_f,
            env=child_env,
            start_new_session=True,  # fully detached; survives the hook returning
        )
    except Exception:
        try:
            lock.unlink()  # release so a later hook can retry, not wedged for the TTL
        except OSError:
            pass
        return False
    finally:
        if log_f is not subprocess.DEVNULL:
            try:
                log_f.close()  # parent's copy; the child dup'd its own fd
            except OSError:
                pass
    return True


def main() -> int:
    try:
        rc = connect()
    finally:
        try:
            _lock_path().unlink()  # release the autoconnect lock when done
        except OSError:
            pass
    return rc


if __name__ == "__main__":
    sys.exit(main())
