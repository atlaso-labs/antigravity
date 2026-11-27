"""Held notes: preview them, upload them only with a human's explicit OK, or decline.

Held notes are outbox rows an older Atlaso client queued before rows recorded their tool
(tool IS NULL). cache.db does not record which ACCOUNT those belong to: one may have been
captured while this device was linked to another account, or used by someone else. No sync
uploads one on its own; this entrypoint is the one human opt-in. The CLI's `atlaso held`
calls it through the plugin runtime. Rows this client stamped for a DIFFERENT account than the
one linked now are listed too (other_account); they cannot be added here and upload if that
account is connected again.

INTERFACE
  python -m atlaso_client.held [--tool T] [--include-untagged] [--json]
      Preview. Changes nothing (the cache is opened read-only).
  python -m atlaso_client.held --upload --tool T [--include-untagged]
                               (--yes --count N --snapshot S | <TTY confirmation>) [--json]
      Adopt exactly the previewed selection to tool T (stamped for the linked account), then
      run T's sync. T must be cloud-linked now. Without --yes a TTY prompt asks; with --yes
      both --count and --snapshot are required (else exit 2) and must equal the current
      selection (else exit 3). The snapshot id covers the rows' ids and bytes AND the linked
      account, so a re-link between preview and upload is refused. A second run is a no-op.
  python -m atlaso_client.held --decline --tool T --snapshot S [--json]
      "Not now" for exactly that selection: the held-notes reminder in T goes quiet for 30
      days or until the held set changes. Exit 0.

SELECTION through T: rows whose first tag is T (by_tool[T]); --include-untagged adds the
`untagged` rows (no first tag, "atlaso", "manual"). Never `other_tags` (named other tools,
e.g. cursor), never rows naming another Python connector, never `other_account`.

EXIT CODES  0 done / nothing to do / declined recorded · 1 error or T not linked ·
            2 confirmation needed, declined at the prompt, or --yes without --count/--snapshot ·
            3 --count or --snapshot does not match the current selection (re-preview)

JSON (--json, one object on stdout; never a token, a raw user id or note text)
  preview: {"action": "preview", "count", "first", "last",
            "by_tool": {tool: n}, "other_tags": {name: n}, "untagged": n, "other_account": n,
            "account": "the account this device is linked to",
            "account_label": "a•••@gmail.com" | null, "warning": WARNING,
            "selection": null | {"tool", "include_untagged", "count", "first", "last",
                                 "snapshot", "warning": WARNING}}
  upload:  {"action": "upload", "ok", "tool", "include_untagged", "account", "account_label",
            "selected", "adopted", "changed", "sent", "remaining", "snapshot",
            "error": null | code, "message"}
  decline: {"action": "decline", "ok", "tool", "snapshot", "matches_current",
            "quiet_until", "error": null | code, "message"}
  error codes: bad_tool, not_linked, confirmation_required, declined, missing_count,
               missing_snapshot, count_mismatch, snapshot_mismatch
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from typing import Any, Optional

from . import config
from .cache import HELD_SYNC_TOOLS, Cache, identity_acct

_PUSH_BATCH = 100
DEFAULT_ACCOUNT = "the account this device is linked to"
WARNING = ("Older versions of Atlaso didn't record which account a note belongs to, so Atlaso "
           "asks first. Add them only if they're yours.")
_TOOL_LABELS = {"claude-code": "Claude Code", "codex": "Codex", "antigravity": "Antigravity",
                "grok-build": "Grok"}


def current_account() -> Optional[str]:
    """Identity hash of the account in auth.json (server + user id, hashed), or None."""
    auth = config.load_auth() or {}
    return identity_acct(auth.get("server"), auth.get("user_id"))


def account_label(cache: Optional[Cache] = None) -> Optional[str]:
    """The server's masked label for the linked account (/v1/entitlement `account_hint`, kept
    by the client bound to that account), or None when the server sent none."""
    if cache is None:
        return None
    try:
        raw = cache.get_meta("account_hint")
        obj = json.loads(raw) if raw else {}
    except Exception:  # noqa: BLE001
        return None
    acct = current_account()
    hint = obj.get("hint") if isinstance(obj, dict) else None
    return hint if acct and obj.get("acct") == acct and isinstance(hint, str) and hint else None


def snapshot_id(rows: list[tuple], acct: Optional[str]) -> str:
    """Id of a selection: the linked account and every row's id and bytes (any change → new)."""
    h = hashlib.sha256(("acct:" + (acct or "-") + "\n").encode("utf-8"))
    for r in sorted(rows, key=lambda t: str(t[0])):
        h.update(json.dumps(list(r), ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()[:16]


def _range(rows: list[tuple]) -> tuple[Optional[str], Optional[str]]:
    days = sorted(str(r[-1])[:10] for r in rows if isinstance(r[-1], str) and r[-1])
    return (days[0], days[-1]) if days else (None, None)


def preview(cache: Cache, *, tool: Optional[str] = None,
            include_untagged: bool = False) -> dict:
    """Read only."""
    b = cache.held_breakdown()
    out: dict[str, Any] = {
        "action": "preview", "count": b["count"],
        "first": (b["first"] or "")[:10] or None, "last": (b["last"] or "")[:10] or None,
        "by_tool": dict(b["by_tool"]), "other_tags": dict(b["other_tags"]),
        "untagged": b["untagged"], "other_account": b["other_account"],
        "account": DEFAULT_ACCOUNT, "account_label": account_label(cache),
        "warning": WARNING, "selection": None,
    }
    if tool:
        snap = cache.held_snapshot(tool, include_untagged=include_untagged)
        first, last = _range(snap)
        out["selection"] = {"tool": tool, "include_untagged": include_untagged,
                            "count": len(snap), "first": first, "last": last,
                            "snapshot": snapshot_id(snap, current_account()),
                            "warning": WARNING}
    return out


def _to(p: dict) -> str:
    label = p.get("account_label")
    return f"{p['account']} ({label})" if label else p["account"]


def say_preview(p: dict) -> str:
    """The preview in plain words (no brackets when there is no account label)."""
    from .notice_policy import format_iso_day

    if not p["count"]:
        return "No held notes on this device."
    a, z = format_iso_day(p["first"]), format_iso_day(p["last"])
    span = (f" from {a} to {z}" if a != z else f" from {a}") if a and z else ""
    one = p["count"] == 1
    lines = [f"{p['count']} older note{'' if one else 's'}{span} "
             f"{'is' if one else 'are'} saved only on this device."]
    for t, n in sorted(p["by_tool"].items()):
        lines.append(f"  {n} saved by {_TOOL_LABELS.get(t, t)}")
    for t, n in sorted(p["other_tags"].items()):
        lines.append(f"  {n} saved by {t}")
    if p["untagged"]:
        lines.append(f"  {p['untagged']} with no tool recorded")
    if p["other_account"]:
        lines.append(f"  {p['other_account']} saved while this device was linked to a different "
                     "Atlaso account (they upload if you connect that account again)")
    sel = p.get("selection")
    if sel:
        extra = " and notes with no tool recorded" if sel["include_untagged"] else ""
        lines.append(f"Adding the ones saved by {_TOOL_LABELS.get(sel['tool'], sel['tool'])}"
                     f"{extra} would add {sel['count']} note{'' if sel['count'] == 1 else 's'} "
                     f"to {_to(p)}.")
    lines.append(p["warning"])
    return "\n".join(lines)


def _linked_client(tool: str):
    """The tool's own client, and whether its fresh verdict says cloud-linked now (and the
    linked account is the one in auth.json)."""
    from . import state
    from .core import Client

    c = Client(tool=tool)
    ok = bool(c._online())
    st = state.get()
    ok = ok and st.get("mode") == state.LINKED and state.matches(st, tool, c._device_id) \
        and state.is_fresh(st)
    if ok:
        c._note_linked()
        acct = current_account()
        ok = bool(acct) and acct == c.cache.linked_acct()
    return c, ok


def upload(*, tool: str, include_untagged: bool = False, yes: bool = False,
           count: Optional[int] = None, snapshot: Optional[str] = None,
           confirm: Any = None, client: Any = None) -> tuple[int, dict]:
    """Adopt exactly the confirmed selection to `tool`, then sync it. Returns (exit code, JSON).
    `confirm(preview) -> bool` asks a human (TTY); `client` is injectable for tests and must
    already be the linked client for `tool`."""
    res: dict[str, Any] = {"action": "upload", "ok": False, "tool": tool,
                           "include_untagged": include_untagged, "account": DEFAULT_ACCOUNT,
                           "account_label": None, "selected": 0, "adopted": 0, "changed": 0,
                           "sent": 0, "remaining": 0, "snapshot": None, "error": None,
                           "message": ""}
    if not tool or tool not in HELD_SYNC_TOOLS:
        res.update(error="bad_tool",
                   message=f"Unknown tool. Use one of: {', '.join(HELD_SYNC_TOOLS)}.")
        return 1, res
    if yes and count is None:
        res.update(error="missing_count", message="--yes needs --count N from the preview.")
        return 2, res
    if yes and not snapshot:
        res.update(error="missing_snapshot", message="--yes needs --snapshot S from the preview.")
        return 2, res
    label = _TOOL_LABELS.get(tool, tool)
    linked = True
    if client is None:
        client, linked = _linked_client(tool)
    try:
        if not linked:
            res.update(error="not_linked",
                       message=f"{label} is not connected to your Atlaso account on this device "
                               "right now. Run atlaso connect, then try again.")
            return 1, res
        cache = client.cache
        res["account_label"] = account_label(cache)
        acct = current_account()
        snap = cache.held_snapshot(tool, include_untagged=include_untagged)
        sid = snapshot_id(snap, acct)
        res.update(selected=len(snap), snapshot=sid)
        if yes:
            if count != len(snap):
                res.update(error="count_mismatch",
                           message="The held notes changed since the preview. Preview again.")
                return 3, res
            if snapshot != sid:
                res.update(error="snapshot_mismatch",
                           message="The held notes or the linked account changed since the "
                                   "preview. Preview again.")
                return 3, res
        if not snap:
            res.update(ok=True, message="Nothing to add: no held notes match.")
            return 0, res
        if not yes:
            if confirm is None:
                res.update(error="confirmation_required",
                           message="Run it in a terminal to confirm, or pass --yes --count N "
                                   "--snapshot S from the preview.")
                return 2, res
            if not confirm(preview(cache, tool=tool, include_untagged=include_untagged)):
                res.update(error="declined", message="Nothing was changed.")
                return 2, res
        got = cache.adopt_held_snapshot(tool, snap, acct)
        res.update(adopted=got["adopted"], changed=got["changed"])
        ids = {r[0] for r in snap}
        rounds = -(-max(got["adopted"], 1) // _PUSH_BATCH) + 2
        for _ in range(rounds):
            if not _left(cache, tool, ids):
                break
            if not client.sync_once().get("synced"):
                break
        left = _left(cache, tool, ids)
        res.update(remaining=left, sent=max(0, got["adopted"] - left), ok=True)
        to = _to({"account": res["account"], "account_label": res["account_label"]})
        res["message"] = (f"Added {res['sent']} note{'' if res['sent'] == 1 else 's'} to {to}."
                          + (f" {left} will finish uploading on the next sync." if left else ""))
        return 0, res
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass


def decline(*, tool: str, snapshot: Optional[str], cache: Optional[Cache] = None,
            now: Optional[float] = None) -> tuple[int, dict]:
    """Record "not now" for exactly this selection: T's reminder goes quiet for 30 days or
    until the held set changes. Never changes the cache."""
    from . import notice_policy

    res: dict[str, Any] = {"action": "decline", "ok": False, "tool": tool, "snapshot": snapshot,
                           "matches_current": False, "quiet_until": None, "error": None,
                           "message": ""}
    if not tool or tool not in HELD_SYNC_TOOLS:
        res.update(error="bad_tool",
                   message=f"Unknown tool. Use one of: {', '.join(HELD_SYNC_TOOLS)}.")
        return 1, res
    if not snapshot:
        res.update(error="missing_snapshot", message="--decline needs --snapshot S.")
        return 2, res
    own = cache is None
    cache = cache or Cache.open_readonly(config.cache_path())
    try:
        current = snapshot_id(cache.held_snapshot(tool), current_account())
    finally:
        if own:
            cache.close()
    until = notice_policy.record_declined(tool, snapshot, now=now)
    res.update(ok=True, matches_current=current == snapshot,
               quiet_until=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(until)),
               message="OK. Atlaso won't remind you about these notes for 30 days, or until "
                       "more are found.")
    return 0, res


def _left(cache: Cache, tool: str, ids: set) -> int:
    return sum(1 for r in cache.list_outbox(limit=100_000, tool=tool) if r["client_id"] in ids)


def _tty_confirm(as_json: bool):
    def ask(p: dict) -> bool:
        out = sys.stderr if as_json else sys.stdout
        print(say_preview(p), file=out)
        sel = p["selection"]
        print(f"Add these {sel['count']} notes to {_to(p)}? Type yes to continue: ",
              end="", file=out, flush=True)
        try:
            return sys.stdin.readline().strip().lower() == "yes"
        except (OSError, ValueError):
            return False
    return ask


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="atlaso held", description="Preview, add or decline held notes.")
    ap.add_argument("--tool", choices=HELD_SYNC_TOOLS)
    ap.add_argument("--include-untagged", action="store_true")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--upload", action="store_true")
    mode.add_argument("--decline", action="store_true")
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--count", type=int)
    ap.add_argument("--snapshot")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    if a.decline:
        if not a.tool:
            ap.error("--decline needs --tool")
        code, res = decline(tool=a.tool, snapshot=a.snapshot)
        print(json.dumps(res) if a.json else res["message"])
        return code
    if not a.upload:
        cache = Cache.open_readonly(config.cache_path())
        try:
            p = preview(cache, tool=a.tool, include_untagged=a.include_untagged)
        finally:
            cache.close()
        print(json.dumps(p) if a.json else say_preview(p))
        return 0
    if not a.tool:
        ap.error("--upload needs --tool")
    confirm = None
    if not a.yes and sys.stdin.isatty():
        confirm = _tty_confirm(a.json)
    code, res = upload(tool=a.tool, include_untagged=a.include_untagged, yes=a.yes,
                       count=a.count, snapshot=a.snapshot, confirm=confirm)
    print(json.dumps(res) if a.json else res["message"])
    return code


if __name__ == "__main__":
    sys.exit(main())
