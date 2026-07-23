"""The thin client core — the tool-agnostic foundation every connector reuses.

It does four things, and NOTHING tool-specific:
  • remember(text)  → write to the local cache + outbox instantly, push in the
                      background (best-effort). Returns immediately.
  • recall(query)   → ask the server (the smart engine) when online; fall back to
                      the local commodity keyword cache when offline.
  • sync_once()     → push the outbox, then pull new server deposits into the cache.
  • status()        → connected? pending? cached? cursor?

A per-tool connector (Claude Code hooks, Claude Desktop MCP, Codex, …) is just a
thin wrapper that captures that tool's conversation and calls these methods. See
the SEAM notes in README — the connector decides WHEN to call recall/remember/
sync_once; the core decides HOW.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from typing import Any, Optional

from . import _credential, _telemetry, config, state
from .api import AuthRejected, BrainAPI, EdgeBlocked, NotEntitled
from .cache import Cache

# Safety valve: never let a connector's per-turn call balloon. The server caps
# batch at 100; we push at most this many per sync tick.
_PUSH_BATCH = 100
_SYNC_PAGE = 500
# How many days of cumulative capture counters ride along on a push (content-free).
_STATS_DAYS = 35


class Client:
    """Tool-agnostic memory client. Construct once per process where possible
    (keeps the cache + keep-alive connection warm); cheap to construct per hook
    invocation too.

    Injectable for tests: pass ``api=`` (anything with recall/deposit_batch/sync)
    and/or ``cache=``. With no usable auth, ``api`` is None → fully offline:
    remember() still queues locally, recall() serves the local cache.
    """

    def __init__(
        self,
        *,
        api: Any | None = None,
        cache: Optional[Cache] = None,
        server: str | None = None,
        token: str | None = None,
        cache_path: str | None = None,
        tool: str | None = None,
        _auto_api: bool = True,
    ):
        self.cache = cache or Cache(cache_path or config.cache_path())
        # The connector that owns this client (e.g. "claude-code"). Used for plan
        # entitlement: on free, only the device's ACTIVE tool is cloud-linked; the
        # rest run LOCAL-ONLY. None → no per-tool gating (generic client / tests).
        self.tool = tool
        # This machine's device_id (from auth.json). With `tool`, it scopes the
        # cached cloud-link verdict so a different tool/device never inherits it.
        self._device_id = (config.load_auth() or {}).get("device_id")
        # Which credential file backed this session's token ("own" = this tool's, so a
        # 401 retires only IT; "shared" = the legacy bearer, which we must never delete
        # out from under the machine's other integrations).
        self._cred_source: str | None = None
        self._cred_token: str | None = None
        if api is not None:
            self.api = api
        elif _auto_api:
            self.api = self._resolve_api(server, token)
        else:
            self.api = None

    def _resolve_api(self, server: str | None, token: str | None) -> Optional[BrainAPI]:
        if server and token:  # explicit override (tests / embedding)
            try:
                return BrainAPI(server, token)
            except Exception:
                return None
        try:
            cred = _credential.resolve(self.tool)
        except _credential.ToolRemoved:
            # The user removed this tool from this device. Go quiet — do NOT fall back
            # to the shared bearer, which would resurrect exactly what they removed.
            state.set_local_only(state.AUTH_REJECTED, tool=self.tool,
                                 device_id=self._device_id)
            return None
        except _credential.ToolNotEntitled:
            # Free plan, another tool holds the slot. Local-only — and NOT on the
            # shared bearer, which would let this tool masquerade as the entitled one.
            state.set_local_only(state.NOT_ENTITLED, tool=self.tool,
                                 device_id=self._device_id)
            return None
        except Exception:
            cred = None
        if not cred or not cred.get("token"):
            return None  # not connected → offline mode
        self._cred_source = cred.get("source")
        self._cred_token = cred.get("token")
        # A FRESHLY MINTED credential must not inherit the dead one's punishment. The
        # run that got the 401 wrote an auth_rejected verdict with a 1-hour TTL; without
        # this, the next run — now holding a brand-new working credential — would keep
        # suppressing cloud sync for the rest of that hour, and a paying user would see
        # an outage we had already fixed. Forget the verdict; the next op re-verifies.
        if cred.get("minted"):
            state.invalidate()
        try:
            return BrainAPI(cred.get("server") or config.DEFAULT_SERVER, cred["token"])
        except Exception:
            return None

    @property
    def connected(self) -> bool:
        """Has a usable token (an API object). NOT the same as cloud-linked — a
        connected device can still be LOCAL-ONLY (revoked token / non-active tool);
        see cloud_mode()."""
        return self.api is not None

    # ── cloud-link state machine (linked vs local-only) ────────────────────────
    def cloud_mode(self) -> dict:
        """The current cloud-link verdict for a connector's notice. Reports
        not_connected when there's no token; otherwise the persisted verdict — but
        ONLY if it belongs to this (tool, device_id), so one tool's local-only
        notice never shows up under another tool."""
        if self.api is None:
            return {"mode": state.LOCAL_ONLY, "reason": state.NOT_CONNECTED,
                    "since": 0, "checked_at": 0, "active_tool": None, "grace": None}
        st = state.get()
        if not state.matches(st, self.tool, self._device_id):
            return state.default()  # foreign/absent verdict → no notice
        return st

    def _note_auth_failure(self, exc: BaseException) -> None:
        """Map a transport exception onto persisted cloud-link state. ONLY verified
        app verdicts move state: AuthRejected → auth_rejected/reconnect_required
        (TTL'd, self-healing), NotEntitled → not_entitled (soft, short TTL).
        EdgeBlocked (a WAF/edge 403 that is NOT verifiably ours) and every other
        transport error are TRANSIENT: state untouched, items stay queued — the
        exact discipline whose absence once let a Cloudflare block page silently
        kill all sync as a fake 'revoked'."""
        if isinstance(exc, AuthRejected):
            reason = (state.RECONNECT_REQUIRED if exc.code == "reconnect_required"
                      else state.AUTH_REJECTED)
            state.set_local_only(reason, tool=self.tool, device_id=self._device_id)
            _telemetry.log("auth", "auth_rejected", code=exc.code, tool=self.tool)
            # Retire ONLY the credential that was actually rejected. If this tool had
            # its own and it died (the user removed the tool, or it rotated), drop that
            # file so the next run re-bootstraps — and gets told to stay down if it was
            # revoked. Never delete the shared bearer: the machine's other integrations
            # are still riding it.
            if self._cred_source:
                _credential.retire(self.tool, self._cred_source, self._cred_token)
        elif isinstance(exc, NotEntitled):
            state.set_local_only(state.NOT_ENTITLED, tool=self.tool, device_id=self._device_id)
            _telemetry.log("auth", "not_entitled", tool=self.tool)
        elif isinstance(exc, EdgeBlocked):
            _telemetry.log("transport", "edge_block", status=exc.status,
                           cf_ray=exc.cf_ray, content_type=exc.content_type, tool=self.tool)

    def _online(self) -> bool:
        """Should we attempt a cloud call right now? True only when we have a token
        AND this (tool, device) is CLOUD-LINKED. A known-revoked / non-entitled
        identity returns False WITHOUT touching the network, so a dead token is
        never hammered. The verdict is cached (state.ENTITLEMENT_TTL) and scoped to
        the identity that produced it; a stale or foreign verdict triggers one quiet
        re-check via /v1/entitlement. Never raises (recall must never break a turn)."""
        if self.api is None:
            return False
        try:
            st = state.get()
            mine = state.matches(st, self.tool, self._device_id)
            if st.get("mode") == state.LOCAL_ONLY:
                # Trust a local-only verdict only for the SAME identity and only
                # while FRESH (per-reason TTL: auth rejections 1h, entitlement
                # 10min). NO verdict is forever-sticky — once stale we re-verify
                # quietly, so a wrong flip self-heals instead of killing sync
                # until a manual reconnect. Foreign verdicts always re-verify.
                if mine and state.is_fresh(st):
                    return False
                return self._verify_entitlement()
            # LINKED: trust only a fresh verdict for THIS identity; otherwise verify.
            if mine and state.is_fresh(st):
                return True
            return self._verify_entitlement()
        except Exception:
            return False  # never break the turn — fall back to local

    def _verify_entitlement(self) -> bool:
        """Ask the brain for this device's tool policy and persist the verdict
        (scoped to this tool + device). Returns True (cloud-linked) / False
        (local-only). A transport error keeps trying optimistically (the real op
        will transient-fallback); a 401/403 means revoked → local-only."""
        if self.api is None:
            return False
        tool, did = self.tool, self._device_id
        try:
            ent = self.api.entitlement()
        except AuthRejected as e:
            self._note_auth_failure(e)
            return False
        except Exception:
            # Transient (offline/5xx/edge-block): we couldn't VERIFY entitlement, so
            # we must not grant a cloud window to an unverified identity (the server
            # doesn't gate by tool). Stay local this turn, leave state unchanged →
            # retry verification next time.
            return False
        if ent.get("needs_reconnect"):
            state.set_local_only(state.RECONNECT_REQUIRED, tool=tool, device_id=did)
            return False
        # Downgrade grace: the brain keeps multi-tool sync alive for a short
        # window after a paid→free drop and reports it here so each tool can show
        # an upgrade banner (the EXPENSIVE features are already off server-side).
        grace = None
        if ent.get("in_grace"):
            grace = {"in_grace": True, "days_left": ent.get("grace_days_left"),
                     "tools_connected": ent.get("tools_connected")}
        if ent.get("multi_tool") or not self.tool:
            state.set_linked(tool=tool, device_id=did, grace=grace)
            return True
        active = ent.get("active_tool")
        if active is None:
            # No tool has claimed the (free) active slot yet — the first tool
            # self-activates instead of failing into local-only.
            try:
                claimed = self.api.claim_tool(self.tool)
                active = claimed.get("active_tool")
            except AuthRejected as e:
                self._note_auth_failure(e)
                return False
            except Exception:
                return False  # transient — stay local, retry verification next time
        if active == self.tool:
            state.set_linked(tool=tool, device_id=did)
            return True
        state.set_local_only(state.NOT_ENTITLED, active_tool=active, tool=tool, device_id=did)
        return False

    # ── write ────────────────────────────────────────────────────────────────
    def remember(
        self,
        text: str,
        *,
        polarity: str = "open",
        evidence_grade: str = "anecdotal",
        scope_note: str | None = None,
        tags: list[str] | None = None,
        push: bool = True,
    ) -> str:
        """Queue a memory locally (instant) and best-effort push it. Returns the
        client_id (also the server idempotency key, so a retry never duplicates).
        Never raises on a network problem — the item stays in the outbox."""
        client_id = uuid.uuid4().hex
        self.cache.enqueue(
            client_id=client_id, text=text, polarity=polarity,
            evidence_grade=evidence_grade, scope_note=scope_note, tags=tags,
        )
        if push and self._online():
            try:
                mapping = self._push()
                # return the DURABLE server id when the push settled, so a caller
                # (e.g. the MCP remember→forget flow) gets an id the server knows.
                return mapping.get(client_id, client_id)
            except Exception as e:
                self._note_auth_failure(e)  # revoked → local-only; transient → keep queued
        return client_id

    def capture(self, user_text: str, assistant_text: str | None = None,
                *, source_tag: str | None = None, push: bool = False,
                project: str | None = None) -> dict:
        """Commodity capture pipeline (no engine/IP): worth-keeping gate → secret
        scrub → scope route (personal vs project) → polarity hint → near-dup check
        vs the local cache → remember() with the right tags. Preserves the engine
        plugin's L1 capture quality on the thin client. Returns
        {saved, reason|id, scope, project}. Never raises."""
        from . import _capture, _project
        try:
            ok, reason = _capture.should_deposit(user_text)
            # Content-free capture-quality counter (LabDirector ruling 2913669f:
            # counts only). Guarded so a telemetry hiccup can never lose a memory.
            try:
                self.cache.record_capture_gate(reason)
            except Exception:
                pass
            if not ok:
                return {"saved": False, "reason": reason}
            content = _capture.scrub(user_text)[0]
            if assistant_text:
                a = _capture.scrub(assistant_text)[0].strip()
                if a:
                    content += f"\n\n(assistant: {a[:400]})"
            scope = _capture.classify_scope(user_text)
            pol = _capture.heuristic_polarity(user_text)
            tags = [source_tag or self.tool or "atlaso", "auto",
                    f"pol-hint:{pol}", f"scope:{scope}"]
            # Caller may supply the project key — connectors whose hook cwd is NOT
            # the repo (e.g. Antigravity, cwd = the plugin dir) pass it from the
            # event's workspace path; else derive it from the cwd. Only attached for
            # project-scoped captures.
            proj = (project if project is not None else _project.project_key()) if scope == "project" else None
            if proj:
                tags.append(f"project:{proj}")
            # near-dup vs the local commodity cache (offline-safe; no server call)
            try:
                for e in self.cache.keyword_search(content[:200], 5):
                    if _capture.near_dup(content, (e or {}).get("content", "")):
                        return {"saved": False, "reason": "near_dup"}
            except Exception:
                pass
            # Capture polarity (Week-1 Step 4): default "open" (legacy). With
            # ATLASO_CAPTURE_PENDING=1, auto-captures land as "pending" — the
            # honest "not yet classified" state the async classifier drains.
            # SEQUENCING: the flag stays OFF until the Step-5 classifier is
            # live in prod. pol-hint:* provenance tags are kept either way.
            capture_polarity = (
                "pending"
                if os.environ.get("ATLASO_CAPTURE_PENDING") == "1"
                else "open"
            )
            cid = self.remember(content, polarity=capture_polarity, tags=tags, push=push)
            return {"saved": True, "id": cid, "scope": scope, "project": proj}
        except Exception:
            return {"saved": False, "reason": "error"}

    # ── read ─────────────────────────────────────────────────────────────────
    def recall(self, query: str, limit: int = 5, project: str | None = None,
               session: str | None = None) -> dict:
        """Smart recall from the server when online; commodity local keyword search
        when offline. `project` (per-project scope key) filters server recall to
        personal + this-project memories. `session` (the caller's session id) lets
        the server log which memories were injected for the recall-usefulness judge.
        Always returns {source, results, is_confident, has_disagreement}. Never raises."""
        if self._online():
            try:
                res = self.api.recall(query, limit, project=project, session=session)
                res["source"] = "server"
                return res
            except Exception as e:
                self._note_auth_failure(e)  # fall through to the local floor
        try:
            # over-fetch then apply the SAME per-project visibility rule as the
            # server, so OFFLINE recall can't leak repo A's project memory into
            # repo B (Codex BLOCKER).
            from . import _project
            raw = self.cache.keyword_search(query, max(limit * 4, limit))
            results = [r for r in raw
                       if _project.visible_in_project(r.get("tags") or [], project)][:limit]
        except Exception:
            results = []  # SQLite lock/corruption/pathological FTS → empty, never raise
        return {
            "source": "local",
            "results": results,
            "is_confident": None,
            "has_disagreement": None,
            "verdict": "offline — local keyword match only",
        }

    def forget(self, deposit_id: str) -> bool:
        """Delete a memory by id, on the server AND in the local cache. Returns
        True only on a confirmed server delete. Offline → False (left untouched so
        it can't silently resurrect on the next pull); caller can report that."""
        if not self._online():
            return False
        try:
            self.api.delete(deposit_id)
        except Exception as e:
            self._note_auth_failure(e)
            return False
        self.cache.remove(deposit_id)
        return True

    def recent(self, limit: int = 10) -> list[dict]:
        """Most-recent memories — from the server when online, the local cache when
        offline. Each item: {id, content, polarity, created_at, tags}."""
        if self._online():
            try:
                res = self.api.recent(limit)
                return res.get("deposits", [])
            except Exception as e:
                self._note_auth_failure(e)
        return self.cache.recent(limit)

    def health(self) -> dict | None:
        """Server-side memory health (FMI + components + deposit_count), or None
        when offline."""
        if not self._online():
            return None
        try:
            return self.api.health()
        except Exception as e:
            self._note_auth_failure(e)
            return None

    def _ambient_identity(self) -> str | None:
        """Bind the cached block to server + account + device + tool (Codex MED).
        None when we lack a user_id/device_id → ineligible to load any ambient."""
        auth = config.load_auth() or {}
        server = auth.get("server") or config.DEFAULT_SERVER
        uid = auth.get("user_id")
        dev = auth.get("device_id") or self._device_id
        if not (uid and dev):
            return None
        return f"{server}:{uid}:{dev}:{self.tool}"

    def ambient(self) -> str | None:
        """The Ambient Memory orientation block — the SAME server source for every
        tool (connectors differ only in HOW they inject the returned string).
        Hits the network; None when offline / not cloud-linked / not paid / nothing
        to say. Never raises. For the hot path use ambient_cached()."""
        if not self._online():
            return None
        try:
            res = self.api.ambient()
        except Exception as e:
            self._note_auth_failure(e)
            return None
        block = res.get("block")
        return block if isinstance(block, str) and block.strip() else None

    def ambient_cached(self) -> str | None:
        """Hot path: the cached block ONLY (file-only, no network) so SessionStart
        stays instant. None when nothing fresh is cached.

        Gated on the persisted cloud-link verdict (Codex HIGH#1): if this identity
        is LOCAL-ONLY (token revoked / tool not entitled / not connected) we never
        serve a cached block AND clear it, so a stale paid-era block can't surface
        after revocation/de-entitlement or resurrect on re-link. The block's own
        TTL bounds the paid→free downgrade window (Codex HIGH#2); a fresh cached
        block IS a fresh paid verdict (it's only written when the server confirmed
        paid)."""
        ident = self._ambient_identity()
        if not ident:
            return None
        from . import _ambient
        if self.cloud_mode().get("mode") == state.LOCAL_ONLY:
            _ambient.save(self.tool, ident, None)  # clear — never serve / resurrect
            return None
        return _ambient.load(self.tool, ident)

    def refresh_ambient(self) -> None:
        """Background: fetch the block and cache it. Only writes on a definitive
        server answer (paid→block / free→null), so a transient offline never
        clobbers a good cached block. Best-effort, never raises."""
        if not self._online():
            return
        ident = self._ambient_identity()
        if not ident:
            return
        try:
            res = self.api.ambient()
        except Exception as e:
            self._note_auth_failure(e)
            return
        from . import _ambient
        _ambient.save(self.tool, ident, res.get("block"))

    # ── sync ─────────────────────────────────────────────────────────────────
    def sync_once(self) -> dict:
        """Push the outbox, then pull new server deposits. Returns {pushed, pulled}.
        Safe to call from a SessionEnd hook or a background thread. In LOCAL-ONLY
        (no token / revoked / non-active tool) this is a no-op for the cloud — the
        local cache + outbox are left intact so nothing is lost before re-linking."""
        if not self._online():
            return {"pushed": 0, "pulled": 0}
        try:
            pushed = len(self._push())
            pulled = self._pull()
        except Exception as e:
            self._note_auth_failure(e)
            return {"pushed": 0, "pulled": 0}
        # refresh the cached ambient block off the hot path (best-effort) so the
        # next SessionStart can emit it instantly.
        try:
            self.refresh_ambient()
        except Exception:
            pass
        return {"pushed": pushed, "pulled": pulled}

    @staticmethod
    def _item_payload(it: dict, *, b64: bool = False) -> dict:
        p = {
            "client_id": it["client_id"], "polarity": it["polarity"],
            "evidence_grade": it["evidence_grade"], "scope_note": it["scope_note"],
            "tags": it["tags"],
        }
        if b64:
            # WAF fallback: the plain text pattern-matched an edge rule; base64
            # denies the lexical match (the server decodes; content unchanged).
            import base64 as _b64
            p["text_b64"] = _b64.b64encode(it["text"].encode("utf-8")).decode("ascii")
        else:
            p["text"] = it["text"]
        return p

    def _apply_results(self, resp: dict, mapping: dict, created: dict | None = None) -> None:
        """Settle server per-item results into the outbox/cache (shared by the
        batch path and the per-item fallback path). `created` maps client_id →
        the item's original created_at, used to attribute an accepted deposit back
        to the day it was captured. Each outbox item settles here exactly once
        (resolve_outbox removes the row), so accepted is counted exactly once."""
        for res in resp.get("results", []):
            cid = res.get("client_id")
            if not cid:
                continue
            status = res.get("status")
            if status in ("added", "duplicate"):
                sid = res.get("id")
                # adopt the server's scrubbed text so the local cache never holds
                # (or recalls offline) content the server redacted.
                self.cache.resolve_outbox(cid, server_id=sid, content=res.get("text"))
                if sid:
                    mapping[cid] = sid
                # content-free counters, attributed to the item's capture day.
                # ONLY status=="added" is capture quality: a server-deduped
                # "duplicate" is the SAME memory arriving again (a 93x replay must
                # read ~0% captured, not 100%), so it lands in its own drop bucket
                # and never inflates accepted.
                try:
                    if status == "added":
                        self.cache.add_capture_accepted_for((created or {}).get(cid), 1)
                    else:
                        self.cache.add_capture_drop_for((created or {}).get(cid), "duplicate", 1)
                except Exception:
                    pass
            elif status in ("rejected", "invalid"):
                # the server's gate refused it — drop the optimistic local row
                self.cache.resolve_outbox(cid, dropped=True)
                _telemetry.log("push", "server_refused", client_id=cid, status=status)
            else:  # "error"/"pending"/unknown → leave queued, count the attempt
                self.cache.bump_attempt(cid)

    # An item is quarantined after this many INDIVIDUAL edge/WAF blocks (each one
    # already retried once more as base64). Poison must never wedge the queue.
    _EDGE_QUARANTINE_AFTER = 2
    # Per-item fallback aborts after this many CONSECUTIVE transient failures —
    # if the server/network is down, iterating the whole outbox is just noise.
    _TRANSIENT_ABORT_AFTER = 3

    # ── capture-quality stats attachment (content-free) ────────────────────────
    def _stats_payload(self) -> list[dict] | None:
        """Current content-free capture counters (last ≤35 days) or None when
        there are none. Never raises."""
        try:
            rows = self.cache.capture_stats(limit=_STATS_DAYS)
            return rows or None
        except Exception:
            return None

    @staticmethod
    def _stats_hash(rows: list[dict]) -> str:
        """A hash of the COUNTS themselves (not content) — used only to skip a
        redundant outbox-empty flush when nothing changed since the last send."""
        return hashlib.sha256(
            json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def _stats_dirty(self, rows: list[dict] | None) -> bool:
        """True when there ARE counters and they changed since the last send."""
        if not rows:
            return False
        try:
            return self._stats_hash(rows) != self.cache.get_capture_stats_hash()
        except Exception:
            return False

    def _mark_stats_sent(self, rows: list[dict] | None) -> None:
        if not rows:
            return
        try:
            self.cache.set_capture_stats_hash(self._stats_hash(rows))
        except Exception:
            pass

    def _deposit(self, payloads: list[dict], stats: list[dict] | None) -> dict:
        """deposit_batch with capture_stats attached only when there's something to
        send — so the wire shape (and any pre-field API double) is untouched when
        there are no stats. Attaching stats must never alter item delivery."""
        if stats is not None:
            return self.api.deposit_batch(payloads, capture_stats=stats)
        return self.api.deposit_batch(payloads)

    def _push(self) -> dict:
        """Drain the outbox. Fast path: one batch deposit. If the BATCH request
        itself fails for a non-auth reason (edge/WAF block, 5xx, timeout), fall
        back to item-by-item delivery so one poisoned item can't hold the rest
        hostage — the exact failure mode of the Cloudflare incident. Verified app
        auth verdicts (AuthRejected/NotEntitled) propagate to the caller.

        Content-free capture counters ride along on the batch (idempotent — the
        server max-merges). When the outbox is empty but the counters changed since
        the last send, a stats-only batch (items=[]) still goes out; when nothing
        changed and there's nothing to push, this is a no-op. Stats attachment can
        never wedge delivery: if the batch fails, the per-item fallback runs WITHOUT
        stats and the counters simply retry next tick.
        Returns {client_id: server_id} for every settled item."""
        items = self.cache.list_outbox(limit=_PUSH_BATCH)
        stats = self._stats_payload()
        if not items and not self._stats_dirty(stats):
            return {}
        mapping: dict[str, str] = {}
        created = {it["client_id"]: it["created_at"] for it in items}
        try:
            resp = self._deposit([self._item_payload(it) for it in items], stats)
        except (AuthRejected, NotEntitled):
            raise  # a verified app verdict — no point retrying per-item
        except Exception as e:
            _telemetry.log("push", "batch_failed", error=type(e).__name__,
                           status=getattr(e, "status", None),
                           cf_ray=getattr(e, "cf_ray", None), items=len(items))
            self._push_each(items, mapping, created)
            return mapping
        self._apply_results(resp, mapping, created)
        self._mark_stats_sent(stats)
        _telemetry.log("push", "push_ok", items=len(items), settled=len(mapping))
        return mapping

    def _push_each(self, items: list[dict], mapping: dict, created: dict | None = None) -> None:
        """Item-by-item fallback after a failed batch. Delivery semantics:
          • verified app auth verdict → stop (state transition upstream)
          • edge/WAF block → count it; retry once as base64; still blocked at the
            threshold → QUARANTINE (parked locally, never wedges the queue again)
          • 429 → back off entirely (stop this run)
          • other transient errors → count the attempt, keep going a little, but
            abort after a few consecutive failures (server likely down)."""
        transient_streak = 0
        for it in items:
            cid = it["client_id"]
            try:
                resp = self.api.deposit_batch([self._item_payload(it)])
            except (AuthRejected, NotEntitled) as e:
                self._note_auth_failure(e)
                return
            except EdgeBlocked as e:
                transient_streak = 0
                # One base64 retry — but its failures must be classified with the
                # SAME discipline as the first attempt: a verified auth verdict,
                # 429, or 5xx/timeout on the retry is NOT another edge block and
                # must never push the item toward quarantine.
                try:
                    if self._retry_b64(it, mapping, created):
                        continue
                except (AuthRejected, NotEntitled) as e2:
                    self._note_auth_failure(e2)
                    return
                except EdgeBlocked:
                    pass  # blocked in b64 form too — falls through to the counter
                except Exception as e2:
                    status = getattr(getattr(e2, "response", None), "status_code", None)
                    if status == 429:
                        _telemetry.log("push", "rate_limited", client_id=cid)
                        return
                    self.cache.bump_attempt(cid)
                    _telemetry.log("push", "transient_item", client_id=cid,
                                   error=type(e2).__name__, status=status)
                    continue  # transient on the retry — item stays queued as-is
                blocks = self.cache.bump_edge_block(cid)
                _telemetry.log("push", "edge_block_item", client_id=cid,
                               status=e.status, cf_ray=e.cf_ray, blocks=blocks)
                if blocks >= self._EDGE_QUARANTINE_AFTER:
                    self.cache.quarantine_outbox(cid, "edge_blocked")
                    _telemetry.log("push", "quarantined", client_id=cid,
                                   reason="edge_blocked",
                                   queue=self.cache.counts().get("pending"))
                continue
            except Exception as e:
                status = getattr(getattr(e, "response", None), "status_code", None)
                if status == 429:
                    _telemetry.log("push", "rate_limited", client_id=cid)
                    return  # back off — let the next sync tick retry everything
                self.cache.bump_attempt(cid)
                _telemetry.log("push", "transient_item", client_id=cid,
                               error=type(e).__name__, status=status)
                transient_streak += 1
                if transient_streak >= self._TRANSIENT_ABORT_AFTER:
                    return  # server/network likely down — stop hammering
                continue
            transient_streak = 0
            self._apply_results(resp, mapping, created)

    def _retry_b64(self, it: dict, mapping: dict, created: dict | None = None) -> bool:
        """One base64 retry for an edge-blocked item (denies the WAF its lexical
        match without changing content). True if the item settled. Exceptions
        PROPAGATE — the caller classifies them (auth vs 429 vs transient vs
        another edge block); swallowing them here once misfiled a 429 as an edge
        block and quarantined a good memory."""
        resp = self.api.deposit_batch([self._item_payload(it, b64=True)])
        before = len(mapping)
        self._apply_results(resp, mapping, created)
        settled = len(mapping) > before or not any(
            o["client_id"] == it["client_id"] for o in self.cache.list_outbox(limit=_PUSH_BATCH))
        if settled:
            _telemetry.log("push", "b64_rescued", client_id=it["client_id"])
        return settled

    def _pull(self) -> int:
        pulled = 0
        for _ in range(1000):  # hard ceiling: never loop forever
            since = self.cache.get_cursor()
            tomb_since = self.cache.get_tomb_cursor()
            ch_since = self.cache.get_changes_cursor()
            res = self.api.sync(since, tomb_since=tomb_since, limit=_SYNC_PAGE,
                                changes_cursor=ch_since)
            deposits = res.get("deposits", [])
            for d in deposits:
                self.cache.upsert_deposit(
                    id=d["id"], seq=d.get("seq"), content=d.get("content", ""),
                    polarity=d.get("polarity"), evidence_grade=d.get("evidence_grade"),
                    scope_note=d.get("scope_note"), created_at=d.get("created_at"),
                    tags=d.get("tags") or [], retracted=bool(d.get("retracted")),
                )
            # change stream: full current state of memories UPDATED in place on the
            # server (polarity reclassification, retraction tags, evidence grade)
            # since our changes cursor — the same idempotent upsert applies them.
            for d in res.get("changes", []):
                self.cache.upsert_deposit(
                    id=d["id"], seq=d.get("seq"), content=d.get("content", ""),
                    polarity=d.get("polarity"), evidence_grade=d.get("evidence_grade"),
                    scope_note=d.get("scope_note"), created_at=d.get("created_at"),
                    tags=d.get("tags") or [], retracted=bool(d.get("retracted")),
                )
            # apply forgets from other devices — prune them from the local cache/FTS.
            # Deliberately LAST within a page: if the same id appears in deposits/
            # changes and tombstones, the deletion must win (never resurrect).
            for t in res.get("tombstones", []):
                if t.get("id"):
                    self.cache.remove(t["id"])
            pulled += len(deposits)
            next_cursor = int(res.get("next_cursor", since))
            next_tomb = int(res.get("next_tomb_cursor", tomb_since))
            next_ch = int(res.get("changes_cursor", ch_since))
            advanced = False
            if next_cursor > since:
                self.cache.set_cursor(next_cursor)
                advanced = True
            if next_tomb > tomb_since:
                self.cache.set_tomb_cursor(next_tomb)
                advanced = True
            if next_ch > ch_since:
                self.cache.set_changes_cursor(next_ch)
                advanced = True
            more = (res.get("has_more") or res.get("has_more_tomb")
                    or res.get("has_more_changes"))
            # stop when all drained, or if no cursor advanced (loop guard)
            if not more or not advanced:
                break
        return pulled

    # ── introspection ────────────────────────────────────────────────────────
    def status(self) -> dict:
        """connected? + local counts (cached/pending/cursor) + server health (FMI,
        authoritative deposit_count) when online."""
        out = {"connected": self.connected, **self.cache.counts()}
        h = self.health()
        if h:
            out["fmi"] = h.get("fmi")
            out["total"] = h.get("deposit_count")
        return out

    def close(self) -> None:
        try:
            if self.api is not None and hasattr(self.api, "close"):
                self.api.close()
        finally:
            self.cache.close()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
