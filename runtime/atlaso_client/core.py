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

import uuid
from typing import Any, Optional

from . import config, state
from .api import AuthRejected, BrainAPI
from .cache import Cache

# Safety valve: never let a connector's per-turn call balloon. The server caps
# batch at 100; we push at most this many per sync tick.
_PUSH_BATCH = 100
_SYNC_PAGE = 500


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
        if api is not None:
            self.api = api
        elif _auto_api:
            self.api = self._resolve_api(server, token)
        else:
            self.api = None

    @staticmethod
    def _resolve_api(server: str | None, token: str | None) -> Optional[BrainAPI]:
        if not (server and token):
            auth = config.load_auth() or {}
            server = server or auth.get("server") or config.DEFAULT_SERVER
            token = token or auth.get("token")
        if not (server and token):
            return None  # not connected → offline mode
        try:
            return BrainAPI(server, token)
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
        """A reachable brain rejected our token (401/403) → go LOCAL-ONLY until the
        user reconnects. Transport errors are transient and are ignored here."""
        if isinstance(exc, AuthRejected):
            state.set_local_only(state.REVOKED, tool=self.tool, device_id=self._device_id)

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
                # Trust a local-only verdict only for the SAME identity: 'revoked'
                # is sticky until reconnect; 'not_entitled' re-checks once stale
                # (a dashboard plan/active-tool change). A foreign verdict re-verifies.
                if mine and st.get("reason") == state.REVOKED:
                    return False
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
        except AuthRejected:
            state.set_local_only(state.REVOKED, tool=tool, device_id=did)
            return False
        except Exception:
            # Transient (offline/5xx): we couldn't VERIFY entitlement, so we must
            # not grant a cloud window to an unverified identity (the server doesn't
            # gate by tool). Stay local this turn, leave state unchanged → retry
            # verification next time.
            return False
        if ent.get("needs_reconnect"):
            state.set_local_only(state.REVOKED, tool=tool, device_id=did)
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
            except AuthRejected:
                state.set_local_only(state.REVOKED, tool=tool, device_id=did)
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
            cid = self.remember(content, polarity="open", tags=tags, push=push)
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

    def _push(self) -> dict:
        """Drain the outbox via batch deposit. Returns {client_id: server_id} for
        every item the server settled (added or duplicate) — callers use it to learn
        the durable id. Adopts the server's (scrubbed) canonical text into the cache."""
        items = self.cache.list_outbox(limit=_PUSH_BATCH)
        if not items:
            return {}
        payload = [
            {
                "client_id": it["client_id"], "text": it["text"], "polarity": it["polarity"],
                "evidence_grade": it["evidence_grade"], "scope_note": it["scope_note"],
                "tags": it["tags"],
            }
            for it in items
        ]
        resp = self.api.deposit_batch(payload)
        mapping: dict[str, str] = {}
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
            elif status in ("rejected", "invalid"):
                # the server's gate refused it — drop the optimistic local row
                self.cache.resolve_outbox(cid, dropped=True)
            else:  # "error"/"pending"/unknown → leave queued, count the attempt
                self.cache.bump_attempt(cid)
        return mapping

    def _pull(self) -> int:
        pulled = 0
        for _ in range(1000):  # hard ceiling: never loop forever
            since = self.cache.get_cursor()
            tomb_since = self.cache.get_tomb_cursor()
            res = self.api.sync(since, tomb_since=tomb_since, limit=_SYNC_PAGE)
            deposits = res.get("deposits", [])
            for d in deposits:
                self.cache.upsert_deposit(
                    id=d["id"], seq=d.get("seq"), content=d.get("content", ""),
                    polarity=d.get("polarity"), evidence_grade=d.get("evidence_grade"),
                    scope_note=d.get("scope_note"), created_at=d.get("created_at"),
                    tags=d.get("tags") or [], retracted=bool(d.get("retracted")),
                )
            # apply forgets from other devices — prune them from the local cache/FTS
            for t in res.get("tombstones", []):
                if t.get("id"):
                    self.cache.remove(t["id"])
            pulled += len(deposits)
            next_cursor = int(res.get("next_cursor", since))
            next_tomb = int(res.get("next_tomb_cursor", tomb_since))
            advanced = False
            if next_cursor > since:
                self.cache.set_cursor(next_cursor)
                advanced = True
            if next_tomb > tomb_since:
                self.cache.set_tomb_cursor(next_tomb)
                advanced = True
            more = res.get("has_more") or res.get("has_more_tomb")
            # stop when both drained, or if neither cursor advanced (loop guard)
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
