"""Local commodity cache for the thin client — a plain SQLite mirror of the
user's memories plus an outbox of not-yet-synced local writes.

This is intentionally COMMODITY (standard SQLite + FTS5 keyword search): it holds
NO proprietary ranking/gate/health logic. It exists for two reasons only:
  1. instant local writes (the user's save feels immediate), queued for push;
  2. an offline fallback for recall (basic keyword match) when the server (which
     runs the real smart engine) is unreachable.

Tables:
  cached_deposits  — mirror of server deposits (+ optimistic local rows, pending=1)
  cached_fts       — FTS5 keyword index over content (offline recall)
  outbox           — local writes awaiting push to the server
  cache_meta       — sync cursor (last server `seq` we've pulled)
"""
from __future__ import annotations

import json
import re
import sqlite3
import time
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cached_deposits (
    id             TEXT PRIMARY KEY,   -- server deposit id; or local client_id until synced
    seq            INTEGER,            -- server rowid cursor; NULL while pending
    content        TEXT NOT NULL,
    polarity       TEXT,
    evidence_grade TEXT,
    scope_note     TEXT,
    created_at     TEXT,
    tags_json      TEXT NOT NULL DEFAULT '[]',
    retracted      INTEGER NOT NULL DEFAULT 0,
    pending        INTEGER NOT NULL DEFAULT 0  -- 1 = optimistic local row, not server-confirmed
);
CREATE INDEX IF NOT EXISTS cached_deposits_seq_idx ON cached_deposits(seq);

CREATE VIRTUAL TABLE IF NOT EXISTS cached_fts
    USING fts5(deposit_id UNINDEXED, content, tokenize='porter unicode61');

CREATE TABLE IF NOT EXISTS cache_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS outbox (
    client_id      TEXT PRIMARY KEY,
    text           TEXT NOT NULL,
    polarity       TEXT NOT NULL DEFAULT 'open',
    evidence_grade TEXT NOT NULL DEFAULT 'anecdotal',
    scope_note     TEXT,
    tags_json      TEXT NOT NULL DEFAULT '[]',
    created_at     TEXT NOT NULL,
    attempts       INTEGER NOT NULL DEFAULT 0,
    edge_blocks    INTEGER NOT NULL DEFAULT 0
);

-- Items that repeatedly fail to deliver for a NON-transient reason (edge/WAF
-- block, oversize) are PARKED here instead of wedging the outbox forever
-- (one poisoned item must never block the batch). The optimistic row in
-- cached_deposits STAYS, so the memory remains locally recallable.
CREATE TABLE IF NOT EXISTS quarantine (
    client_id      TEXT PRIMARY KEY,
    text           TEXT NOT NULL,
    polarity       TEXT NOT NULL DEFAULT 'open',
    evidence_grade TEXT NOT NULL DEFAULT 'anecdotal',
    scope_note     TEXT,
    tags_json      TEXT NOT NULL DEFAULT '[]',
    created_at     TEXT NOT NULL,
    reason         TEXT NOT NULL,
    quarantined_at TEXT NOT NULL
);
"""

# Additive column migrations for caches created by older clients. Applied
# opportunistically at open; "duplicate column" errors mean already-migrated.
_MIGRATIONS = (
    "ALTER TABLE outbox ADD COLUMN edge_blocks INTEGER NOT NULL DEFAULT 0",
)

_WORD_RE = re.compile(r"[A-Za-z0-9]+")


def _fts_query(text: str) -> str:
    """Sanitise free text into a safe FTS5 MATCH expression. Each alnum token is
    wrapped as a quoted string literal (so a stray "OR"/"AND"/"NEAR" in the user's
    text can't act as an FTS5 operator) and the literals are OR-joined (recall over
    precision — the server does the smart ranking online; this is the offline floor).
    Returns '' if there's nothing searchable."""
    toks = _WORD_RE.findall(text or "")
    return " OR ".join(f'"{t}"' for t in toks) if toks else ""


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Cache:
    """Plain SQLite cache. Single-threaded use per instance (open one per process /
    per hook invocation). All writes commit immediately — the cache is small."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        for mig in _MIGRATIONS:
            try:
                self._conn.execute(mig)
            except sqlite3.OperationalError:
                pass  # already migrated (duplicate column) — expected
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Cache":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ── sync cursor ──────────────────────────────────────────────────────────
    def get_cursor(self) -> int:
        r = self._conn.execute("SELECT v FROM cache_meta WHERE k = 'last_seq'").fetchone()
        return int(r["v"]) if r else 0

    def set_cursor(self, seq: int) -> None:
        self._conn.execute(
            "INSERT INTO cache_meta(k, v) VALUES('last_seq', ?) "
            "ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            (str(int(seq)),),
        )
        self._conn.commit()

    def get_tomb_cursor(self) -> int:
        r = self._conn.execute("SELECT v FROM cache_meta WHERE k = 'last_tomb_seq'").fetchone()
        return int(r["v"]) if r else 0

    def set_tomb_cursor(self, seq: int) -> None:
        self._conn.execute(
            "INSERT INTO cache_meta(k, v) VALUES('last_tomb_seq', ?) "
            "ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            (str(int(seq)),),
        )
        self._conn.commit()

    # ── FTS index helper ─────────────────────────────────────────────────────
    def _index_fts(self, deposit_id: str, content: str, *, retracted: bool = False) -> None:
        self._conn.execute("DELETE FROM cached_fts WHERE deposit_id = ?", (deposit_id,))
        if not retracted:
            self._conn.execute(
                "INSERT INTO cached_fts(deposit_id, content) VALUES(?, ?)",
                (deposit_id, content),
            )

    # ── server → cache (pull) ────────────────────────────────────────────────
    def upsert_deposit(
        self,
        *,
        id: str,
        seq: int | None,
        content: str,
        polarity: str | None = None,
        evidence_grade: str | None = None,
        scope_note: str | None = None,
        created_at: str | None = None,
        tags: list[str] | None = None,
        retracted: bool = False,
    ) -> None:
        self._conn.execute(
            "INSERT INTO cached_deposits"
            "(id, seq, content, polarity, evidence_grade, scope_note, created_at, "
            " tags_json, retracted, pending) VALUES(?,?,?,?,?,?,?,?,?,0) "
            "ON CONFLICT(id) DO UPDATE SET seq=excluded.seq, content=excluded.content, "
            "polarity=excluded.polarity, evidence_grade=excluded.evidence_grade, "
            "scope_note=excluded.scope_note, created_at=excluded.created_at, "
            "tags_json=excluded.tags_json, retracted=excluded.retracted, pending=0",
            (id, seq, content, polarity, evidence_grade, scope_note, created_at,
             json.dumps(tags or []), 1 if retracted else 0),
        )
        self._index_fts(id, content, retracted=retracted)
        self._conn.commit()

    # ── local write (remember) → cache + outbox ──────────────────────────────
    def enqueue(
        self,
        *,
        client_id: str,
        text: str,
        polarity: str = "open",
        evidence_grade: str = "anecdotal",
        scope_note: str | None = None,
        tags: list[str] | None = None,
        created_at: str | None = None,
    ) -> None:
        created_at = created_at or _now_iso()
        tags_json = json.dumps(tags or [])
        self._conn.execute(
            "INSERT OR REPLACE INTO outbox"
            "(client_id, text, polarity, evidence_grade, scope_note, tags_json, created_at, attempts) "
            "VALUES(?,?,?,?,?,?,?,0)",
            (client_id, text, polarity, evidence_grade, scope_note, tags_json, created_at),
        )
        # optimistic local row so recall sees it immediately (pending=1, no seq yet)
        self._conn.execute(
            "INSERT OR REPLACE INTO cached_deposits"
            "(id, seq, content, polarity, evidence_grade, scope_note, created_at, "
            " tags_json, retracted, pending) VALUES(?,?,?,?,?,?,?,?,0,1)",
            (client_id, None, text, polarity, evidence_grade, scope_note, created_at, tags_json),
        )
        self._index_fts(client_id, text)
        self._conn.commit()

    def list_outbox(self, limit: int = 100) -> list[dict]:
        rows = self._conn.execute(
            "SELECT client_id, text, polarity, evidence_grade, scope_note, tags_json, "
            "attempts, edge_blocks, created_at "
            "FROM outbox ORDER BY created_at LIMIT ?",
            (limit,),
        ).fetchall()
        out = []
        for r in rows:
            try:
                tags = json.loads(r["tags_json"])
            except (ValueError, TypeError):
                tags = []
            out.append({
                "client_id": r["client_id"], "text": r["text"], "polarity": r["polarity"],
                "evidence_grade": r["evidence_grade"], "scope_note": r["scope_note"],
                "tags": tags, "attempts": r["attempts"],
                "edge_blocks": r["edge_blocks"], "created_at": r["created_at"],
            })
        return out

    def bump_attempt(self, client_id: str) -> None:
        self._conn.execute("UPDATE outbox SET attempts = attempts + 1 WHERE client_id = ?", (client_id,))
        self._conn.commit()

    def bump_edge_block(self, client_id: str) -> int:
        """Count an INDIVIDUAL edge/WAF block against this item. Returns the new
        count — the caller quarantines once it crosses the threshold."""
        self._conn.execute(
            "UPDATE outbox SET edge_blocks = edge_blocks + 1, attempts = attempts + 1 "
            "WHERE client_id = ?", (client_id,))
        self._conn.commit()
        r = self._conn.execute(
            "SELECT edge_blocks FROM outbox WHERE client_id = ?", (client_id,)).fetchone()
        return int(r["edge_blocks"]) if r else 0

    def quarantine_outbox(self, client_id: str, reason: str) -> None:
        """Park a poisoned outbox item so it can never wedge the queue again. The
        optimistic cached_deposits row is DELIBERATELY kept (still recallable
        locally) — quarantine is about delivery, not about the memory itself."""
        self._conn.execute(
            "INSERT OR REPLACE INTO quarantine"
            "(client_id, text, polarity, evidence_grade, scope_note, tags_json, "
            " created_at, reason, quarantined_at) "
            "SELECT client_id, text, polarity, evidence_grade, scope_note, tags_json, "
            "       created_at, ?, ? FROM outbox WHERE client_id = ?",
            (reason, _now_iso(), client_id),
        )
        self._conn.execute("DELETE FROM outbox WHERE client_id = ?", (client_id,))
        self._conn.commit()

    def list_quarantine(self, limit: int = 100) -> list[dict]:
        rows = self._conn.execute(
            "SELECT client_id, reason, quarantined_at, created_at FROM quarantine "
            "ORDER BY quarantined_at DESC LIMIT ?", (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def oldest_pending_at(self) -> str | None:
        """created_at of the oldest queued item (ISO), or None when empty — used
        by the flush debounce to force a push when items are going stale."""
        r = self._conn.execute("SELECT min(created_at) AS m FROM outbox").fetchone()
        return r["m"] if r and r["m"] else None

    def resolve_outbox(
        self, client_id: str, *, server_id: str | None = None,
        dropped: bool = False, content: str | None = None,
    ) -> None:
        """Settle an outbox item after a push attempt.
          dropped=True            → server refused it (gate/invalid): remove the optimistic row.
          server_id given         → rekey the optimistic row to the server id (so the next
                                     pull upserts onto it instead of duplicating).
          server_id == client_id  → just clear the pending flag.
          content given           → adopt the server's canonical (scrubbed) text into the
                                     cache + FTS, so offline recall never shows un-scrubbed text.
        """
        self._conn.execute("DELETE FROM outbox WHERE client_id = ?", (client_id,))
        if dropped:
            self._conn.execute("DELETE FROM cached_deposits WHERE id = ?", (client_id,))
            self._conn.execute("DELETE FROM cached_fts WHERE deposit_id = ?", (client_id,))
            self._conn.commit()
            return

        if server_id and server_id != client_id:
            exists = self._conn.execute(
                "SELECT 1 FROM cached_deposits WHERE id = ?", (server_id,)
            ).fetchone()
            if exists:
                # server row already pulled — drop the optimistic duplicate
                self._conn.execute("DELETE FROM cached_deposits WHERE id = ?", (client_id,))
                self._conn.execute("DELETE FROM cached_fts WHERE deposit_id = ?", (client_id,))
                self._conn.commit()
                return
            self._conn.execute(
                "UPDATE cached_deposits SET id = ?, pending = 0 WHERE id = ?",
                (server_id, client_id),
            )
            self._conn.execute(
                "UPDATE cached_fts SET deposit_id = ? WHERE deposit_id = ?",
                (server_id, client_id),
            )
            final_id = server_id
        else:
            self._conn.execute("UPDATE cached_deposits SET pending = 0 WHERE id = ?", (client_id,))
            final_id = client_id

        if content is not None:
            self._conn.execute(
                "UPDATE cached_deposits SET content = ? WHERE id = ?", (content, final_id))
            self._index_fts(final_id, content)
        self._conn.commit()

    # ── offline recall (commodity keyword search) ────────────────────────────
    def keyword_search(self, query: str, limit: int = 5) -> list[dict]:
        q = _fts_query(query)
        if not q:
            return []
        rows = self._conn.execute(
            "SELECT d.id, d.content, d.polarity, d.created_at, d.tags_json, d.pending "
            "FROM cached_fts f JOIN cached_deposits d ON d.id = f.deposit_id "
            "WHERE cached_fts MATCH ? AND d.retracted = 0 "
            "ORDER BY bm25(cached_fts) LIMIT ?",
            (q, limit),
        ).fetchall()
        out = []
        for r in rows:
            try:
                tags = json.loads(r["tags_json"])
            except (ValueError, TypeError):
                tags = []
            out.append({
                "id": r["id"], "content": r["content"], "polarity": r["polarity"],
                "created_at": r["created_at"], "tags": tags, "pending": bool(r["pending"]),
            })
        return out

    def recent(self, limit: int = 10) -> list[dict]:
        """Most-recent memories from the cache (offline fallback for `recent`).
        Pending local writes (no seq yet) sort first, then newest server rows."""
        rows = self._conn.execute(
            "SELECT id, content, polarity, created_at, tags_json, pending "
            "FROM cached_deposits WHERE retracted = 0 "
            "ORDER BY (seq IS NULL) DESC, seq DESC, created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        out = []
        for r in rows:
            try:
                tags = json.loads(r["tags_json"])
            except (ValueError, TypeError):
                tags = []
            out.append({
                "id": r["id"], "content": r["content"], "polarity": r["polarity"],
                "created_at": r["created_at"], "tags": tags, "pending": bool(r["pending"]),
            })
        return out

    def remove(self, deposit_id: str) -> None:
        """Drop a memory from the cache + outbox + quarantine (used by forget)."""
        self._conn.execute("DELETE FROM cached_deposits WHERE id = ?", (deposit_id,))
        self._conn.execute("DELETE FROM cached_fts WHERE deposit_id = ?", (deposit_id,))
        self._conn.execute("DELETE FROM outbox WHERE client_id = ?", (deposit_id,))
        self._conn.execute("DELETE FROM quarantine WHERE client_id = ?", (deposit_id,))
        self._conn.commit()

    # ── introspection (for connectors / status / debugging) ──────────────────
    def counts(self) -> dict:
        total = self._conn.execute(
            "SELECT count(*) AS n FROM cached_deposits WHERE retracted = 0"
        ).fetchone()["n"]
        pending = self._conn.execute("SELECT count(*) AS n FROM outbox").fetchone()["n"]
        quarantined = self._conn.execute("SELECT count(*) AS n FROM quarantine").fetchone()["n"]
        return {"cached": int(total), "pending": int(pending),
                "quarantined": int(quarantined), "cursor": self.get_cursor()}
