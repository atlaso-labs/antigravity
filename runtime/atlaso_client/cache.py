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
from typing import Any

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

-- Content-free daily "capture quality" telemetry (LabDirector ruling 2913669f:
-- counts only — NO content, NO content-derived hashes). Lets the dashboard show
-- "eligible exchanges captured = server-accepted deposits / eligible capture
-- opportunities". attempts = gate-PASSED user exchanges (the denominator);
-- accepted = deposits the server confirmed; drops_json = hygiene-dropped gate
-- reasons counted separately by reason. All per-UTC-day, monotonic integers.
CREATE TABLE IF NOT EXISTS capture_stats (
    day        TEXT PRIMARY KEY,
    attempts   INTEGER NOT NULL DEFAULT 0,
    accepted   INTEGER NOT NULL DEFAULT 0,
    drops_json TEXT NOT NULL DEFAULT '{}',
    -- per-day {hour -> attempts} spread map (content-free ints). Kept LOCAL: the
    -- payload derives only two ints from it (hours_active, max_hour_attempts) so a
    -- burst-replay looks different from genuine all-day usage without shipping the
    -- map itself.
    hours_json TEXT NOT NULL DEFAULT '{}'
);

-- Local supersession marks (id is superseded by by_id). Written by the client's
-- edge writer when a supersedes edge is recorded; read by capture's near-dup
-- search, which compares only against LIVE memories and treats a twin of a
-- superseded memory as a revert (kept), never as a duplicate.
CREATE TABLE IF NOT EXISTS superseded (
    id     TEXT PRIMARY KEY,
    by_id  TEXT NOT NULL,
    at     TEXT NOT NULL
);
"""

# Additive column migrations for caches created by older clients. Applied
# opportunistically at open; "duplicate column" errors mean already-migrated.
_MIGRATIONS = (
    "ALTER TABLE outbox ADD COLUMN edge_blocks INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE capture_stats ADD COLUMN hours_json TEXT NOT NULL DEFAULT '{}'",
)


# Capture's near-dup bucket (rung 404a1485). Two plain nullable columns on
# cached_deposits, written in PYTHON by this client's own writers (upsert_deposit,
# enqueue, rekey_scope after the _reconcile raw-SQL tag rewrite) and backfilled once
# by Python when they are added. No trigger, index or other schema object: a cache
# file stays writable by every client, including older clients on a SQLite build
# without JSON functions (round-2 finding D-092).
#   scope_key  = the row's (scope, project, project-unknown) bucket, see _scope_key_of;
#   scope_tags = the exact tags_json string scope_key was computed from.
# A row is trusted only when scope_key is set AND scope_tags still equals tags_json.
# Rows inserted by older clients carry NULL; rows whose tags an older client changed
# carry a stale scope_tags. Both are re-checked with the Python scope filter.
_SCOPE_COLUMNS = ("scope_key", "scope_tags")
# The round-2 build dc34871ff (withdrawn, never released) installed these; they call
# JSON functions on every write, so a cache that build touched loses them on open.
_WITHDRAWN_TRIGGERS = ("cached_deposits_scope_key_ai", "cached_deposits_scope_key_au")


def _row_tags(tags_json: str | None) -> list[Any]:
    """A cached row's tags as the Python readers see them: malformed JSON or a
    non-list value reads as [] (personal)."""
    try:
        tags = json.loads(tags_json) if tags_json else []
    except (ValueError, TypeError):
        return []
    return tags if isinstance(tags, list) else []


def _scope_key(scope: str, project: str | None, unknown: bool) -> str:
    """The scope_key of the bucket (scope, project, project-unknown marker)."""
    return f"{scope}|{'u' if unknown else 'k'}|{'-' if project is None else '=' + project}"


def _scope_key_of(tags: list[Any]) -> str:
    """A row's scope_key, from _project.scope_of (the capture filter's own
    definition). Orphaned rows key as 'orphaned|…', which no capture bucket matches."""
    from . import _project
    scope, project = _project.scope_of(tags)
    return _scope_key(scope, project, "project-unknown" in tags)


def _in_bucket(tags: list[Any], scope: str, project: str | None, unknown: bool) -> bool:
    """The Python scope filter for rows without a trusted scope_key."""
    return _scope_key_of(tags) == _scope_key(scope, project, unknown)


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


def _utc_day() -> str:
    """Today's UTC calendar day ('YYYY-MM-DD') — the bucket key for capture stats."""
    return time.strftime("%Y-%m-%d", time.gmtime())


def _day_of_iso(created_at: str | None) -> str:
    """The UTC day of a cache timestamp ('%Y-%m-%dT%H:%M:%SZ'); today when the
    value is missing or malformed. Used to attribute an accepted deposit back to
    the day its item was originally captured."""
    if created_at and len(created_at) >= 10 and re.match(r"\d{4}-\d{2}-\d{2}$", created_at[:10]):
        return created_at[:10]
    return _utc_day()


# Gate reasons that count as an eligible capture OPPORTUNITY (the `attempts`
# denominator). Every other should_deposit() reason is a hygiene drop, bucketed
# by reason in drops_json instead.
_ATTEMPT_REASONS = ("signal", "substantive")


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
        self._scope_key_ready = self._ensure_scope_columns()

    def _ensure_scope_columns(self) -> bool:
        """Make the cache ready for the scoped near-dup search. On a cache already
        migrated by this client this is two read-only catalogue reads (no write lock).
        Otherwise, in ONE write transaction: drop the withdrawn round-2 triggers, add
        the scope columns and key every row in Python. False when that cannot happen
        now (locked or read-only file); near-dup then Python-filters every candidate."""
        cols = self._columns()
        stale_triggers = self._withdrawn_triggers()
        if not stale_triggers and all(c in cols for c in _SCOPE_COLUMNS):
            return True
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            for name in _WITHDRAWN_TRIGGERS:
                self._conn.execute(f"DROP TRIGGER IF EXISTS {name}")
            cols = self._columns()
            for col in _SCOPE_COLUMNS:
                if col not in cols:
                    self._conn.execute(f"ALTER TABLE cached_deposits ADD COLUMN {col} TEXT")
            self._rekey_scope(everything=True)  # one-time backfill, same transaction
            self._conn.commit()
            return True
        except sqlite3.OperationalError:
            self._conn.rollback()
            # ready only if another client finished the job meanwhile: a surviving
            # withdrawn trigger may rewrite scope_key, so it keeps the cache not-ready
            return not self._withdrawn_triggers() and all(
                c in self._columns() for c in _SCOPE_COLUMNS)

    def _columns(self) -> set[str]:
        return {r[1] for r in self._conn.execute("PRAGMA table_info(cached_deposits)")}

    def _withdrawn_triggers(self) -> list[str]:
        return [r[0] for r in self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' AND name IN (?, ?)",
            _WITHDRAWN_TRIGGERS)]

    def _rekey_scope(self, *, everything: bool = False) -> int:
        """Recompute scope_key/scope_tags in Python for every row whose key is missing
        or stale (or for every row when `everything`). No commit: the caller owns the
        transaction. Returns the number of rows keyed."""
        where = "" if everything else " WHERE scope_key IS NULL OR scope_tags IS NOT tags_json"
        rows = self._conn.execute("SELECT id, tags_json FROM cached_deposits" + where).fetchall()
        self._conn.executemany(
            "UPDATE cached_deposits SET scope_key = ?, scope_tags = ? WHERE id = ?",
            [(_scope_key_of(_row_tags(r["tags_json"])), r["tags_json"], r["id"]) for r in rows])
        return len(rows)

    def rekey_scope(self) -> int:
        """Re-key rows whose tags changed outside this class (the _reconcile raw-SQL
        tag rewrite, or an older client sharing the file) and commit. Returns the
        number of rows keyed; 0 when the scope columns are not installed."""
        if not self._scope_key_ready:
            return 0
        n = self._rekey_scope()
        self._conn.commit()
        return n

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

    def get_meta(self, key: str) -> str | None:
        """Generic cache_meta read (one-shot markers, e.g. the junk-project
        reconcile). Cursors above keep their dedicated typed accessors."""
        r = self._conn.execute("SELECT v FROM cache_meta WHERE k = ?", (key,)).fetchone()
        return r["v"] if r else None

    def set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO cache_meta(k, v) VALUES(?, ?) "
            "ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            (key, value),
        )
        self._conn.commit()

    def get_changes_cursor(self) -> int:
        """Cursor into the server's change stream (in-place UPDATEs — polarity
        reclassification, retraction tags, evidence grade). Distinct from the
        deposit cursor: deposits page by rowid, changes by change-event seq."""
        r = self._conn.execute("SELECT v FROM cache_meta WHERE k = 'last_changes_seq'").fetchone()
        return int(r["v"]) if r else 0

    def set_changes_cursor(self, seq: int) -> None:
        self._conn.execute(
            "INSERT INTO cache_meta(k, v) VALUES('last_changes_seq', ?) "
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

    def _scope_write(self, tags_json: str) -> tuple[str, str, str, tuple[str, ...]]:
        """SQL fragments + values that key a row being written with `tags_json`:
        (column list, placeholders, ON CONFLICT assignments, values). Empty when the
        scope columns are not installed (the row is then keyed by the next migration)."""
        if not self._scope_key_ready:
            return "", "", "", ()
        return (", scope_key, scope_tags", ",?,?",
                ", scope_key=excluded.scope_key, scope_tags=excluded.scope_tags",
                (_scope_key_of(_row_tags(tags_json)), tags_json))

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
        tags_json = json.dumps(tags or [])
        cols, marks, sets, extra = self._scope_write(tags_json)
        self._conn.execute(
            "INSERT INTO cached_deposits"
            "(id, seq, content, polarity, evidence_grade, scope_note, created_at, "
            " tags_json, retracted, pending" + cols + ") VALUES(?,?,?,?,?,?,?,?,?,0" + marks + ") "
            "ON CONFLICT(id) DO UPDATE SET seq=excluded.seq, content=excluded.content, "
            "polarity=excluded.polarity, evidence_grade=excluded.evidence_grade, "
            "scope_note=excluded.scope_note, created_at=excluded.created_at, "
            "tags_json=excluded.tags_json, retracted=excluded.retracted, pending=0" + sets,
            (id, seq, content, polarity, evidence_grade, scope_note, created_at,
             tags_json, 1 if retracted else 0, *extra),
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
        cols, marks, _, extra = self._scope_write(tags_json)
        self._conn.execute(
            "INSERT OR REPLACE INTO cached_deposits"
            "(id, seq, content, polarity, evidence_grade, scope_note, created_at, "
            " tags_json, retracted, pending" + cols + ") VALUES(?,?,?,?,?,?,?,?,0,1" + marks + ")",
            (client_id, None, text, polarity, evidence_grade, scope_note, created_at, tags_json,
             *extra),
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
            # supersession marks follow the rekey (either side of the edge)
            self._conn.execute("UPDATE OR IGNORE superseded SET id = ? WHERE id = ?",
                               (server_id, client_id))
            self._conn.execute("UPDATE superseded SET by_id = ? WHERE by_id = ?",
                               (server_id, client_id))
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

    # ── capture near-dup candidates (scoped, live/superseded) ────────────────
    def near_dup_candidates(self, query: str, limit: int, *, scope: str,
                            project: str | None, unknown: bool,
                            superseded: bool = False) -> list[dict[str, Any]]:
        """Top-`limit` keyword hits (bm25 order) for capture's near-dup check, taken
        ONLY from the capture's own bucket, so other projects' rows can never crowd
        the same-project twin out:
          scope='project', project=K  → rows tagged scope:project whose project tag is K
          scope='project', project=None → unattributed project rows (no project: tag)
          scope='personal'            → rows with neither scope:project nor a project: tag
        `unknown` must match the row's project-unknown marker; orphaned rows never
        match. SQL keeps rows with a trusted scope_key equal to the bucket's, plus rows
        without a trusted key (NULL: written by an older client; stale: tags changed
        since keying). Only those untrusted rows go through the Python scope filter,
        and it runs BEFORE the `limit` cut. superseded=False returns LIVE rows only;
        True returns only rows marked superseded (with `superseded_by`), and skips the
        search outright while the superseded table is empty."""
        q = _fts_query(query)
        if not q:
            return []
        if superseded and self._conn.execute(
                "SELECT NOT EXISTS (SELECT 1 FROM superseded)").fetchone()[0]:
            return []
        live = "s.id IS NOT NULL" if superseded else "s.id IS NULL"
        if self._scope_key_ready:
            keyed = "(d.scope_key IS NOT NULL AND d.scope_tags IS d.tags_json)"
            where, args = f"(d.scope_key = ? OR NOT {keyed})", [_scope_key(scope, project, unknown)]
        else:  # columns not installed yet (locked/read-only at open): filter every row
            keyed, where, args = "0", "1", []
        cur = self._conn.execute(
            f"SELECT d.id, d.content, d.tags_json, s.by_id, {keyed} AS keyed "
            "FROM cached_fts f JOIN cached_deposits d ON d.id = f.deposit_id "
            "LEFT JOIN superseded s ON s.id = d.id "
            f"WHERE cached_fts MATCH ? AND d.retracted = 0 AND {live} AND {where} "
            "ORDER BY bm25(cached_fts)",
            [q, *args])
        out: list[dict[str, Any]] = []
        try:
            for r in cur:
                tags = _row_tags(r["tags_json"])
                if not r["keyed"] and not _in_bucket(tags, scope, project, unknown):
                    continue
                out.append({"id": r["id"], "content": r["content"], "tags": tags,
                            "superseded_by": r["by_id"]})
                if len(out) >= limit:
                    break
        finally:
            cur.close()  # release the read statement before capture writes
        return out

    def mark_superseded(self, old_id: str, by_id: str) -> None:
        """Record that `old_id` is superseded by `by_id` (the edge writer calls this
        once the supersedes edge is recorded)."""
        self._conn.execute(
            "INSERT INTO superseded(id, by_id, at) VALUES(?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET by_id = excluded.by_id, at = excluded.at",
            (old_id, by_id, _now_iso()))
        self._conn.commit()

    def content_of(self, deposit_id: str) -> str | None:
        """Content of a non-retracted cached memory, or None."""
        r = self._conn.execute(
            "SELECT content FROM cached_deposits WHERE id = ? AND retracted = 0",
            (deposit_id,)).fetchone()
        return r["content"] if r else None

    def live_superseder(self, deposit_id: str, max_hops: int = 32) -> str | None:
        """Follow superseded → by_id to the live head of the chain; None when
        `deposit_id` is not superseded (or the chain loops)."""
        cur, seen = deposit_id, set[str]()
        while len(seen) < max_hops:
            r = self._conn.execute("SELECT by_id FROM superseded WHERE id = ?", (cur,)).fetchone()
            if r is None:
                return None if cur == deposit_id else cur
            if cur in seen:
                return None
            seen.add(cur)
            cur = r["by_id"]
        return None

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

    # ── capture-quality telemetry (content-free daily counters) ───────────────
    def _apply_drop(self, day: str, reason: str, n: int) -> None:
        """Read-modify-write a per-day drop bucket (no commit — caller commits)."""
        row = self._conn.execute(
            "SELECT drops_json FROM capture_stats WHERE day = ?", (day,)).fetchone()
        try:
            drops = json.loads(row["drops_json"]) if row else {}
        except (ValueError, TypeError):
            drops = {}
        drops[reason] = int(drops.get(reason, 0)) + int(n)
        self._conn.execute(
            "UPDATE capture_stats SET drops_json = ? WHERE day = ?",
            (json.dumps(drops, sort_keys=True), day))

    def _bump_hour(self, day: str, hour: int | None) -> None:
        """Count one attempt into its UTC hour bucket (no commit). Used only to
        derive the two spread ints; the map never leaves the client."""
        hr = str(int(hour) if hour is not None else int(time.strftime("%H", time.gmtime())))
        row = self._conn.execute(
            "SELECT hours_json FROM capture_stats WHERE day = ?", (day,)).fetchone()
        try:
            hours = json.loads(row["hours_json"]) if row and row["hours_json"] else {}
        except (ValueError, TypeError):
            hours = {}
        hours[hr] = int(hours.get(hr, 0)) + 1
        self._conn.execute(
            "UPDATE capture_stats SET hours_json = ? WHERE day = ?",
            (json.dumps(hours, sort_keys=True), day))

    def record_capture_gate(self, reason: str, *, day: str | None = None,
                            hour: int | None = None) -> None:
        """Count one capture-gate evaluation for the given UTC day. A gate-PASSED
        reason (signal/substantive) increments `attempts` — the eligible-opportunity
        denominator — and its UTC hour bucket (spread signal); every other
        (hygiene-drop) reason increments its own bucket in drops_json. Content-free
        by construction: the ONLY things recorded are a fixed reason label and
        integer counts — never user text, never a content-derived value. Monotonic."""
        day = day or _utc_day()
        self._conn.execute(
            "INSERT INTO capture_stats(day) VALUES(?) ON CONFLICT(day) DO NOTHING", (day,))
        if reason in _ATTEMPT_REASONS:
            self._conn.execute(
                "UPDATE capture_stats SET attempts = attempts + 1 WHERE day = ?", (day,))
            self._bump_hour(day, hour)
        else:
            self._apply_drop(day, reason, 1)
        self._conn.commit()

    def add_capture_accepted(self, day: str, n: int = 1) -> None:
        """Add `n` server-accepted (status=="added") deposits to the given UTC day's
        counter. Content-free integer; monotonic."""
        if n <= 0:
            return
        self._conn.execute(
            "INSERT INTO capture_stats(day, accepted) VALUES(?, ?) "
            "ON CONFLICT(day) DO UPDATE SET accepted = accepted + excluded.accepted",
            (day, int(n)))
        self._conn.commit()

    def add_capture_accepted_for(self, created_at: str | None, n: int = 1) -> None:
        """Attribute `n` accepted deposits to the UTC day of `created_at` (the
        item's ORIGINAL capture day), or today when it's missing/malformed."""
        self.add_capture_accepted(_day_of_iso(created_at), n)

    def add_capture_drop(self, day: str, reason: str, n: int = 1) -> None:
        """Add `n` to a per-day drop bucket (e.g. server-deduped "duplicate")."""
        if n <= 0:
            return
        self._conn.execute(
            "INSERT INTO capture_stats(day) VALUES(?) ON CONFLICT(day) DO NOTHING", (day,))
        self._apply_drop(day, reason, n)
        self._conn.commit()

    def add_capture_drop_for(self, created_at: str | None, reason: str, n: int = 1) -> None:
        """Attribute a drop to the UTC day of `created_at` (the item's original
        capture day) — used for server-dedup 'duplicate', which is settled at push
        time but belongs to the day the item was captured."""
        self.add_capture_drop(_day_of_iso(created_at), reason, n)

    def capture_stats(self, limit: int = 35) -> list[dict]:
        """The last ≤`limit` UTC days of cumulative capture counters, OLDEST first.
        Each row: {day, attempts, accepted, drops, hours_active, max_hour_attempts}.
        Content-free — safe to attach to a sync payload. Deterministic order.

        INVARIANT enforced AT EMIT: accepted is clamped to attempts, so a snapshot
        can never claim more accepted deposits than eligible opportunities (a
        replay-only or manual-remember-only day never reads >100% capture quality).
        The two spread ints (distinct active UTC hours; busiest-hour attempts) are
        derived from the local hours map, which itself is never emitted."""
        rows = self._conn.execute(
            "SELECT day, attempts, accepted, drops_json, hours_json FROM capture_stats "
            "ORDER BY day DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in reversed(rows):  # newest ≤N days, re-sorted ascending for the wire
            try:
                drops = json.loads(r["drops_json"])
            except (ValueError, TypeError):
                drops = {}
            try:
                hours = json.loads(r["hours_json"]) if r["hours_json"] else {}
            except (ValueError, TypeError):
                hours = {}
            attempts = int(r["attempts"])
            hour_counts = [int(v) for v in hours.values()]
            out.append({
                "day": r["day"], "attempts": attempts,
                "accepted": min(int(r["accepted"]), attempts),  # invariant: ≤ attempts
                "drops": {k: int(v) for k, v in drops.items()},
                "hours_active": len(hour_counts),
                "max_hour_attempts": max(hour_counts) if hour_counts else 0,
            })
        return out

    def get_capture_stats_hash(self) -> str:
        """Hash of the counters as of the last successful send (empty string until
        a first send). Lets an outbox-empty flush skip when nothing changed."""
        r = self._conn.execute(
            "SELECT v FROM cache_meta WHERE k = 'capture_stats_hash'").fetchone()
        return r["v"] if r else ""

    def set_capture_stats_hash(self, h: str) -> None:
        self._conn.execute(
            "INSERT INTO cache_meta(k, v) VALUES('capture_stats_hash', ?) "
            "ON CONFLICT(k) DO UPDATE SET v = excluded.v", (h,))
        self._conn.commit()
