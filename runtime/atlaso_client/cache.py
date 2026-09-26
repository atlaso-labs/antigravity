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
  cache_meta       — sync cursors (deposit, tombstone, change stream)
  forgotten        — ids the user forgot (here or on another device); a pulled
                     row with one of these ids is never stored again

FORGET STICKS. A forgotten memory must never come back into this cache, whatever
order the server pages arrive in and whatever cursor state the cache is in:
  * remove() records the id in `forgotten` in the same transaction as the delete;
  * upsert_deposit() refuses a forgotten id, and never stores a retracted row's
    text (it prunes the row instead);
  * the three sync cursors are reset only together, in one transaction, through
    reset_sync_cursors(), which fails closed. Any future repair or resync command
    must use it; resetting one cursor alone is the defect this rule exists for.

FORGOTTEN TEXT LEAVES THE FILE. A plain DELETE only unlinks a row: its bytes stay
in free pages, in FTS5 index segments (FTS5 deletes lazily, by delete-key) and in
WAL frames, where `strings cache.db` still finds them. So:
  * the connection runs PRAGMA secure_delete=ON (freed pages are zeroed) and
    temp_store=MEMORY (a VACUUM's scratch copy never touches disk);
  * TWO MONOTONIC COUNTERS in cache_meta record what is owed. `deleted_gen` is
    raised in the SAME transaction as every delete of memory text; `scrubbed_gen`
    is raised only by a completed scrub. A scrub is owed iff
    deleted_gen > scrubbed_gen. Nothing ever deletes a marker, so no process can
    erase another process's deletion (no ABA);
  * scrub(): (1) in ONE write transaction read g = deleted_gen and run FTS5
    'optimize' (drops the lazily deleted entries); (2) wal_checkpoint(TRUNCATE),
    stopping if a reader keeps it busy; (3) only then scrubbed_gen =
    max(scrubbed_gen, g). A delete committed after (1) carries a higher
    generation and stays owed; a crash anywhere leaves it owed;
  * a cache file written by an older client is upgraded once: its retracted rows
    are deleted (raising deleted_gen), then optimize + VACUUM (text those clients
    deleted without secure_delete sits in free pages) + TRUNCATE. Its done marker
    is written only after the TRUNCATE succeeded.
MAINTENANCE NEVER BLOCKS A HOT PATH. Everything above that runs on open (and the
scope-column migration) runs with SQLite's busy handler off (busy_timeout 0): a lock
error is retried in Python against a real-clock limit of 100 ms per statement, all
inside ONE total deadline (OPEN_MAINTENANCE_S), with a progress handler that
interrupts a statement past the deadline. busy_timeout bounds planned sleep, not
wall time; in a timer-throttled process wall time can exceed it by more than 10x,
so maintenance is bounded by a real-clock deadline instead. Busy, locked or out of
time means deferred, never lost: the counters still say what is owed, and the
next open, forget or sync (the 30 s background path, which also runs the VACUUM
of a large legacy file) finishes it. Ordinary user-path writes keep the normal
5 s busy timeout: correctness wins there.
The FTS5 'secure-delete' table option is deliberately NOT used: once a row is
deleted with it set, FTS5 older than SQLite 3.42 can no longer read or write the
table ("invalid fts5 file format"), and every connector runtime on a machine
shares this one file, each on its own SQLite build. 'optimize' reaches the same
bytes on every version.
"""
from __future__ import annotations

import json
import re
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import _telemetry

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

-- Durable forget filter: ids forgotten on this device or learned from a server
-- tombstone. Survives every cursor reset, so a replayed deposit page can never
-- bring a forgotten memory back (a tombstoned id is never live again on the
-- server: re-remembering the same text mints a new id).
CREATE TABLE IF NOT EXISTS forgotten (
    id  TEXT PRIMARY KEY,
    at  TEXT NOT NULL
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


# Maintenance limits. Every open is treated as the smallest opener on any tool
# (claude-code and codex SessionStart: 3.0 s internal budget, start.py hook_budget;
# 5 s host fuse, hooks.json), so maintenance on open gets a small slice of it.
OPEN_MAINTENANCE_S = 0.5      # total deadline for ALL maintenance in one open
LONG_MAINTENANCE_S = 30.0     # the background sync path and forget's scrub cap
SWEEP_INLINE_BYTES = 1 << 20  # a legacy file this small is upgraded on any open
_MAINT_BUSY_MS = 100          # real-clock lock-retry limit per maintenance statement
_RETRY_SLEEP_S = 0.01         # between lock retries under maintenance
_USER_BUSY_MS = 5000          # busy timeout for user-path writes (sqlite3 default)
_PROGRESS_STEPS = 1000        # VM steps between deadline checks


class Cache:
    """Plain SQLite cache. Single-threaded use per instance (open one per process /
    per hook invocation). All writes commit immediately — the cache is small."""

    _maint_deadline: float | None = None  # set only inside _maintenance_limits
    _deferred_for_size = False            # set by the upgrade on a short open

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # timeout = the USER-path busy timeout (capture enqueue, sync writes);
        # maintenance sets it to 0 for its own statements only and restores it
        self._conn = sqlite3.connect(str(self.path), timeout=_USER_BUSY_MS / 1000)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        # per connection: zero freed pages, so deleted memory text is overwritten,
        # and keep a VACUUM's temporary copy of the file in memory
        self._conn.execute("PRAGMA secure_delete=ON")
        self._conn.execute("PRAGMA temp_store=MEMORY")
        self._conn.executescript(_SCHEMA)
        for mig in _MIGRATIONS:
            try:
                self._conn.execute(mig)
            except sqlite3.OperationalError:
                pass  # already migrated (duplicate column) — expected
        self._conn.commit()
        self._scope_key_ready = False
        # every open is treated as the SMALLEST opener (SessionStart: 3 s internal
        # budget, 5 s host fuse): bounded maintenance only, the rest deferred
        self.maintain(OPEN_MAINTENANCE_S)

    # ── maintenance: bounded, deferrable, never blocks a hot path ────────────
    def maintain(self, seconds: float = OPEN_MAINTENANCE_S, *, long: bool = False) -> bool:
        """Run the maintenance this file owes (scope-column migration, legacy
        upgrade, scrub), all inside ONE deadline of `seconds`, each statement under a
        real-clock lock-retry limit of _MAINT_BUSY_MS. `long` is the 30 s background
        path (sync): only it runs the VACUUM of a legacy file larger than
        SWEEP_INLINE_BYTES. Returns True when
        nothing is owed afterwards. Busy, locked, read-only or out of time: returns
        False and the owed work stays recorded (the counters), never raises."""
        deadline = time.monotonic() + seconds
        self._deferred_for_size = False
        with self._maintenance_limits(deadline):
            ready = self._guarded(self._ensure_scope_columns)
            self._scope_key_ready = bool(ready)
            upgraded = self._guarded(lambda: self._upgrade_legacy(long=long))
            if self._deferred_for_size:
                # the long path's upgrade optimizes the whole index anyway: do not
                # spend this short open on an optimize of a large legacy file
                return False
            scrubbed = self._guarded(self._scrub)
        return bool(upgraded) and bool(scrubbed)

    def _guarded(self, step: Any) -> Any:
        """One maintenance step: a busy/locked/interrupted/read-only error rolls
        back and yields None (deferred); the counters keep what is owed."""
        try:
            return step()
        except sqlite3.OperationalError:
            if self._conn.in_transaction:
                self._conn.rollback()
            return None

    @contextmanager
    def _maintenance_limits(self, deadline: float) -> Iterator[None]:
        """Run the statements inside with NO SQLite busy wait (lock waits are
        retried in Python for at most _MAINT_BUSY_MS each, see _write_txn and
        _checkpoint) and a hard deadline (progress handler interrupts a statement
        past it); the user-path busy timeout is restored after, on every exit.
        SQLite's own busy handler is not used here. busy_timeout bounds planned
        sleep, not wall time. In a timer-throttled process, wall time can exceed it
        by more than 10x. Bound maintenance with a real-clock deadline. (SQLite
        3.47.1, one machine, 2026-09-26: busy_timeout=100 cost 1.34-1.39 s per
        statement in a background-priority process, 0.12-0.13 s in an interactive
        one; research/artifacts/forget-sticks-r4/attribution_cell.py.) A
        time.monotonic() limit overshoots by at most one stretched sleep."""
        self._conn.execute("PRAGMA busy_timeout = 0")
        self._conn.set_progress_handler(
            lambda: 1 if time.monotonic() > deadline else 0, _PROGRESS_STEPS)
        self._maint_deadline = deadline
        try:
            yield
        finally:
            self._maint_deadline = None
            self._conn.set_progress_handler(None, 0)
            try:
                self._conn.execute(f"PRAGMA busy_timeout = {_USER_BUSY_MS}")
            except sqlite3.Error:
                pass

    def _retry_busy(self, attempt: Any) -> Any:
        """Call attempt() until it stops failing with a lock error, for at most
        _MAINT_BUSY_MS and never past the maintenance deadline; the last error
        is raised."""
        deadline = self._maint_deadline
        stop = time.monotonic() + _MAINT_BUSY_MS / 1000
        if deadline is not None:
            stop = min(stop, deadline)
        while True:
            try:
                return attempt()
            except sqlite3.OperationalError as e:
                if "locked" not in str(e) and "busy" not in str(e):
                    raise
                if deadline is None or time.monotonic() + _RETRY_SLEEP_S > stop:
                    raise
                time.sleep(_RETRY_SLEEP_S)

    def _write_txn(self) -> None:
        """BEGIN IMMEDIATE (take the write lock now, so reads inside it are the
        state the write commits against); bounded retry under maintenance."""
        if self._conn.in_transaction:
            self._conn.commit()
        self._retry_busy(lambda: self._conn.execute("BEGIN IMMEDIATE"))

    def _checkpoint(self) -> bool:
        """wal_checkpoint(TRUNCATE); True only when the WAL was fully written back
        and truncated. Busy (a reader on an old snapshot, a writer) is retried for
        at most _MAINT_BUSY_MS, then False."""
        def attempt() -> bool:
            if self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]:
                raise sqlite3.OperationalError("checkpoint busy")
            return True
        try:
            return bool(self._retry_busy(attempt))
        except sqlite3.OperationalError as e:
            if "busy" in str(e) or "locked" in str(e):
                return False
            raise

    # ── the two counters ─────────────────────────────────────────────────────
    _DELETED_GEN = "deleted_gen"
    _SCRUBBED_GEN = "scrubbed_gen"
    _LEGACY_PENDING_KEY = "scrub_pending"  # ef045bfbe's deletable marker (lab only)

    def _gen(self, key: str) -> int:
        v = self.get_meta(key)
        try:
            return int(v) if v is not None else 0
        except ValueError:
            return 0

    def _note_deleted(self) -> None:
        """Raise deleted_gen inside the CALLER'S transaction (no commit). Every
        delete of memory text calls this in the same transaction as the delete."""
        self._conn.execute(
            "INSERT INTO cache_meta(k, v) VALUES(?, '1') ON CONFLICT(k) DO UPDATE "
            "SET v = CAST(CAST(v AS INTEGER) + 1 AS TEXT)", (self._DELETED_GEN,))

    def _raise_scrubbed(self, g: int, *, done_marker: str | None = None) -> None:
        """scrubbed_gen = max(scrubbed_gen, g) in its own transaction (with the
        upgrade's done marker, when given); max() makes concurrent scrubbers safe
        in any order."""
        self._write_txn()
        if done_marker:
            self._set_meta_in_txn(done_marker, _now_iso())
        self._conn.execute(
            "INSERT INTO cache_meta(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE "
            "SET v = CAST(max(CAST(v AS INTEGER), CAST(excluded.v AS INTEGER)) AS TEXT)",
            (self._SCRUBBED_GEN, str(int(g))))
        self._conn.commit()

    def _scrub_owed(self) -> bool:
        """deleted_gen > scrubbed_gen (or ef045bfbe's marker is still present)."""
        return (self._gen(self._DELETED_GEN) > self._gen(self._SCRUBBED_GEN)
                or self.get_meta(self._LEGACY_PENDING_KEY) is not None)

    def scrub_pending(self) -> bool:
        """True while deleted memory text may still be in the file's bytes: a
        scrub is owed, or the one-time upgrade of an older client's file (its
        VACUUM) has not completed."""
        return self._scrub_owed() or self.get_meta(self._UPGRADED_KEY) is None

    def deleted_generation(self) -> int:
        """How many text deletes this file has recorded (monotonic)."""
        return self._gen(self._DELETED_GEN)

    # ── scrub: forgotten text leaves the file ────────────────────────────────
    def scrub(self, seconds: float = LONG_MAINTENANCE_S) -> bool:
        """Remove deleted memory text from the file's bytes, within `seconds`.
        True when nothing is owed afterwards; False when a reader kept the WAL from
        truncating, the file was locked or time ran out (still owed: the next
        forget, sync or open retries). A no-op read when nothing is owed. Never
        raises for a locked or read-only file."""
        deadline = time.monotonic() + seconds
        with self._maintenance_limits(deadline):
            return bool(self._guarded(self._scrub))

    def _scrub(self) -> bool:
        if not self._scrub_owed():
            return not self.scrub_pending()
        # (1) read the owed generation and optimize in ONE write transaction: every
        # delete counted in g committed before this optimize ran
        self._write_txn()
        if self._conn.execute("DELETE FROM cache_meta WHERE k = ?",
                              (self._LEGACY_PENDING_KEY,)).rowcount:
            self._note_deleted()  # the old marker becomes a generation, atomically
        g = self._gen(self._DELETED_GEN)
        self._conn.execute("INSERT INTO cached_fts(cached_fts) VALUES('optimize')")
        self._conn.commit()
        # (2) every WAL frame that held the text goes; a reader keeps it busy
        if not self._checkpoint():
            return False
        # (3) only now is g scrubbed
        self._raise_scrubbed(g)
        return not self.scrub_pending()

    # ── one-time upgrade of a file written by an older client ────────────────
    # _ROWS_KEY: retracted rows deleted and their residue recorded as owed.
    # _UPGRADED_KEY: optimize + VACUUM + TRUNCATE completed. The v2 marker written
    # by ef045bfbe (before its checkpoint result was known) is not trusted.
    _ROWS_KEY = "legacy_rows_swept_v3"
    _UPGRADED_KEY = "legacy_vacuumed_v3"
    _SWEPT_KEY = _UPGRADED_KEY

    def _upgrade_legacy(self, *, long: bool) -> bool:
        """Older clients kept a retracted row's TEXT behind a flag, and deleted
        forgotten rows without secure_delete (text in free pages, FTS5 segments and
        WAL frames). (a) Delete the retracted rows and raise deleted_gen, in one
        transaction, so the ordinary scrub owes their residue. (b) Estimate the
        VACUUM from page_count; a short opener defers a file larger than
        SWEEP_INLINE_BYTES to the long (sync) path. (c) optimize (reading g in the
        same transaction), VACUUM, TRUNCATE; only after the TRUNCATE succeeded write
        the done marker and scrubbed_gen = max(scrubbed_gen, g). True when done."""
        if self.get_meta(self._UPGRADED_KEY) is not None:
            return True
        if self.get_meta(self._ROWS_KEY) is None:
            self._write_txn()
            self._conn.execute(
                "DELETE FROM cached_fts WHERE deposit_id IN "
                "(SELECT id FROM cached_deposits WHERE retracted != 0)")
            self._conn.execute("DELETE FROM cached_deposits WHERE retracted != 0")
            self._note_deleted()  # residue of older clients' deletes is owed
            self._set_meta_in_txn(self._ROWS_KEY, _now_iso())
            self._conn.commit()
        size = (self._conn.execute("PRAGMA page_count").fetchone()[0]
                * self._conn.execute("PRAGMA page_size").fetchone()[0])
        if not long and size > SWEEP_INLINE_BYTES:
            _telemetry.log("cache", "legacy_upgrade_deferred", bytes=size)
            self._deferred_for_size = True
            return False
        started = time.monotonic()
        self._write_txn()
        g = self._gen(self._DELETED_GEN)
        self._conn.execute("INSERT INTO cached_fts(cached_fts) VALUES('optimize')")
        self._conn.commit()
        self._retry_busy(lambda: self._conn.execute("VACUUM"))
        if not self._checkpoint():
            _telemetry.log("cache", "legacy_upgrade_busy", bytes=size)
            return False
        self._raise_scrubbed(g, done_marker=self._UPGRADED_KEY)
        _telemetry.log("cache", "legacy_upgrade_done", bytes=size,
                       ms=int((time.monotonic() - started) * 1000))
        return True

    def _set_meta_in_txn(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO cache_meta(k, v) VALUES(?, ?) "
            "ON CONFLICT(k) DO UPDATE SET v = excluded.v", (key, value))

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
            self._write_txn()
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

    # ── sync cursors ─────────────────────────────────────────────────────────
    _CURSOR_KEYS = ("last_seq", "last_tomb_seq", "last_changes_seq")

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

    def advance_cursors(self, *, deposit: int, tomb: int, changes: int) -> None:
        """Store all three sync cursors in ONE transaction (a pull page's cursors
        move together or not at all)."""
        with self._conn:
            self._conn.executemany(
                "INSERT INTO cache_meta(k, v) VALUES(?, ?) "
                "ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                [(k, str(int(v))) for k, v in zip(self._CURSOR_KEYS, (deposit, tomb, changes))])

    def reset_sync_cursors(self) -> None:
        """The ONLY sanctioned way to make the next pull replay from the start: the
        deposit, tombstone and change-stream cursors go back to 0 together, in one
        write transaction. Fails closed: if the transaction cannot be taken or
        committed (locked or read-only file) it raises and no cursor moves. The
        `forgotten` filter is kept, so the replay cannot resurrect a forget."""
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.executemany("DELETE FROM cache_meta WHERE k = ?",
                                   [(k,) for k in self._CURSOR_KEYS])
            self._conn.commit()
        except sqlite3.Error:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise

    def is_forgotten(self, deposit_id: str) -> bool:
        return self._conn.execute(
            "SELECT 1 FROM forgotten WHERE id = ?", (deposit_id,)).fetchone() is not None

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
    def _index_fts(self, deposit_id: str, content: str) -> None:
        self._conn.execute("DELETE FROM cached_fts WHERE deposit_id = ?", (deposit_id,))
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
    ) -> bool:
        """Mirror one server row. Returns False when the row was NOT stored: its id
        is forgotten (never stored again), or it is retracted (its text is pruned
        from the cache instead of being kept behind a flag)."""
        if retracted or self.is_forgotten(id):
            self._prune(id)
            self._conn.commit()
            return False
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
             tags_json, 0, *extra),
        )
        self._index_fts(id, content)
        self._conn.commit()
        return True

    def _prune(self, deposit_id: str) -> None:
        """Delete a row and its keyword index entry and, when anything was deleted,
        raise deleted_gen in the same transaction (no commit)."""
        n = self._conn.execute("DELETE FROM cached_deposits WHERE id = ?", (deposit_id,)).rowcount
        n += self._conn.execute("DELETE FROM cached_fts WHERE deposit_id = ?", (deposit_id,)).rowcount
        if n:
            self._note_deleted()

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

        if server_id and self.is_forgotten(server_id):
            # the server settled this write onto a memory the user forgot: never
            # rekey a live local row onto a forgotten id
            self._prune(client_id)
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
        """Forget a memory locally: drop it from the cache + outbox + quarantine and
        record the id in `forgotten`, all in one transaction (used by forget and by
        server tombstones). A text delete raises deleted_gen in the same
        transaction; the caller runs scrub() afterwards (Client.forget and the end
        of every pull do), and an owed scrub also runs on the next open."""
        with self._conn:
            self._prune(deposit_id)
            n = self._conn.execute("DELETE FROM outbox WHERE client_id = ?",
                                   (deposit_id,)).rowcount
            n += self._conn.execute("DELETE FROM quarantine WHERE client_id = ?",
                                    (deposit_id,)).rowcount
            if n:
                self._note_deleted()
            self._conn.execute("INSERT OR IGNORE INTO forgotten(id, at) VALUES(?, ?)",
                               (deposit_id, _now_iso()))

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
