"""Client half of the junk-project-key rescue (the plugin-cwd bug).

Old hooks minted project keys from their own plugin-install paths (see
_project.py header; field deposit 52c7e97d). Only THIS machine can prove which
keys are junk: it enumerates the plugin-install layouts that exist (or ever
plausibly existed) locally, hashes them with the LEGACY hash basis old clients
used, intersects with the project keys actually present in the local cache
mirror, and submits the intersection to POST /v1/memories/reconcile-projects.

Precision guarantees (lab RedTeam fbc2c680):
  * every candidate path must itself sit in tool-install territory
    (_project._garbage_root) — belt over the by-construction suspenders;
  * only fallback-form keys ("<name>-<sha8>") are ever submitted — the server
    refuses anything else, so a real remote-keyed project can't be orphaned;
  * intersection with locally-present keys bounds the list (server cap 64) and
    means we never claim a key we can't see in data;
  * runs ONCE per cache (marker in cache_meta), marker set only on success —
    a failed attempt retries on the next sync.

After a successful server retag we mirror the same retag onto the local
cached_deposits rows so offline recall agrees immediately (the change stream
would eventually deliver it anyway; this closes the gap).
"""
from __future__ import annotations

import json
from pathlib import Path

from . import _project

_MARKER = "projects_reconciled_v1"
_MAX_KEYS = 24  # server-side cap (server/reconcile.py MAX_KEYS_PER_CALL)


def _candidate_runtime_dirs() -> set[str]:
    """Plugin-install dirs that exist now OR plausibly existed on this machine
    (version-pinned cache dirs are deleted on update — enumerate the version
    grid so we can reproduce keys minted from dirs that are now gone)."""
    home = Path.home()
    dirs: set[str] = set()
    versioned_bases = [
        home / ".claude" / "plugins" / "cache" / "atlaso" / "atlaso",
        home / ".codex" / "plugins" / "cache" / "atlaso" / "atlaso",
    ]
    versions = [f"{a}.{b}.{c}" for a in (0, 1) for b in range(10) for c in range(31)]
    for base in versioned_bases:
        for v in versions:
            dirs.add(str(base / v / "runtime"))
    dirs.add(str(home / ".claude" / "plugins" / "marketplaces" / "atlaso" / "atlaso" / "runtime"))
    dirs.add(str(home / ".gemini" / "config" / "plugins" / "atlaso" / "runtime"))
    # whatever actually exists on disk right now (layouts the grid missed)
    for rel in (".claude/plugins", ".codex/plugins", ".gemini"):
        root = home / rel
        try:
            if root.is_dir():
                for p in root.rglob("runtime"):
                    if p.is_dir():
                        dirs.add(str(p))
                        dirs.add(str(p.resolve()))
        except OSError:
            continue
    # desktop-app session mirrors of the plugin tree
    la = home / "Library" / "Application Support"
    try:
        if la.is_dir():
            for p in la.glob("*/claude-sessions/*/plugins/marketplaces/atlaso/atlaso/runtime"):
                dirs.add(str(p))
                dirs.add(str(p.resolve()))
    except OSError:
        pass
    return dirs


def candidate_junk_keys() -> dict[str, str]:
    """{legacy key → candidate dir} for every candidate that is PROVABLY in
    garbage territory. The path travels with the key as PROOF: the server
    re-derives the hash and re-checks the territory independently, so a buggy
    client can never orphan a real project (CodeRedTeam gate). Compute-only —
    touches no network, writes nothing."""
    keys: dict[str, str] = {}
    for d in _candidate_runtime_dirs():
        try:
            if not _project._garbage_root(Path(d)):
                continue  # never claim a key for a path we can't prove is junk
            keys[_project.legacy_fallback_key(d)] = d
        except Exception:
            continue
    return keys


def _present_project_keys(cache) -> set[str]:
    """Fallback-form project keys present in the local cache mirror."""
    present: set[str] = set()
    try:
        rows = cache._conn.execute(
            "SELECT DISTINCT value FROM cached_deposits, json_each(cached_deposits.tags_json) "
            "WHERE value LIKE 'project:%'"
        ).fetchall()
    except Exception:
        return present
    for r in rows:
        key = r[0][len("project:"):]
        present.add(key)
    return present


def _retag_local(cache, matched_keys: list[str]) -> None:
    """Mirror the server retag onto the local cache so offline recall agrees
    immediately. Same transform as server/reconcile.py."""
    for key in matched_keys:
        try:
            cache._conn.execute(
                "UPDATE cached_deposits SET tags_json = json_insert(json_insert("
                "  (SELECT json_group_array(value) FROM json_each(cached_deposits.tags_json)"
                "     WHERE value <> 'project:' || ?1 AND value <> 'scope:project'),"
                "  '$[#]', 'scope:orphaned'), '$[#]', 'project-orphaned:' || ?1) "
                "WHERE EXISTS (SELECT 1 FROM json_each(cached_deposits.tags_json)"
                "              WHERE value = 'project:' || ?1)",
                (key,),
            )
        except Exception:
            pass
    try:
        cache._conn.commit()
    except Exception:
        pass


def run_if_due(client) -> dict | None:
    """One-shot rescue, called from sync (online only). Never raises.
    Returns the server response when a reconcile ran, else None."""
    try:
        if client.cache.get_meta(_MARKER):
            return None
        cand = candidate_junk_keys()
        junk = sorted(set(cand) & _present_project_keys(client.cache))
        if not junk:
            client.cache.set_meta(_MARKER, json.dumps({"matched": 0, "note": "no junk keys"}))
            return None
        batch = [{"key": k, "path": cand[k]} for k in junk[:_MAX_KEYS]]
        resp = client.api.reconcile_projects(batch)
        _retag_local(client.cache, [k for k, n in (resp.get("matched") or {}).items() if n])
        if len(junk) <= _MAX_KEYS:
            # done — record the summary; >cap leftovers retry next sync
            client.cache.set_meta(_MARKER, json.dumps(
                {"matched": resp.get("updated_rows", 0), "keys": len(batch)}))
        return resp
    except Exception:
        return None  # offline / transient — retried on a later sync
