"""Derive a stable PROJECT KEY for per-project memory — commodity, never the IP.

The thin client preserves the "automatic per-project memory" UX (new folder →
its own isolated memory scope, zero setup) WITHOUT writing anything into the
project folder. We only compute a string key from the current directory:

  1. the git remote origin URL (stable across machines/clones), else
  2. the project root (walk up for common markers; if none, the cwd itself) as
     "<basename>-<short hash of abspath>".

CRITICAL: this function only READS — it never creates a `.atlaso` folder or any
file in the project, and never raises (returns None → treated as personal-only).
Works with or without git, for any folder, handling all edge cases.
"""
from __future__ import annotations

import hashlib
import os
import re
import unicodedata
from pathlib import Path
from typing import Optional

_MARKERS = (".git", "pyproject.toml", "package.json", "Cargo.toml", "go.mod",
            ".hg", ".svn", "Gemfile", "pom.xml", "build.gradle", "requirements.txt")

# Tool-install territory: a "project" resolved inside any of these is the
# connector's own runtime/extension dir or a package cache, never the user's
# work. The shipped hooks `cd` into their vendored runtime/ (which carries
# pyproject.toml, a root marker) before python starts, so an unguarded cwd
# walk lands exactly here — every key it produced was a plugin path, one NEW
# fake project per version-pinned release dir (field deposit 52c7e97d).
# Membership is by path ANCESTRY over the canonicalized (realpath'd) root —
# exact-path lists rot on the next versioned release (lab ruling).
_TOOL_DOT_DIRS = {".claude", ".codex", ".gemini", ".vscode",
                  ".opencode", ".atlaso", "node_modules", "site-packages",
                  "__pypackages__", ".cache", "Caches"}


def _garbage_root(root: Path) -> bool:
    """True when `root` is tool-install/cache territory — the measurement
    itself is garbage (we learn nothing about where the user was working).
    Distinct from _no_project_root: garbage → status 'unknown'."""
    try:
        parts = set(root.parts)
        if parts & _TOOL_DOT_DIRS:
            return True
        # plugin caches that hide under non-dot dirs (marketplaces/cache/repos
        # layouts, e.g. "…/plugins/marketplaces/atlaso/atlaso/runtime")
        if "plugins" in parts and parts & {"cache", "marketplaces", "repos"}:
            return True
        if "extensions" in parts and parts & {"Cursor", "Code", "VSCodium"}:
            return True
        # ~/.cursor hosts BOTH junk (extensions, plugin caches) and real user
        # work (background-agent worktrees under .cursor/worktrees) — block
        # only its non-worktree subtrees.
        if ".cursor" in parts and "worktrees" not in parts:
            return True
    except OSError:
        return True
    return False


def _no_project_root(root: Path) -> bool:
    """True when `root` is a real place that simply ISN'T a project ($HOME
    itself, the filesystem root). A trustworthy 'no project here' answer —
    status 'none', genuine personal scope."""
    try:
        return root == Path.home() or root == Path(root.anchor)
    except OSError:
        return True


def _start_dir(start: Optional[Path]) -> Optional[Path]:
    """The directory project detection should trust: the caller's explicit
    path, else ATLASO_CALLER_PWD (stamped by the hook shell wrapper BEFORE it
    cds into the vendored runtime), else the process cwd."""
    if start is not None:
        return start
    env = os.environ.get("ATLASO_CALLER_PWD")
    if env:
        p = Path(env)
        try:
            if p.is_dir():
                return p
        except OSError:
            pass
    return None  # → project_root falls back to Path.cwd()


def project_root(start: Optional[Path] = None) -> Path:
    try:
        cur = (_start_dir(start) or Path.cwd()).resolve()
    except OSError:
        return Path.cwd()
    for d in (cur, *cur.parents):
        try:
            if any((d / m).exists() for m in _MARKERS):
                return d
        except OSError:
            continue
    return cur  # no markers → the cwd itself is the "project"


def _git_origin(root: Path) -> Optional[str]:
    """Read remote.origin.url straight from .git/config (no subprocess). None if
    absent. Handles a .git file (worktrees) by following gitdir."""
    try:
        gitpath = root / ".git"
        cfg: Optional[Path] = None
        if gitpath.is_dir():
            cfg = gitpath / "config"
        elif gitpath.is_file():
            # worktree/submodule: ".git" is a file "gitdir: <path>". Linked
            # worktrees keep remotes in the COMMON git dir (commondir), not the
            # per-worktree gitdir — read commondir first so all worktrees of one
            # repo resolve to the SAME project key (Codex MED).
            txt = gitpath.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r"gitdir:\s*(.+)", txt)
            if m:
                gd = (root / m.group(1).strip()).resolve()
                common = gd
                cd = gd / "commondir"
                if cd.exists():
                    try:
                        common = (gd / cd.read_text(encoding="utf-8", errors="ignore").strip()).resolve()
                    except OSError:
                        common = gd
                cfg = common / "config"
        if not cfg or not cfg.exists():
            return None
        text = cfg.read_text(encoding="utf-8", errors="ignore")
        # find [remote "origin"] ... url = ...
        in_origin = False
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("["):
                in_origin = s.replace(" ", "").lower().startswith('[remote"origin"]')
            elif in_origin and s.lower().startswith("url"):
                _, _, val = s.partition("=")
                return val.strip() or None
        return None
    except OSError:
        return None


def _normalize_remote(url: str) -> str:
    """Normalize a git remote to a stable key: drop scheme/creds/.git, lowercase
    host+path. git@github.com:me/app.git and https://github.com/me/app(.git) →
    github.com/me/app."""
    u = url.strip()
    u = re.sub(r"^[a-zA-Z]+://", "", u)   # strip scheme (https://, ssh://, …)
    u = re.sub(r"^[^@/]+@", "", u)         # strip user@ (git@)
    u = u.replace(":", "/", 1)            # scp-style host:path → host/path
    u = re.sub(r"\.git$", "", u)
    return u.strip("/").lower()


def scope_of(tags) -> tuple[str, Optional[str]]:
    """(scope, project_key) from a deposit's tags — mirrors the server.

    Scope is ORDER-INDEPENDENT with precedence orphaned > project > personal
    (CodeRedTeam block: last-tag-wins let a crafted tag array like
    ['scope:project','project:X','scope:personal'] leak a project memory
    everywhere, or revive a rescued orphan into recall)."""
    tl = [t for t in (tags or []) if isinstance(t, str)]
    pkey = None
    for t in tl:
        if t.startswith("project:"):
            pkey = t[len("project:"):]
    if "scope:orphaned" in tl:
        scope = "orphaned"
    elif "scope:project" in tl:
        scope = "project"
    else:
        scope = "personal"
    return scope, pkey


def visible_in_project(tags, project: Optional[str]) -> bool:
    """Per-project visibility — MUST match the server (server/app.py). Personal/
    untagged → visible everywhere. Project-scoped with a key → visible only in
    its own project. Project-scoped with NO key (orphan) → VISIBLE everywhere
    (fail OPEN): hiding is invisible to the user so it can never be corrected,
    while over-visibility of the user's OWN memory is observable and fixable
    (lab ruling — asymmetric loss; the old fail-closed rule silently buried
    every capture the key derivation couldn't attribute)."""
    scope, pkey = scope_of(tags)
    if scope == "orphaned":
        return False  # junk-key rescue — recovery view only, never normal recall
    if scope != "project":
        return True
    if pkey is None:
        return True  # orphan → visible-with-provenance, never silently buried
    return pkey == project


def _fallback_key(root: Path) -> str:
    """name-hash key for a non-git project root. Hash basis is the NFC-
    normalized, case-folded path — APFS is case-insensitive-preserving and
    hands back NFD filenames, so two layers producing the same directory's
    string must never hash it differently (lab ruling). Mirrored 1:1 in the
    TS connectors (lib/project.ts)."""
    basis = unicodedata.normalize("NFC", str(root)).lower()
    h = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:8]
    name = re.sub(r"[^A-Za-z0-9_.-]", "-",
                  unicodedata.normalize("NFC", root.name)) or "project"
    return f"{name}-{h}"


def legacy_fallback_key(path: str) -> str:
    """The PRE-2026-07 hash basis (raw un-normalized string). ONLY for the
    junk-key reconciler, which must reproduce the exact keys old clients
    minted from their plugin-install paths."""
    h = hashlib.sha256(path.encode("utf-8")).hexdigest()[:8]
    name = re.sub(r"[^A-Za-z0-9_.-]", "-", Path(path).name) or "project"
    return f"{name}-{h}"


def project_resolution(start: Optional[Path] = None) -> tuple[str, Optional[str]]:
    """(status, key) — the tri-state project measurement.

    'ok'      → key is a real project identity (normalized git remote, else
                name-hash of the canonical root).
    'none'    → trustworthy "this work belongs to NO project" ($HOME, the
                filesystem root) → genuine personal scope.
    'unknown' → the measurement itself failed or was garbage (root resolved
                into tool-install/cache territory, unreadable dir, exception)
                → record as an unattributed project memory, visible with a
                provenance marker, never silently buried.

    The none/unknown split is load-bearing: collapsing them is exactly how
    298 memories became indistinguishable from "no project" and disappeared
    (lab ruling; field deposit 52c7e97d)."""
    try:
        root = project_root(start)
        if _garbage_root(root):
            return "unknown", None
        if _no_project_root(root):
            return "none", None
        origin = _git_origin(root)
        if origin:
            key = _normalize_remote(origin)
            if key:
                return "ok", key[:120]
        return "ok", _fallback_key(root)
    except Exception:
        return "unknown", None


def project_key(start: Optional[Path] = None) -> Optional[str]:
    """A stable identity for the current project. None → personal-only (both
    the 'none' and 'unknown' cases — recall treats them the same)."""
    status, key = project_resolution(start)
    return key if status == "ok" else None
