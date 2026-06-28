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
from pathlib import Path
from typing import Optional

_MARKERS = (".git", "pyproject.toml", "package.json", "Cargo.toml", "go.mod",
            ".hg", ".svn", "Gemfile", "pom.xml", "build.gradle", "requirements.txt")


def project_root(start: Optional[Path] = None) -> Path:
    try:
        cur = (start or Path.cwd()).resolve()
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
    """(scope, project_key) from a deposit's tags — mirrors the server."""
    scope, pkey = "personal", None
    for t in tags or []:
        if t == "scope:project":
            scope = "project"
        elif t == "scope:personal":
            scope = "personal"
        elif isinstance(t, str) and t.startswith("project:"):
            pkey = t[len("project:"):]
    return scope, pkey


def visible_in_project(tags, project: Optional[str]) -> bool:
    """Per-project visibility — MUST match the server (server/app.py). Personal/
    untagged → visible everywhere. Project-scoped → visible only in its own
    project. Project-scoped with NO key (orphan) → FAIL CLOSED (hidden), so a
    capture we couldn't attribute to a repo never leaks across repos."""
    scope, pkey = scope_of(tags)
    if scope != "project":
        return True
    if pkey is None:
        return False  # orphan project memory → hidden (fail closed)
    return pkey == project


def project_key(start: Optional[Path] = None) -> Optional[str]:
    """A stable identity for the current project. None on any failure → personal-only."""
    try:
        root = project_root(start)
        origin = _git_origin(root)
        if origin:
            key = _normalize_remote(origin)
            if key:
                return key[:120]
        h = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:8]
        name = re.sub(r"[^A-Za-z0-9_.-]", "-", root.name) or "project"
        return f"{name}-{h}"
    except Exception:
        return None
