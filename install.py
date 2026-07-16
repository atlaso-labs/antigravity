#!/usr/bin/env python3
"""Install the Atlaso memory connector as a NATIVE Google Antigravity PLUGIN.

Antigravity has a real plugin format: a namespaced bundle (marked by a
`plugin.json`) that groups skills, rules, an MCP server, and hooks in ONE package.
On agy 1.0.14 a plugin must be REGISTERED via `agy plugin install <dir>` (a raw
file-drop into the plugins dir is NOT auto-loaded, and there is no git-URL /
`owner/repo` install form). This installer builds the self-contained bundle and, if
`agy` is on PATH, registers it — copying it into and recording it under:

    GLOBAL   ~/.gemini/config/plugins/atlaso/  +  ~/.gemini/config/import_manifest.json
    PROJECT  <workspace>/.agents/plugins/atlaso/

If `agy` is absent it falls back to a plain file-drop (the Antigravity IDE may pick
that up, but the agy CLI won't load an unregistered plugin). The file-drop path
substitutes the `__ATLASO_PLUGIN_DIR__` placeholder in `mcp_config.json` + `hooks.json`
with the real absolute install path if present (the bundle currently uses relative
launcher paths, so this is a no-op — Antigravity runs hooks with cwd = the plugin dir).

We no longer merge into the user's shared config files (mcp_config.json /
hooks.json) or their AGENTS.md — everything (MCP, hooks, skill, rules) lives
INSIDE the plugin's own bundle. The install is idempotent: it replaces the whole
`~/.gemini/config/plugins/atlaso/` directory atomically.

The hook field contract (PreInvocation injectSteps/ephemeralMessage; Stop +
transcriptPath) is corroborated across docs but NOT first-party smoke-tested by
us; everything fails open — if a field is wrong, recall/capture no-op and the
MCP + skill path still work. See README for the honest details.

Usage:
  python install.py            # install / update (replace the plugin dir)
  python install.py --dry-run  # print what would change, write nothing
  python install.py --uninstall
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

PLUGIN_NAME = "atlaso"
PLACEHOLDER = "__ATLASO_PLUGIN_DIR__"
# json files at the plugin root that carry absolute launcher paths
_SUBST_FILES = ("mcp_config.json", "hooks.json")


def gemini_dir() -> Path:
    """Antigravity's shared config root. ~/.gemini on POSIX; %USERPROFILE%\\.gemini
    on Windows (Path.home() resolves that). Overridable for tests."""
    override = os.environ.get("ANTIGRAVITY_HOME") or os.environ.get("GEMINI_HOME")
    return Path(override).expanduser() if override else Path.home() / ".gemini"


def plugins_dir() -> Path:
    """Global plugin dir Antigravity auto-scans."""
    return gemini_dir() / "config" / "plugins"


def install_dir() -> Path:
    return plugins_dir() / PLUGIN_NAME


# ── bundle source resolution ─────────────────────────────────────────────────
def _is_built_bundle(d: Path) -> bool:
    """A ready-to-install bundle: plugin marker + vendored runtime + root config."""
    return (
        (d / "plugin.json").exists()
        and (d / "runtime").is_dir()
        and (d / "mcp_config.json").exists()
        and (d / "hooks.json").exists()
    )


def resolve_bundle_source() -> Path:
    """Return the directory holding the ready plugin bundle to copy.

    - If install.py is running from INSIDE a built bundle (dist/plugins/atlaso or
      an already-installed copy), use that directory as-is.
    - Otherwise (dev tree at platform/tools/antigravity), build the bundle via
      package.py and use dist/plugins/atlaso. package.py is the single source of
      truth for the bundle layout, so we never duplicate it here."""
    if _is_built_bundle(HERE):
        return HERE

    built = HERE / "dist" / "plugins" / PLUGIN_NAME
    # (re)build from the dev tree so the bundle is always fresh + complete
    pkg = HERE / "package.py"
    if not pkg.exists():
        sys.exit(f"atlaso: no built bundle and no package.py at {pkg} — cannot install.")
    import importlib.util

    spec = importlib.util.spec_from_file_location("atlaso_package", pkg)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    mod.main()
    if not _is_built_bundle(built):
        sys.exit(f"atlaso: package.py ran but {built} is not a complete bundle.")
    return built


# ── install / uninstall ──────────────────────────────────────────────────────
def _substitute_placeholders(root: Path, final: Path) -> None:
    """Replace __ATLASO_PLUGIN_DIR__ → the FINAL absolute install path in the
    plugin's root json files, validating each is still valid JSON afterward.

    `root` is where the files physically live right now (possibly a staging dir);
    `final` is the path the plugin will occupy once installed — the launcher paths
    must point there, not at the staging dir."""
    real = str(final.resolve())
    for name in _SUBST_FILES:
        f = root / name
        if not f.exists():
            continue
        text = f.read_text().replace(PLACEHOLDER, real)
        json.loads(text)  # fail loudly if substitution broke the JSON
        f.write_text(text)


def _make_executable(root: Path) -> None:
    execs = [root / "bin" / "atlaso-memory-mcp"]
    execs += list((root / "hooks").glob("*.sh")) if (root / "hooks").is_dir() else []
    for f in execs:
        if f.exists():
            try:
                f.chmod(0o755)
            except OSError:
                pass


def _agy() -> str | None:
    """Path to the `agy` CLI, or None. Registration goes through it: on agy 1.0.14 a
    raw file-drop into the plugins dir is NOT auto-loaded — the plugin must be
    registered via `agy plugin install <dir>` (which also writes import_manifest.json)."""
    return shutil.which("agy")


def install(dry: bool) -> None:
    src = resolve_bundle_source()
    dst = install_dir()
    print(f"  source bundle: {src}")

    # Preferred path: let `agy` register the plugin (copies it into place +
    # import_manifest.json). Required for the `agy` CLI on 1.0.14; the IDE also picks
    # up the registered plugin.
    #
    # We stage a copy and substitute __ATLASO_PLUGIN_DIR__ → the FINAL install path
    # FIRST: agy runs hooks with cwd=the plugin dir (so their `./hooks/…` resolve), but
    # it runs the MCP server from a DIFFERENT cwd, so the MCP `command` MUST be absolute
    # (a relative `./bin/…` gives `fork/exec: no such file or directory`). agy copies the
    # staged dir verbatim to `dst`, so the absolute path we bake in points at the real
    # installed launcher.
    agy = _agy()
    if agy:
        if dry:
            print(f"  [dry-run] would substitute {PLACEHOLDER} → {dst}, then: {agy} plugin install <staged>")
            return
        staging_root = Path(tempfile.mkdtemp(prefix="atlaso-ag-"))
        staging = staging_root / PLUGIN_NAME
        try:
            shutil.copytree(src, staging, ignore=shutil.ignore_patterns(
                "__pycache__", "*.pyc", ".pytest_cache", "dist", ".venv"))
            _substitute_placeholders(staging, dst)
            _make_executable(staging)
            r = subprocess.run([agy, "plugin", "install", str(staging)], capture_output=True, text=True)
        finally:
            shutil.rmtree(staging_root, ignore_errors=True)
        if r.returncode == 0:
            print(f"  ✓ registered via agy → {dst}")
            return
        # agy present but registration FAILED. Do NOT silently file-drop: on agy 1.0.14
        # an unregistered file-drop is not loaded, so that would report a dead install as
        # success. Fail loudly so the real error surfaces.
        detail = (r.stderr or r.stdout).strip()
        last = detail.splitlines()[-1] if detail else "unknown error"
        sys.exit(f"atlaso: `agy plugin install` failed — {last}\n"
                 f"       (the plugin was NOT installed; fix the above and re-run)")

    # No `agy` on PATH → file-drop the bundle (the Antigravity IDE may pick it up, but the
    # agy CLI won't load an unregistered plugin — install `agy` and re-run for CLI support).
    print("  ! `agy` not on PATH — writing a file-drop (Antigravity IDE only; the agy CLI "
          "won't load it until you install `agy` and re-run)")
    if dry:
        print(f"  [dry-run] would replace {dst}")
        print(f"  [dry-run] would substitute {PLACEHOLDER} → {dst} "
              f"in {', '.join(_SUBST_FILES)}")
        return

    plugins_dir().mkdir(parents=True, exist_ok=True)
    # Atomic-ish replace: stage next to the target, swap, then drop the old.
    staging = dst.with_name(dst.name + ".atlaso.new")
    backup = dst.with_name(dst.name + ".atlaso.old")
    for p in (staging, backup):
        if p.exists():
            shutil.rmtree(p)
    shutil.copytree(src, staging, ignore=shutil.ignore_patterns(
        "__pycache__", "*.pyc", ".pytest_cache", "dist", ".venv"))
    _substitute_placeholders(staging, dst)
    _make_executable(staging)
    if dst.exists():
        dst.rename(backup)
    try:
        staging.rename(dst)
    except OSError:
        if backup.exists():       # roll back on failure
            backup.rename(dst)
        raise
    if backup.exists():
        shutil.rmtree(backup, ignore_errors=True)
    print(f"  ✓ plugin installed → {dst}")


def uninstall(dry: bool) -> None:
    dst = install_dir()
    agy = _agy()
    if agy:
        if dry:
            print(f"  [dry-run] would run: {agy} plugin uninstall {PLUGIN_NAME}")
            return
        subprocess.run([agy, "plugin", "uninstall", PLUGIN_NAME], capture_output=True, text=True)
        # belt-and-braces: remove any leftover dir so the hooks truly stop
        if dst.exists():
            shutil.rmtree(dst, ignore_errors=True)
        print(f"  ✗ unregistered via agy + removed {dst}")
        return
    if not dst.exists():
        print(f"  no plugin at {dst} — nothing to remove")
        return
    if dry:
        print(f"  [dry-run] would remove {dst}")
        return
    shutil.rmtree(dst)
    # tidy the plugins/ dir if we left it empty
    try:
        next(plugins_dir().iterdir())
    except (StopIteration, FileNotFoundError):
        try:
            plugins_dir().rmdir()
        except OSError:
            pass
    print(f"  ✗ removed {dst}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Install the Atlaso Antigravity plugin.")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--uninstall", action="store_true")
    args = ap.parse_args()

    print(f"Atlaso × Antigravity — plugin dir: {install_dir()}")
    if args.uninstall:
        uninstall(args.dry_run)
        return

    install(args.dry_run)
    if not args.dry_run:
        print("\nDone. Restart Antigravity (IDE / `agy`) so it re-scans plugins.")
        print("The plugin bundles MCP (recall/remember/forget/recent/status) + the")
        print("memory skill + rules + auto recall/capture hooks in one package.")
        print("Hooks fail open: if a field is wrong they no-op and MCP + skill still")
        print("work. See README.md for what still needs live Antigravity validation.")


if __name__ == "__main__":
    main()
