# Shared resolver for the Atlaso Antigravity hooks. Sourced by each hook.
#
# Two modes, auto-detected (mirrors bin/atlaso-memory-mcp and the Claude Code
# connector's hooks/_resolve.sh):
#   BUILT/installed → a vendored `runtime/` dir sits next to hooks/ (built by
#     package.py). We run the bundled packages on a uv-managed Python + deps
#     (`uv run`), so the connector is fully self-contained — no repo, no dev venv.
#   DEV/in-repo     → no runtime/; fall back to the SDK venv + the platform
#     siblings (what our smoke tests use).
#
# `atlaso_run <module>` runs a python module in whichever mode applies, forwarding
# stdin/stdout, and NEVER returns a turn-breaking non-zero (memory is best-effort).
#
# Antigravity has no ${PLUGIN_ROOT}-style variable, so hooks are registered with
# the ABSOLUTE path of each launcher; this resolver derives everything from its own
# location, so a moved/copied tree still works.

_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_TOOL_DIR="$(cd "$_HERE/.." && pwd)"

# The host's cwd. `agy -p` sends workspacePaths [] while treating its own cwd as the
# workspace, and hooks run with cwd = the plugin dir, so read the parent's cwd. agy runs
# a hook as `/usr/bin/env bash <hook>` and env execs, so $PPID is agy itself. Any other
# parent (a `sh -c` wrapper, an IDE, a user shell) may sit in an unrelated repo and would
# tag recall and capture with the wrong project, so its cwd is never used.
_atlaso_parent_is_agy() {
  local comm
  comm="$(ps -o comm= -p "$PPID" 2>/dev/null | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  [ "${comm##*/}" = "agy" ]
}

_atlaso_host_cwd() {
  _atlaso_parent_is_agy || return 0
  if [ -r "/proc/$PPID/cwd" ]; then
    readlink "/proc/$PPID/cwd" 2>/dev/null
  elif command -v lsof >/dev/null 2>&1; then
    lsof -a -p "$PPID" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -n 1
  fi
}

# Resolved at source time, while agy is certainly alive (capture.sh backgrounds its run).
# Always recomputed: an inherited ATLASO_AG_HOST_CWD (a stray export in the user's shell
# or in a parent process) is overwritten, so the value the hook modules read comes from
# this resolver, in this process tree, for a verified agy parent. It is empty otherwise,
# and _shim.workspace_dir then falls back to personal scope.
ATLASO_AG_HOST_CWD="$(_atlaso_host_cwd)"
export ATLASO_AG_HOST_CWD

atlaso_run() {
  local mod="$1"
  if [ -d "$_TOOL_DIR/runtime" ]; then
    # built/installed: portable uv-managed runtime. --frozen installs exactly the
    # shipped runtime/uv.lock (hash-checked) and never re-resolves against an index.
    command -v uv >/dev/null 2>&1 || return 0
    ( cd "$_TOOL_DIR/runtime" && uv run --frozen --quiet python -m "$mod" ) || true
  else
    # dev/in-repo: antigravity lives at platform/tools/antigravity, so ../.. = platform
    local platform py
    platform="$(cd "$_TOOL_DIR/../.." && pwd)"
    py="${ATLASO_PY:-$platform/sdk/.venv/bin/python}"
    [ -x "$py" ] || return 0
    PYTHONPATH="$_TOOL_DIR:$platform/client${PYTHONPATH:+:$PYTHONPATH}" "$py" -m "$mod" || true
  fi
}
