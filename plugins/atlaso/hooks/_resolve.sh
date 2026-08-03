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

atlaso_run() {
  local mod="$1"
  if [ -d "$_TOOL_DIR/runtime" ]; then
    # built/installed: portable uv-managed runtime (Python + httpx + mcp, cached)
    command -v uv >/dev/null 2>&1 || return 0
    ( cd "$_TOOL_DIR/runtime" && uv run --quiet python -m "$mod" ) || true
  else
    # dev/in-repo: antigravity lives at platform/tools/antigravity, so ../.. = platform
    local platform py
    platform="$(cd "$_TOOL_DIR/../.." && pwd)"
    py="${ATLASO_PY:-$platform/sdk/.venv/bin/python}"
    [ -x "$py" ] || return 0
    PYTHONPATH="$_TOOL_DIR:$platform/client${PYTHONPATH:+:$PYTHONPATH}" "$py" -m "$mod" || true
  fi
}
