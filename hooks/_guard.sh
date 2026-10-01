# Atlaso hook guard: hard deadlines and runtime readiness for every Python connector hook.
#
# Canonical copy: tools/runtime-lock/_guard.sh. Each Python connector (claude-code, codex,
# antigravity, grok-build) carries a byte-identical hooks/_guard.sh, which its _resolve.sh
# sources; tools/runtime-lock/tests/test_hook_guard.py fails when a copy drifts.
#
# Why (rung "hooks never hang", 2026-09-30): the host kills a hook at its own timeout (Codex
# and Claude Code: 30 s per prompt, 5 s at session start) and shows the user "hook timed
# out". Two things used to run inside that window with no deadline of ours:
#   1. `uv run --frozen` materialising the runtime on the first hook after an update. That can
#      include downloading a Python and every wheel, with uv's own 30 s HTTP timeout and 3
#      retries: 123 s measured on a stalled download.
#   2. The brain call. httpx's 8 s timeout applies to each read, so a server that trickles a
#      byte every few seconds never trips it (> 100 s measured).
# The rules this file enforces:
#   - The prompt path never runs uv. It runs the runtime's venv python directly, and only when
#     the venv was built from the lock this plugin ships (.venv/.atlaso-lock matches). When it
#     is not ready, recall injects nothing and one detached warm-up (`uv sync --frozen`) starts;
#     where the host shows hook warnings to the user (Codex, Claude Code) the user is told.
#   - Every foreground hook runs under a wall-clock watchdog. stdout reaches the host only when
#     the module finished before its deadline, so a killed recall can never inject a truncated
#     block.
#   - Capture reads its payload with a deadline into a private spool file, hands it to a
#     detached worker and returns. The spool file is the turn's durable copy until the capture
#     module has run on it (see atlaso_bg).
#   - Every skip is counted on this device as one content-free line (time, tool, event,
#     reason) in <atlaso dir>/health/hooks.log, which `atlaso status` reads. Never any text,
#     ids, paths or payloads.
#   - Every hook exits 0: memory is best-effort, the user's turn is not.
#
# Portable to bash 3.2 (stock macOS), Linux and Git Bash: no `timeout`, no `setsid`, no
# fractional `read -t`.
#
# Needs from the sourcing script: ATLASO_GUARD_ROOT = the plugin/tool dir holding runtime/.

# Budgets in seconds. The env overrides exist for the stall harness and for support; the
# defaults are the product.
: "${ATLASO_RECALL_BUDGET:=2.5}"   # recall: whole module, network included (network gets 1.5)
: "${ATLASO_START_BUDGET:=2.5}"    # session start: host budget is 5 s
: "${ATLASO_STDIN_BUDGET:=0.3}"    # reading the host's payload off stdin (hosts write it at once)
: "${ATLASO_WORKER_BUDGET:=120}"   # detached capture/sync worker, including a wait for warm-up
: "${ATLASO_WARM_BUDGET:=600}"     # detached `uv sync --frozen`

_atlaso_dir() {
  printf '%s' "${ATLASO_GLOBAL_PATH:-${ATLASO_PATH:-$HOME/.atlaso}}"
}

# _atlaso_health <tool> <event> <reason>: one content-free line; never fails the hook.
_atlaso_health() {
  local d f
  d="$(_atlaso_dir)/health"
  f="$d/hooks.log"
  (
    umask 077
    mkdir -p "$d" 2>/dev/null || exit 0
    # Bounded: past 64 KiB the file rotates once (.1 overwritten), so it never grows forever.
    if [ -f "$f" ] && [ "$(wc -c <"$f" 2>/dev/null || echo 0)" -gt 65536 ]; then
      mv -f "$f" "$f.1" 2>/dev/null
    fi
    printf '%s %s %s %s\n' "$(date +%s)" "$1" "$2" "$3" >>"$f"
  ) >/dev/null 2>&1 </dev/null
  return 0
}

# _atlaso_stamp: the file whose bytes define "the runtime this plugin ships".
_atlaso_stamp() {
  local rt="$ATLASO_GUARD_ROOT/runtime"
  if [ -f "$rt/uv.lock" ]; then printf '%s' "$rt/uv.lock"; else printf '%s' "$rt/pyproject.toml"; fi
}

# _atlaso_ready_py: print the runtime's python and succeed only when the venv was built from
# exactly this plugin's lock. Never runs uv, never touches the network.
_atlaso_ready_py() {
  local rt="$ATLASO_GUARD_ROOT/runtime" py stamp
  stamp="$(_atlaso_stamp)"
  [ -f "$rt/.venv/.atlaso-lock" ] || return 1
  cmp -s "$stamp" "$rt/.venv/.atlaso-lock" || return 1
  for py in "$rt/.venv/bin/python" "$rt/.venv/Scripts/python.exe"; do
    if [ -x "$py" ]; then printf '%s' "$py"; return 0; fi
  done
  return 1
}

# _atlaso_bounded <seconds> <stdout-file> <cmd...>: run cmd (stdin inherited, stdout to the
# file, stderr to $_ATLASO_BOUNDED_ERR or dropped) under a wall-clock watchdog. cmd must be an
# executable, not a shell function: the watchdog kills that one pid. Returns 124 when the watchdog killed it, else
# cmd's own exit code.
_atlaso_bounded() {
  local budget="$1" out="$2" pid wd rc wrc
  shift 2
  # `<&0` is required: bash gives a background job /dev/null as stdin unless it is redirected
  # explicitly, and the host's payload arrives on stdin.
  "$@" <&0 >"$out" 2>"${_ATLASO_BOUNDED_ERR:-/dev/null}" &
  pid=$!
  # The watchdog exits 0 when cancelled and 124 when it fired. Once it fires it ignores
  # cancellation, so "killed" can never be reported as "finished".
  (
    trap 'kill "$sp" 2>/dev/null; exit 0' TERM
    sleep "$budget" &
    sp=$!
    wait "$sp"
    trap '' TERM
    kill -TERM "$pid" 2>/dev/null
    # Up to 0.2 s for a clean exit, then KILL.
    for _ in 1 2 3 4; do
      kill -0 "$pid" 2>/dev/null || exit 124
      sleep 0.05
    done
    kill -KILL "$pid" 2>/dev/null
    exit 124
  ) >/dev/null 2>&1 </dev/null &
  wd=$!
  wait "$pid" 2>/dev/null
  rc=$?
  if [ "$rc" -eq 143 ] || [ "$rc" -eq 137 ]; then
    # Ended by TERM or KILL: the watchdog's doing. Report it now rather than sitting out
    # the watchdog's grace loop (the child is gone, so the loop has nothing left to kill).
    kill -KILL "$wd" 2>/dev/null
    return 124
  fi
  kill -TERM "$wd" 2>/dev/null
  wait "$wd" 2>/dev/null
  wrc=$?
  [ "$wrc" -eq 124 ] && return 124
  return "$rc"
}

# _atlaso_warm_sync <tool> <budget> <uv-stderr>: build the runtime venv from the shipped lock
# with `uv sync --frozen` (hash-checked, never re-resolved; the watchdog bounds uv itself) and
# stamp it with that lock. The caller holds the warm lock.
_atlaso_warm_sync() {
  local tool="$1" budget="$2" errf="$3" rt="$ATLASO_GUARD_ROOT/runtime" stamp rc py
  stamp="$(_atlaso_stamp)"
  rm -f "$rt/.venv/.atlaso-lock" 2>/dev/null
  # --compile-bytecode, plus compileall for the vendored packages below: a hook must not
  # spend its deadline compiling source on its first run.
  ( cd "$rt" && _ATLASO_BOUNDED_ERR="$errf" _atlaso_bounded "$budget" /dev/null \
      uv sync --frozen --quiet --compile-bytecode </dev/null )
  rc=$?
  if [ "$rc" -eq 0 ]; then
    # Stamp only a venv whose python actually starts.
    rc=1
    for py in "$rt/.venv/bin/python" "$rt/.venv/Scripts/python.exe"; do
      if [ -x "$py" ] && "$py" -c '' </dev/null >/dev/null 2>&1; then
        ( cd "$rt" && _atlaso_bounded 120 /dev/null "$py" -m compileall -q -x '[/\\]\.venv[/\\]' . </dev/null ) \
          || true
        cp -f "$stamp" "$rt/.venv/.atlaso-lock.tmp" \
          && mv -f "$rt/.venv/.atlaso-lock.tmp" "$rt/.venv/.atlaso-lock" && rc=0
        break
      fi
    done
  fi
  if [ "$rc" -eq 124 ]; then _atlaso_health "$tool" warmup deadline
  elif [ "$rc" -ne 0 ]; then _atlaso_health "$tool" warmup failed
  fi
  return "$rc"
}

# _atlaso_warm_lock: take the per-runtime warm lock (mkdir is atomic everywhere). The owner
# writes its pid into it. A lock whose owner is gone (killed with the machine's sleep, or with
# its host's process group) is taken over at once; one older than 13 minutes (warm budget 10 +
# byte-compile 2, plus slack) is taken over whatever its pid says.
_atlaso_warm_lock() {
  local lockd="$ATLASO_GUARD_ROOT/runtime/.atlaso-warming" owner
  mkdir "$lockd" 2>/dev/null && return 0
  owner="$(cat "$lockd/pid" 2>/dev/null)"
  if { [ -n "$owner" ] && ! kill -0 "$owner" 2>/dev/null; } \
      || [ -n "$(find "$lockd" -maxdepth 0 -mmin +13 2>/dev/null)" ]; then
    rm -f "$lockd/pid" 2>/dev/null
    rmdir "$lockd" 2>/dev/null
    mkdir "$lockd" 2>/dev/null && return 0
  fi
  return 1
}

# _atlaso_warm_owner <pid>: record the warm lock's owner.
_atlaso_warm_owner() {
  printf '%s\n' "$1" >"$ATLASO_GUARD_ROOT/runtime/.atlaso-warming/pid" 2>/dev/null
  return 0
}

_atlaso_warm_unlock() {
  rm -f "$ATLASO_GUARD_ROOT/runtime/.atlaso-warming/pid" 2>/dev/null
  rmdir "$ATLASO_GUARD_ROOT/runtime/.atlaso-warming" 2>/dev/null
  return 0
}

# _atlaso_warm <tool>: start at most one DETACHED warm-up and return at once.
_atlaso_warm() {
  local tool="$1"
  [ -d "$ATLASO_GUARD_ROOT/runtime" ] || return 0
  if ! command -v uv >/dev/null 2>&1; then
    _atlaso_health "$tool" warmup uv_missing
    return 0
  fi
  _atlaso_warm_lock || return 0
  (
    _atlaso_warm_sync "$tool" "$ATLASO_WARM_BUDGET" /dev/null
    _atlaso_warm_unlock
  ) </dev/null >/dev/null 2>&1 &
  _atlaso_warm_owner "$!"
  disown 2>/dev/null || true
  return 0
}

# atlaso_warm_now [tool]: FOREGROUND warm-up with uv's errors on stderr. For installers,
# `atlaso setup` and tests; never called from a hook. Exit 0 when the runtime is ready.
atlaso_warm_now() {
  local tool="${1:-${ATLASO_TOOL:-unknown}}" rc errf
  [ -d "$ATLASO_GUARD_ROOT/runtime" ] || return 0
  _atlaso_ready_py >/dev/null && return 0
  command -v uv >/dev/null 2>&1 || { echo "atlaso: uv is required to set up the memory runtime" >&2; return 1; }
  _atlaso_warm_lock || { _atlaso_wait_ready "$ATLASO_WARM_BUDGET"; return $?; }
  _atlaso_warm_owner "$$"
  errf="$(mktemp "${TMPDIR:-/tmp}/atlaso-warm.XXXXXX" 2>/dev/null)" || errf=/dev/null
  _atlaso_warm_sync "$tool" "$ATLASO_WARM_BUDGET" "$errf"
  rc=$?
  [ "$errf" = /dev/null ] || { cat "$errf" >&2; rm -f "$errf"; }
  _atlaso_warm_unlock
  return "$rc"
}

# _atlaso_wait_ready <seconds>: poll (0.25 s steps) until the runtime is ready. Detached
# workers and atlaso_warm_now only; never on a prompt path.
_atlaso_wait_ready() {
  local n=0 max
  max=$(awk "BEGIN{printf \"%d\", $1 * 4}")
  while ! _atlaso_ready_py >/dev/null; do
    [ "$n" -ge "$max" ] && return 1
    sleep 0.25
    n=$((n + 1))
  done
  return 0
}

# _atlaso_resolve_py: choose the interpreter. Sets _ATLASO_PY, _ATLASO_CWD, _ATLASO_PYPATH.
#   0 = ready; 1 = built plugin whose runtime is not ready; 2 = no interpreter at all.
_atlaso_resolve_py() {
  local platform
  _ATLASO_PYPATH=""
  if [ -d "$ATLASO_GUARD_ROOT/runtime" ]; then
    _ATLASO_PY="$(_atlaso_ready_py)" || return 1
    _ATLASO_CWD="$ATLASO_GUARD_ROOT/runtime"   # python -m finds the vendored packages here
  else
    # dev/in-repo: the SDK venv plus the platform siblings (what the unit tests use)
    platform="$(cd "$ATLASO_GUARD_ROOT/../.." && pwd)"
    _ATLASO_PY="${ATLASO_PY:-$platform/sdk/.venv/bin/python}"
    [ -x "$_ATLASO_PY" ] || return 2
    _ATLASO_CWD="$PWD"
    _ATLASO_PYPATH="$ATLASO_GUARD_ROOT:$platform/client${PYTHONPATH:+:$PYTHONPATH}"
  fi
  return 0
}

# _atlaso_module <budget> <stdout-file> <module>: run `python -m module` bounded.
_atlaso_module() {
  (
    cd "$_ATLASO_CWD" 2>/dev/null || exit 0
    [ -n "$_ATLASO_PYPATH" ] && export PYTHONPATH="$_ATLASO_PYPATH"
    # The module sizes its own deadline a little inside ours (atlaso_client._deadline).
    export ATLASO_HOOK_BUDGET="$1"
    _atlaso_bounded "$1" "$2" "$_ATLASO_PY" -m "$3"
  )
}

_atlaso_prep() {
  # Keep the caller's real working directory: project detection reads it (the process
  # itself runs from the vendored runtime/, which carries a pyproject.toml).
  export ATLASO_CALLER_PWD="${ATLASO_CALLER_PWD:-$PWD}"
}

# _atlaso_not_ready_notice <tool>: tell the USER (not the model) that this prompt had no recall.
# Only for hosts whose prompt hook documents a user-visible `systemMessage` warning that is not
# added to the model's context (Codex, Claude Code): the hook script sets ATLASO_NOTICE_NAME.
# At most once a minute per tool, so a burst of prompts during a warm-up shows it once. With uv
# present a not-ready prompt always has a warm-up running (_atlaso_warm starts one when none is),
# so "still setting up" is true; without uv the notice names the missing prerequisite instead.
_atlaso_not_ready_notice() {
  local name="${ATLASO_NOTICE_NAME:-}" mark
  case "$name" in ''|*[!A-Za-z\ ]*) return 0 ;; esac
  mark="$(_atlaso_dir)/health/notice.$1"
  [ -n "$(find "$mark" -mmin -1 2>/dev/null)" ] && return 0
  ( umask 077; mkdir -p "$(_atlaso_dir)/health" && : >"$mark" ) 2>/dev/null
  # Without uv no warm-up can start (_atlaso_warm logged uv_missing), so nothing is "setting
  # up": say what the user must do instead (DXCritic r3 finding 1).
  if ! command -v uv >/dev/null 2>&1; then
    printf '{"systemMessage": "Atlaso needs uv. Install uv, then retry your prompt; memory will set up in the background."}\n'
    return 0
  fi
  # A plugin-only install has no `atlaso` command, so the notice names only what every install
  # has: each not-ready prompt starts a fresh warm-up, which needs the network once (DXCritic
  # 20224868, D-HOOKS-PLUGIN-SETTING-UP-NOTICE).
  printf '{"systemMessage": "%s memory is still setting up, so this prompt had no recall. Each prompt retries the setup; if memory stays off, check that this computer is online (setup downloads its runtime once) or reinstall the Atlaso plugin."}\n' "$name"
}

# atlaso_fg <tool> <event> <budget> <module>: a foreground hook. The module's stdout reaches
# the host only when it finished inside the budget. Runtime not ready → no recall, a user-visible
# notice where the host has one, and a detached warm-up.
atlaso_fg() {
  local tool="$1" event="$2" budget="$3" mod="$4" out rc
  _atlaso_prep
  _atlaso_resolve_py
  rc=$?
  if [ "$rc" -eq 1 ]; then
    _atlaso_health "$tool" "$event" not_ready
    _atlaso_warm "$tool"
    [ "$event" = recall ] && _atlaso_not_ready_notice "$tool"
    return 0
  fi
  [ "$rc" -eq 0 ] || return 0
  out="$(mktemp "${TMPDIR:-/tmp}/atlaso-hook.XXXXXX" 2>/dev/null)" || return 0
  _atlaso_module "$budget" "$out" "$mod"
  if [ "$?" -eq 124 ]; then
    # The watchdog killed it ("killed"; the module's own early exit records "deadline").
    # Its partial stdout is discarded.
    _atlaso_health "$tool" "$event" killed
  else
    cat "$out" 2>/dev/null
  fi
  rm -f "$out" 2>/dev/null
  return 0
}

# The capture spool: <atlaso dir>/spool/capture.<tool>.<random>, one host payload per file (0600,
# dir 0700), beside the cache that already holds captured text. A file is deleted only after
# the capture module ran to completion on it. When its worker found no ready runtime, or was
# stopped at its time limit, the file stays and the next capture worker of the same tool replays
# it (at most 5 per run, once they are ATLASO_SPOOL_REPLAY_AGE_MIN minutes old, so a live
# worker's own file is never taken). Replaying a turn that did reach the cache is harmless: the
# capture pipeline's near-duplicate check drops it, and ATLASO_CAPTURE_REPLAY=1 stops that drop
# from re-dating the memory as if the user had said it again. Files left for 24 h are dropped and counted
# as `capture expired`.
: "${ATLASO_SPOOL_REPLAY_AGE_MIN:=5}"

_atlaso_spool() {
  printf '%s' "$(_atlaso_dir)/spool"
}

# _atlaso_spool_sweep <tool>: return abandoned replay claims to the queue; drop day-old files.
_atlaso_spool_sweep() {
  local tool="$1" spool f n
  spool="$(_atlaso_spool)"
  [ -d "$spool" ] || return 0
  # A claim whose worker died (machine sleep, power) goes back to the queue.
  find "$spool" -type f -name "replay.$tool.*" -mmin +10 2>/dev/null | while IFS= read -r f; do
    mv -f "$f" "$spool/capture.$tool.${f##*.}" 2>/dev/null
  done
  n="$(find "$spool" -type f -name "capture.$tool.*" -mmin +1440 2>/dev/null | wc -l | tr -d ' ')"
  if [ "${n:-0}" -gt 0 ]; then
    find "$spool" -type f -name "capture.$tool.*" -mmin +1440 -exec rm -f {} + 2>/dev/null
    _atlaso_health "$tool" capture expired
  fi
  return 0
}

# _atlaso_spool_replay <tool> <event> <module>: the runtime is ready (_ATLASO_PY set). Claim each
# waiting file with an atomic rename, so two workers never replay the same turn.
_atlaso_spool_replay() {
  local tool="$1" event="$2" mod="$3" spool f claim
  spool="$(_atlaso_spool)"
  [ -d "$spool" ] || return 0
  find "$spool" -type f -name "capture.$tool.*" -mmin +"$ATLASO_SPOOL_REPLAY_AGE_MIN" 2>/dev/null \
    | head -5 | while IFS= read -r f; do
      claim="$spool/replay.$tool.${f##*.}"
      mv "$f" "$claim" 2>/dev/null || continue
      # A replay is the same turn again, never a user re-assertion (the client reads this).
      ATLASO_CAPTURE_REPLAY=1 _atlaso_module "$ATLASO_WORKER_BUDGET" /dev/null "$mod" <"$claim"
      if [ "$?" -eq 124 ]; then
        mv -f "$claim" "$f" 2>/dev/null
        _atlaso_health "$tool" "$event" killed
      else
        rm -f "$claim"
        _atlaso_health "$tool" "$event" replayed
      fi
    done
  return 0
}

# atlaso_bg <tool> <event> <module> [payload-file]: a DETACHED worker. Waits for (and if
# needed starts) the warm-up, then runs the module bounded. With a payload file (capture), the
# file is deleted only once the module ran to completion on it, and waiting files of earlier
# turns are replayed afterwards.
atlaso_bg() {
  local tool="$1" event="$2" mod="$3" pf="${4:-}"
  _atlaso_prep
  (
    [ -n "$pf" ] && _atlaso_spool_sweep "$tool"
    _atlaso_resolve_py
    rc=$?
    if [ "$rc" -eq 1 ]; then
      _atlaso_warm "$tool"
      if _atlaso_wait_ready "$ATLASO_WORKER_BUDGET" && _atlaso_resolve_py; then :; else
        # No runtime yet: the turn stays in the spool for the next capture worker.
        _atlaso_health "$tool" "$event" not_ready
        exit 0
      fi
    elif [ "$rc" -ne 0 ]; then
      [ -n "$pf" ] && rm -f "$pf"
      exit 0
    fi
    if [ -n "$pf" ]; then
      _atlaso_module "$ATLASO_WORKER_BUDGET" /dev/null "$mod" <"$pf"
      rc=$?
      # Stopped at its time limit: keep the turn for a replay. Otherwise it is done.
      [ "$rc" -eq 124 ] || rm -f "$pf"
      [ "$rc" -eq 124 ] && _atlaso_health "$tool" "$event" killed
      _atlaso_spool_replay "$tool" "$event" "$mod"
    else
      _atlaso_module "$ATLASO_WORKER_BUDGET" /dev/null "$mod" </dev/null
      rc=$?
      [ "$rc" -eq 124 ] && _atlaso_health "$tool" "$event" killed
    fi
  ) </dev/null >/dev/null 2>&1 &
  disown 2>/dev/null || true
  return 0
}

# atlaso_capture <tool> <event> <module>: read the host payload off stdin (bounded) into a
# private spool file, hand it to a detached worker, return.
atlaso_capture() {
  local tool="$1" event="$2" mod="$3" spool pf
  spool="$(_atlaso_spool)"
  ( umask 077; mkdir -p "$spool" ) 2>/dev/null || return 0
  pf="$(umask 077; mktemp "$spool/capture.$tool.XXXXXX" 2>/dev/null)" || return 0
  _atlaso_bounded "$ATLASO_STDIN_BUDGET" "$pf" cat
  [ "$?" -eq 124 ] && _atlaso_health "$tool" "$event" stdin_deadline
  atlaso_bg "$tool" "$event" "$mod" "$pf"
  return 0
}

# atlaso_run <module>: compatibility entry point (tests, older callers): a foreground run
# bounded by the session-start budget.
atlaso_run() {
  atlaso_fg "${ATLASO_TOOL:-unknown}" run "$ATLASO_START_BUDGET" "$1"
}
