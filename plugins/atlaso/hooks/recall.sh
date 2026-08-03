#!/usr/bin/env bash
# Atlaso Memory — recall hook (Antigravity PreInvocation).
# Injects recalled memory by printing {"injectSteps":[{"ephemeralMessage":...}]}
# to STDOUT. Runs in the FOREGROUND so its JSON reaches Antigravity before the
# model call. Resolver picks built (uv runtime) or dev mode.
# Never breaks the turn (best-effort, always exit 0).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$HERE/_resolve.sh"
atlaso_run atlaso_ag.recall
exit 0
