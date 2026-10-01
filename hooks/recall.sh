#!/usr/bin/env bash
# Atlaso Memory — recall hook (Antigravity PreInvocation).
# Injects recalled memory by printing {"injectSteps":[{"ephemeralMessage":...}]}
# to STDOUT. Runs in the FOREGROUND so its JSON reaches Antigravity before the
# model call. The shared guard (_guard.sh) bounds it and picks the built runtime or dev mode.
# Never breaks the turn (best-effort, always exit 0).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$HERE/_resolve.sh"
atlaso_fg antigravity recall "$ATLASO_RECALL_BUDGET" atlaso_ag.recall
exit 0
