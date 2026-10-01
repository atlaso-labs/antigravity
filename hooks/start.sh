#!/usr/bin/env bash
# Atlaso Memory: start hook (Antigravity SessionStart; not on the public hooks page,
# present and firing in agy 1.2.9, see atlaso_ag/start.py).
# Prints {"injectSteps":[{"ephemeralMessage":<ambient brief>}]} to STDOUT. Runs in the
# FOREGROUND so the brief reaches Antigravity before the first model call. Resolver
# picks the built runtime or dev mode (bounded by _guard.sh). Never breaks the session (always exit 0).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$HERE/_resolve.sh"
atlaso_fg antigravity start "$ATLASO_START_BUDGET" atlaso_ag.start
exit 0
