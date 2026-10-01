#!/usr/bin/env bash
# Atlaso Memory — capture hook (Antigravity Stop).
# Reads transcriptPath, saves the just-finished exchange (instant local), then
# syncs to the cloud. The capture itself emits no stdout the agent needs, so the
# whole thing runs DETACHED in the background and returns immediately — the Stop
# event never waits on a network sync.
# The shared guard (_guard.sh) bounds it and picks the built runtime or dev mode. Always exit 0 (best-effort).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$HERE/_resolve.sh"

# Antigravity delivers the event on STDIN; capture needs it, so buffer stdin and
# feed it to the backgrounded worker (a detached process can't read the parent's
# stdin once we've returned).
atlaso_capture antigravity capture atlaso_ag.capture
exit 0
