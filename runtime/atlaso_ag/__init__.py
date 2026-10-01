"""Atlaso × Google Antigravity lifecycle hooks.

Thin hooks that wire Antigravity's hook lifecycle to the tool-agnostic memory
core (``atlaso_client.Client``). Nothing tool-specific lives in the core; nothing
smart lives here — each hook just reads the event payload (STDIN JSON) and calls
the client.

  recall  (PreInvocation) → inject recalled memory via injectSteps/ephemeralMessage
  capture (Stop)          → save the just-finished exchange (instant local), then sync

IMPORTANT — UNVERIFIED CONTRACT: the Antigravity hook field shapes used here
(PreInvocation reading the prompt from ``transcriptPath`` + emitting
``{"injectSteps":[{"ephemeralMessage": ...}]}``; the Stop payload carrying
``transcriptPath``; the transcript file format itself) are corroborated across
third-party docs but NOT first-party smoke-tested by us. Everything is fail-open:
if a field name is wrong, recall/capture simply no-op and the turn proceeds. MCP +
skill remain the guaranteed path.
"""
__version__ = "0.1.0"

import time as _time

#: When this hook process started running Python code (monotonic). The hook deadline counts
#: from here, so interpreter imports spend the budget too (atlaso_client._deadline.run_hook).
STARTED = _time.monotonic()
