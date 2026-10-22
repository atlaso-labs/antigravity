"""Per-tool budget for hook-injected memory, and the one fitter every connector uses.

Each host caps what a hook may inject and degrades the whole block when it is exceeded
(Claude Code: the model sees a file path and a 2,000-character preview; Codex: a head and
tail preview with the middle cut out). A cut block can lose every note, so the block is
fitted BEFORE it is printed: whole notes in rank order, never a note cut part way.

Unit: UTF-8 bytes of the injected string as the host receives it (after JSON decoding).
UTF-8 bytes >= UTF-16 code units >= code points for every string, so a byte budget is
safe for a host that counts characters and exact for one that counts bytes.

The TypeScript connectors (tools/cursor and tools/opencode lib/render.ts, ``fitLines``)
mirror ``fit_lines`` exactly; client/tests/fixtures/budget_contract.json holds the shared
expectations (pytest + bun), and tools/conformance/cells/injection_budget.py drives every
connector's real recall entry point against the budgets below.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class HostLimit:
    limit: int | None   # host cap in UTF-8 bytes (None: no documented cap)
    unit: str           # how the host counts
    overflow: str       # what the host does above the cap
    source: str         # where the cap is documented
    budget: int         # what Atlaso injects at most (UTF-8 bytes), always < limit


# Safety margin: 10% under the strictest documented cap (10,000). Tools with no documented
# cap get the same budget, so a block that fits one tool fits every tool.
DEFAULT_BUDGET = 9000

HOSTS: dict[str, HostLimit] = {
    "claude-code": HostLimit(
        10_000, "characters per additionalContext string",
        "saved to a file; the model sees the path and the first 2,000 characters",
        "https://code.claude.com/docs/en/hooks", DEFAULT_BUDGET),
    "codex": HostLimit(
        10_000, "approx tokens = ceil(UTF-8 bytes / 4), limit 2,500",
        "saved to a file; the model sees a head and tail preview with the middle cut",
        "https://learn.chatgpt.com/docs/hooks ; codex-rs/hooks/src/output_spill.rs",
        DEFAULT_BUDGET),
    "grok-build": HostLimit(
        10_000, "Claude Code plugin compatibility (UserPromptSubmit stdout is documented as ignored)",
        "same as Claude Code if the compatibility layer honours it",
        "https://docs.x.ai/build/features/hooks", DEFAULT_BUDGET),
    "antigravity": HostLimit(
        None, "undocumented", "undocumented",
        "https://antigravity.google/docs/hooks", DEFAULT_BUDGET),
    "cursor": HostLimit(
        None, "undocumented", "undocumented",
        "https://cursor.com/docs/agent/hooks", DEFAULT_BUDGET),
    "opencode": HostLimit(
        None, "synthetic text part, no plugin cap", "none (counts against the context window)",
        "https://opencode.ai/docs/plugins/", DEFAULT_BUDGET),
}

_ENV = "ATLASO_INJECT_BUDGET_BYTES"
# Off switch (memo item 32, Tier B rollback): ATLASO_INJECT_BUDGET=off restores the
# pre-budget behaviour exactly (every note printed, no closing line, no brief size check).
_OFF_ENV = "ATLASO_INJECT_BUDGET"
UNLIMITED = 1 << 62


def budget_for(tool: str | None) -> int:
    """The byte budget for ``tool``. An unknown tool gets DEFAULT_BUDGET (the minimum of the
    table). ATLASO_INJECT_BUDGET_BYTES may only LOWER it (tests, support), never raise it.
    ATLASO_INJECT_BUDGET=off turns budgeting off (returns UNLIMITED)."""
    if os.environ.get(_OFF_ENV, "").strip().lower() == "off":
        return UNLIMITED
    host = HOSTS.get(tool or "")
    budget = host.budget if host else DEFAULT_BUDGET
    raw = os.environ.get(_ENV)
    if raw:
        try:
            v = int(raw)
        except ValueError:
            v = budget
        if 0 < v < budget:
            budget = v
    return budget


def size(text: str) -> int:
    return len(text.encode("utf-8"))


@dataclass(frozen=True)
class Candidate:
    """One recalled note, already rendered: its full line, its short line (or None) and
    whether it carries a date (for the undated-first display order)."""
    full: str
    short: str | None
    dated: bool


def omitted_line(n: int) -> str:
    """The plain line that closes a block from which ``n`` notes were left out."""
    return (f"({n} more note{'s' if n != 1 else ''} did not fit here. "
            "The Atlaso recall tool can show them.)")


# Room kept for omitted_line whatever the count (a 3-digit count is far above any recall
# limit; recall returns at most a few dozen notes).
_OMIT_RESERVE = size(omitted_line(999)) + 1


def fit_lines(head: str, tail: str, cands: list[Candidate], budget: int) -> tuple[list[int], list[str], int] | None:
    """Pick whole lines for ``head`` + lines + ``tail`` within ``budget`` bytes.

    Notes are taken in rank order: a note's full line if it fits in the space left, else its
    short line if that fits, else the note is left out and the next one is tried. Room for
    the closing omitted line is reserved, so the block never goes over even when notes are
    dropped. Returns (kept rank indices, chosen line per kept note, omitted count), or None
    when not even the frame fits (inject nothing)."""
    frame = size(head) + size(tail)
    room = budget - frame - _OMIT_RESERVE
    if room < 0:
        return None
    kept: list[int] = []
    chosen: list[str] = []
    for i, c in enumerate(cands):
        for line in (c.full, c.short):
            if not line:
                continue
            cost = size(line) + 1  # the line and its newline
            if cost <= room:
                kept.append(i)
                chosen.append(line)
                room -= cost
                break
    return kept, chosen, len(cands) - len(kept)


def fit_block(head: str, tail: str, cands: list[Candidate], budget: int, order) -> str | None:
    """The fitted block ``head`` + lines + optional omitted line + ``tail``, or None when
    there are no candidates or the frame alone does not fit. ``order`` maps the kept
    ``(dated, line)`` pairs (rank order) to display order (``_render.undated_first``)."""
    if not cands:
        return None
    fitted = fit_lines(head, tail, cands, budget)
    if fitted is None:
        return None
    kept, chosen, omitted = fitted
    lines = order([(cands[i].dated, line) for i, line in zip(kept, chosen)])
    if omitted:
        lines.append(omitted_line(omitted))
    text = head + "\n".join(lines) + tail
    return text if size(text) <= budget else None  # unreachable; never print over budget
