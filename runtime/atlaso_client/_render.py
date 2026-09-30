"""Render the recalled-memory injection block — shared by every connector.

A plain, branded block: the brand fence top and bottom, a short "whose notes,
from when" line, then one bullet per note. No "untrusted data" warning and no
instructions — the model decides how to use it. Driven by the server's /v1/recall
response (which carries per-result scope + conflict info). Recall is queried
EVIDENCE (distinct from the ambient "back of your mind" orientation block);
conflict peers are summarized as a COUNT so internal deposit ids never leak.
"""
from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone

_YEAR_AFTER_DAYS = 335  # ~11 months: older notes carry the year, recent ones do not
# Fixed English abbreviations (never strftime('%b'), which follows the process locale);
# the TypeScript mirrors (tools/cursor, tools/opencode lib/render.ts) use the same table.
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

# ── One line-sanitizer contract for every hook renderer (security batch B1: G1 + L1) ──
# This module, the Codex and Antigravity renderers, and the TypeScript mirrors
# (sanitizeLine in tools/cursor and tools/opencode lib/render.ts) apply exactly these
# steps, in this order, to every stored string they print. The rule is "remove only what
# can forge block structure or hide text; leave ordinary text byte-identical":
#   1. hidden characters are removed: every Cc (control) that is not whitespace, every Cs
#      (lone surrogate) and every Cf (format: zero-width space, bidi embedding/override/
#      isolate, BOM, tag characters), EXCEPT (a) U+200C/U+200D (ZWNJ/ZWJ) whose two
#      neighbours are both visible non-ASCII characters (emoji ZWJ sequences, Indic and
#      Persian text), and (b) the three RGI subdivision flag sequences (_TAG_FLAGS);
#   2. whitespace (_SPACE, Python's str.isspace set spelled out for the mirrors) follows
#      the connector's own pre-B1 spacing, so ordinary notes keep their bytes:
#        "collapse"   (shared recall_block: Claude Code, Grok Build) every run -> one space;
#        "join_lines" (Codex, Antigravity, OpenCode) a run containing a line break
#                     (_BREAKS) -> one space; tabs and other spacing kept verbatim;
#        "each_line"  (Cursor) each line break (CRLF counts once) -> one space; other
#                     spacing kept verbatim;
#      then the ends are trimmed. No mode can leave a line break: saved text can never
#      add a line to the injected block;
#   3. an Atlaso block marker that forges a fence -- '=' in the run of non-alphanumeric
#      characters right before or after it, or a leading END -- is replaced by "[fence]",
#      together with each adjacent run that holds '=' (minus its outer space/tab padding). Markers are found
#      on a per-code-point NFKC + lowercase view that skips the kept joiners, tag
#      characters and combining marks, so fullwidth, case, NUL/ZWSP/ZWJ-split and
#      '\uff1d' (fullwidth '=') variants all count. A marker word in ordinary prose
#      ("use Atlaso memory for this") cannot open or close a block and is kept.
# Step 1 runs before step 3, so a removed character can never be "repaired" into a fence
# after the matcher ran. Shared expectations: client/tests/fixtures/sanitize_contract.json
# (pytest + bun). Not covered: look-alike letters from other scripts (e.g. Cyrillic А);
# the one-line guarantee holds for them regardless.
_SPACE = frozenset(
    "\t\n\x0b\x0c\r\x1c\x1d\x1e\x1f \x85\xa0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)
# Line breaks: str.splitlines() boundaries. A whitespace run holding one of these is a
# line break in every mode.
_BREAKS = frozenset("\n\x0b\x0c\r\x1c\x1d\x1e\x85\u2028\u2029")
_DROP_CATEGORIES = frozenset(("Cc", "Cf", "Cs"))
_JOINERS = frozenset("\u200c\u200d")
_HIDDEN_NEIGHBOUR = frozenset(("Cc", "Cf", "Cs", "Zs", "Zl", "Zp"))
# England, Scotland, Wales: the only RGI emoji that use tag characters. Any other tag
# sequence can smuggle invisible ASCII and is removed.
_TAG_FLAGS = tuple(
    "\U0001F3F4" + "".join(chr(0xE0000 + ord(c)) for c in code) + "\U000E007F"
    for code in ("gbeng", "gbsct", "gbwls")
)
SPACING_MODES = ("collapse", "join_lines", "each_line")
# Marker core on the folded view, anchored on the literal "atlaso"; the words may be
# separated by up to three non-alphanumeric characters ("Atlaso-Memory", "ATLASO · THE
# BACK OF YOUR MIND"). The '=' decoration around it is found and widened by hand in
# _neutralize_markers, which keeps the scan linear on long '=' runs.
_MARKER_SEP = r"[^a-z0-9]{0,3}"  # up to 3 separators of any kind between marker words
_MARKER_RE = re.compile(
    rf"(?:(?<![a-z0-9])end{_MARKER_SEP})?atlaso{_MARKER_SEP}(?:the{_MARKER_SEP})?"
    rf"(?:memory|orientation|back{_MARKER_SEP}of{_MARKER_SEP}your{_MARKER_SEP}mind)"
)
_FENCE_TOKEN = "[fence]"
_PAD = " \t"  # horizontal padding allowed between a marker and its '=' decoration


def _visible_non_ascii(ch: str) -> bool:
    return ord(ch) >= 0x80 and unicodedata.category(ch) not in _HIDDEN_NEIGHBOUR


def _drop_hidden(s: str) -> str:
    """Step 1: remove hidden code points; whitespace is left for step 2."""
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        ch = s[i]
        if ch == "\U0001F3F4":
            flag = next((f for f in _TAG_FLAGS if s.startswith(f, i)), ch)
            out.append(flag)
            i += len(flag)
            continue
        if ch in _SPACE:
            out.append(ch)
        elif ch in _JOINERS:
            if 0 < i < n - 1 and _visible_non_ascii(s[i - 1]) and _visible_non_ascii(s[i + 1]):
                out.append(ch)
        elif unicodedata.category(ch) not in _DROP_CATEGORIES:
            out.append(ch)
        i += 1
    return "".join(out)


def _space(s: str, mode: str) -> str:
    """Step 2: apply the connector's spacing mode to every whitespace run, then trim."""
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        if s[i] not in _SPACE:
            j = i
            while j < n and s[j] not in _SPACE:
                j += 1
            out.append(s[i:j])
            i = j
            continue
        j = i
        while j < n and s[j] in _SPACE:
            j += 1
        run = s[i:j]
        i = j
        if mode == "collapse" or (mode == "join_lines" and any(c in _BREAKS for c in run)):
            out.append(" ")
        elif mode == "each_line":
            out.append("".join(" " if c in _BREAKS or c == "\x1f" else c
                               for c in run.replace("\r\n", "\n")))
        else:  # join_lines without a break: verbatim, except the one non-tab control
            out.append(run.replace("\x1f", " "))
    return "".join(out).strip("".join(_SPACE))


def _folds_to_nothing(ch: str) -> bool:
    return ch in _JOINERS or 0xE0000 <= ord(ch) <= 0xE007F or unicodedata.category(ch) in ("Mn", "Me")


def _fold(s: str) -> tuple[str, list[int]]:
    """Per-code-point NFKC + lowercase view of ``s``, and for every folded code point
    the index of the original code point it came from. Kept joiners, tag characters and
    combining marks fold to nothing, so they cannot split a marker."""
    if s.isascii():
        return s.lower(), list(range(len(s)))
    out: list[str] = []
    origin: list[int] = []
    for i, ch in enumerate(s):
        if _folds_to_nothing(ch):
            continue
        f = unicodedata.normalize("NFKC", ch).lower()
        out.append(f)
        origin.extend([i] * len(f))
    return "".join(out), origin


def _neutralize_markers(s: str) -> str:
    """Step 3: replace every fence-forging marker (plus its '=' decoration) with
    _FENCE_TOKEN in one left-to-right pass on the folded view. One pass is enough: the
    token contains letters, so text on its two sides can never join into a new marker."""
    folded, origin = _fold(s)
    out: list[str] = []
    pos_f = pos = 0  # consumed prefix, in folded and in original coordinates
    for m in _MARKER_RE.finditer(folded):
        a, b = m.start(), m.end()
        if a < pos_f:
            continue
        # The runs of non-alphanumeric characters right before and after the marker. It
        # forges a fence when either run holds '=' (or it starts with END); a run holding
        # '=' is replaced with the marker, minus the space/tab padding at its outer edge.
        lo = a
        while lo > pos_f and not folded[lo - 1].isalnum():
            lo -= 1
        hi = b
        while hi < len(folded) and not folded[hi].isalnum():
            hi += 1
        pre, post = "=" in folded[lo:a], "=" in folded[b:hi]
        if not (pre or post or m.group().startswith("end")):
            continue
        if pre:
            while folded[lo] in _PAD:
                lo += 1
        else:
            lo = a
        if post:
            while folded[hi - 1] in _PAD:
                hi -= 1
        else:
            hi = b
        start, end = origin[lo], origin[hi - 1] + 1
        # Never split a joiner, tag or combining sequence at the edges of the replacement.
        while start > pos and _folds_to_nothing(s[start - 1]):
            start -= 1
        while end < len(s) and _folds_to_nothing(s[end]):
            end += 1
        out += (s[pos:start], _FENCE_TOKEN)
        pos, pos_f = end, hi
    out.append(s[pos:])
    return "".join(out)


def sanitize_line(s: object, mode: str = "collapse") -> str:
    """One stored string -> one safe line, per the contract above. ``mode`` is the
    connector's spacing mode (SPACING_MODES). A non-string or empty value renders as ""."""
    if mode not in SPACING_MODES:
        raise ValueError(f"unknown spacing mode {mode!r}")
    if not isinstance(s, str) or not s:
        return ""
    return _neutralize_markers(_space(_drop_hidden(s), mode))


_sanitize = sanitize_line  # earlier private name; kept for existing importers


def _date_label(created_at: object, now: datetime) -> str | None:
    """'Aug 14' (UTC calendar day, English month, no zero pad); 'Aug 14 2025' when the
    note is more than ~11 months older than ``now``. None when the server sent no or a
    malformed created_at (an older brain): the line renders undated, never an error.
    A timestamp without an offset is read as UTC (the server always sends UTC)."""
    if not isinstance(created_at, str) or not created_at:
        return None
    try:
        dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    dt = (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    now = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    label = f"{_MONTHS[dt.month - 1]} {dt.day}"
    if (now - dt).days > _YEAR_AFTER_DAYS:
        label += f" {dt.year}"
    return label


def undated_first(lines: list[tuple[bool, str]]) -> list[str]:
    """Stable partition of rendered ``(dated, line)`` pairs: UNDATED lines first,
    then dated lines, each group in recall order. A line is undated when the
    server could not justify an original statement time (null ``created_at``), so
    it is never placed where a reader would read it as the newest note."""
    return [line for dated, line in lines if not dated] + [line for dated, line in lines if dated]


def recall_block(result: dict, *, uid: str = "you", show_scope: bool = True,
                 now: datetime | None = None) -> str | None:
    """Build the recall block from a /v1/recall response dict, or None if no
    results. Each line carries the note's date when the server sent created_at
    (rung 85bcf262 card B1); ``now`` decides whether the year is shown. Undated
    lines come first (``undated_first``)."""
    now = now or datetime.now(timezone.utc)
    results = (result or {}).get("results") or []
    if not results:
        return None
    lines: list[tuple[bool, str]] = []
    for r in results:
        hd = bool(r.get("has_disagreement"))
        date = _date_label(r.get("created_at"), now)
        line = ("- " + (f"[{date}] " if date else "") + ("[conflict] " if hd else "")
                + sanitize_line(r.get("content", "")))
        peers = r.get("conflict_peers") or []
        if hd and peers:
            n = len(peers)
            line += f" (conflicts with {n} other note{'s' if n != 1 else ''})"
        scope = sanitize_line(r.get("scope"))
        if show_scope and scope:
            line += f"  [{scope}]"
        lines.append((date is not None, line))
    return (
        "=== ATLASO MEMORY ===\n"
        f"Recalled notes from prior sessions for user \"{sanitize_line(uid)}\".\n"
        + "\n".join(undated_first(lines))
        + "\n=== END ATLASO MEMORY ==="
    )
