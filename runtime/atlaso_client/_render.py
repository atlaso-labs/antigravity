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

from ._capture import scrub as _scrub_credentials

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


# A credential-scrub marker in the folded (lowercased) view: [REDACTED] or [REDACTED:kind].
_SCRUB_MARK_RE = re.compile(r"\[redacted(?::[a-z0-9_]+)?\]")


def _in_scrub_marker(i: int, held: list[tuple[int, int]]) -> bool:
    return any(a <= i < b for a, b in held)


def _neutralize_markers(s: str) -> str:
    """Step 3: replace every fence-forging marker (plus its '=' decoration) with
    _FENCE_TOKEN in one left-to-right pass on the folded view. One pass is enough: the
    token contains letters, so text on its two sides can never join into a new marker."""
    folded, origin = _fold(s)
    held = [m.span() for m in _SCRUB_MARK_RE.finditer(folded)]
    out: list[str] = []
    pos_f = pos = 0  # consumed prefix, in folded and in original coordinates
    for m in _MARKER_RE.finditer(folded):
        a, b = m.start(), m.end()
        if a < pos_f:
            continue
        # The runs of non-alphanumeric characters right before and after the marker. It
        # forges a fence when either run holds '=' (or it starts with END); a run holding
        # '=' is replaced with the marker, minus the space/tab padding at its outer edge.
        # A run never reaches into a credential-scrub marker ("[REDACTED...]"): the hook
        # line is scrubbed before it is sanitized (redact_line), so a marker can sit
        # right next to a fence decoration and must keep its brackets.
        lo = a
        while lo > pos_f and not folded[lo - 1].isalnum() and not _in_scrub_marker(lo - 1, held):
            lo -= 1
        hi = b
        while hi < len(folded) and not folded[hi].isalnum() and not _in_scrub_marker(hi, held):
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


# How many scrub/sanitize rounds ``redact_line`` runs after the raw-text scrub. Each
# round only replaces matches with markers; real notes settle in one or two. A line that
# has not settled by then is returned as the last round left it, and the renderer
# contract test (test_redact_fixpoint) proves a further scrub changes nothing.
_REDACT_ROUNDS = 4


def redact_line(s: object, mode: str = "collapse") -> str:
    """One stored string -> one safe, credential-redacted line. Every note text and short
    form goes through this before it can reach a prompt, so a credential stored by an
    older client, an import, or in local-only/offline mode (where only the connector ever
    scrubbed it) is replaced in place; the note itself is never dropped.

    Order matters (CodeRedTeam 8af8fbbe CRT-1):
      1. scrub the text AS STORED (``redact_text``), while its line breaks still end
         values: a quoted value with no closing quote stops at the line end, so a
         multiword passphrase is masked whole, exactly as the server and the MCP
         ``redact_text`` paths mask it. Collapsing the line first left the tail visible;
      2. ``sanitize_line`` (one line, no hidden characters, no forged fence);
      3. scrub the sanitized line again and re-sanitize until nothing changes, so hidden
         characters cannot split a token past the scrub and the printed line is a fixed
         point of the scrub (a second scrub removes nothing; at most it relabels one of
         its own markers, see ``_unlabel``).
    The scrub is the connector credential scrub (``_capture.scrub``: the server's full
    detection set, kept in a byte-identical copy in ``_scrub`` with a drift test, plus the
    server's markers). Text with no credential keeps its bytes (``sanitize_line`` of the
    stored text). The TypeScript mirrors (tools/cursor, tools/opencode lib/render.ts,
    ``redactLine``) do the same; shared expectations: client/tests/fixtures/
    redact_contract.json."""
    if mode not in SPACING_MODES:
        raise ValueError(f"unknown spacing mode {mode!r}")
    if not isinstance(s, str) or not s:
        return ""
    line = sanitize_line(redact_text(s), mode)
    for _ in range(_REDACT_ROUNDS):
        if not line:
            return line
        red, _kinds = _scrub_credentials(line)
        if _unlabel(red) == _unlabel(line):
            # Nothing new removed. The canonical scrub relabels its own marker on a second
            # pass in URI userinfo ("[REDACTED]" <-> "[REDACTED:residue]", period 2), so a
            # label-only change counts as settled; the line is returned as it was.
            return line
        line = sanitize_line(red, mode)
    return line


_SCRUB_LABEL_RE = re.compile(r"\[REDACTED(?::[a-z0-9_]+)?\]")


def _unlabel(s: str) -> str:
    """``s`` with every scrub marker written as plain ``[REDACTED]``."""
    return _SCRUB_LABEL_RE.sub("[REDACTED]", s)


def redact_text(s: object) -> object:
    """Credential redaction for model-visible Atlaso text that is NOT printed as a hook
    line: the MCP ``recall``/``recent``/``ambient`` tool results and the session-start
    brief. Same scrub and markers as ``redact_line``, but no
    sanitizing: spacing, line breaks and every other byte are left alone, so text with no
    credential is returned unchanged (the same object). Hidden characters are removed
    only when that is what exposes a split credential (``sk-...<U+200B>...``). Never
    drops the text; a non-string is returned as is. Text the scrub changed is scrubbed
    again until a pass removes nothing more (``_settle``), so a second scrub of the result
    removes nothing (CodeRedTeam 8af8fbbe CRT-1 contract)."""
    if not isinstance(s, str) or not s:
        return s
    red, _ = _scrub_credentials(s)
    bare = _drop_hidden(red)
    if bare != red:
        rejoined, kinds = _scrub_credentials(bare)
        if kinds:
            return _settle(rejoined)
    return s if red == s else _settle(red)


def _settle(red: str) -> str:
    """Scrub already-scrubbed text again until a pass removes nothing (a label-only change
    counts as settled, see ``_unlabel``). The canonical scrub can remove a little more on a
    second pass: punctuation glued to a marker ("password=[REDACTED]; later")."""
    for _ in range(_REDACT_ROUNDS):
        again, _kinds = _scrub_credentials(red)
        if _unlabel(again) == _unlabel(red):
            return red
        red = again
    return red


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


def _short_content(r: dict, full: str, mode: str) -> str | None:
    """The note's short form (the ranker's optional ``short`` field), sanitized and
    redacted like the content, or None when absent, empty or no shorter than the content."""
    short = redact_line(r.get("short"), mode)
    return short if short and len(short) < len(full) else None


# The header never names the user: the connected user id is an account identifier and
# must not be put in front of the model (SecurityEngineer 4c26fd7d finding 3).
RECALL_HEAD = ("=== ATLASO MEMORY ===\n"
               "Recalled notes from prior sessions for user \"you\".\n")


def recall_block(result: dict, *, uid: str = "you", show_scope: bool = True,
                 now: datetime | None = None, tool: str | None = None,
                 budget: int | None = None) -> str | None:
    """Build the recall block from a /v1/recall response dict, or None if no
    results. Each line carries the note's date when the server sent created_at
    (rung 85bcf262 card B1); ``now`` decides whether the year is shown. Undated
    lines come first (``undated_first``). ``uid`` is accepted for older callers and
    ignored: the header always says "you" (RECALL_HEAD). Note text and short forms are
    credential-redacted (``redact_line``) before fitting, so the budget measures what is
    printed.

    The block is fitted to ``budget`` UTF-8 bytes (default: ``tool``'s budget in
    ``_inject.HOSTS``): whole notes in rank order, a note's short form when only that
    fits, lower-ranked notes left out rather than the block going over (``_inject``)."""
    from . import _inject

    now = now or datetime.now(timezone.utc)
    results = (result or {}).get("results") or []
    if not results:
        return None

    def note_line(r: dict, content: str, date: str | None) -> str:
        hd = bool(r.get("has_disagreement"))
        line = "- " + (f"[{date}] " if date else "") + ("[conflict] " if hd else "") + content
        peers = r.get("conflict_peers") or []
        if hd and peers:
            n = len(peers)
            line += f" (conflicts with {n} other note{'s' if n != 1 else ''})"
        scope = sanitize_line(r.get("scope"))
        if show_scope and scope:
            line += f"  [{scope}]"
        return line

    cands: list[_inject.Candidate] = []
    for r in results:
        date = _date_label(r.get("created_at"), now)
        content = redact_line(r.get("content", ""))
        short = _short_content(r, content, "collapse")
        cands.append(_inject.Candidate(note_line(r, content, date),
                                       note_line(r, short, date) if short else None,
                                       date is not None))
    tail = "\n=== END ATLASO MEMORY ==="
    return _inject.fit_block(RECALL_HEAD, tail, cands,
                             _inject.budget_for(tool) if budget is None else budget,
                             undated_first)


def fenced_block(results: list[dict], banner: str, mode: str, *, now: datetime | None = None,
                 tool: str | None = None, budget: int | None = None) -> str | None:
    """The Codex/Antigravity block: ``=== <banner> ===`` fences, one dated line per
    non-empty note (no conflict marker, no scope), in ``mode`` spacing, credential-redacted
    (``redact_line``), fitted to the
    tool's budget exactly like ``recall_block``. None when nothing is usable."""
    from . import _inject

    now = now or datetime.now(timezone.utc)
    cands: list[_inject.Candidate] = []
    for r in results or []:
        content = redact_line(r.get("content", ""), mode)
        if not content:
            continue
        date = _date_label(r.get("created_at"), now)
        prefix = "- " + (f"[{date}] " if date else "")
        short = _short_content(r, content, mode)
        cands.append(_inject.Candidate(prefix + content, prefix + short if short else None,
                                       date is not None))
    fence = f"=== {banner} ==="
    return _inject.fit_block(fence + "\n", "\n" + fence, cands,
                             _inject.budget_for(tool) if budget is None else budget,
                             undated_first)
