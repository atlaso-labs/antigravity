"""Commodity capture heuristics for the thin client — NOT the IP.

These are simple regex/string helpers (a chatter gate, scope router, polarity hint,
secret scrub, near-dup check) that decide WHETHER and HOW to send a capture to the
server. None of the proprietary engine (retrieval/dispersion/evidence-gate/FMI)
lives here — that stays on the brain. Safe to ship to users. Ported from the
legacy engine plugin so the thin connectors keep the same capture quality.
"""
from __future__ import annotations

import math
import re
from collections import Counter

# ── worth-keeping gate ───────────────────────────────────────────────────────
_CHATTER = re.compile(
    r"^(?:ok(?:ay)?|k|thx|thanks?|thank you|ty|yes|yep|yeah|yup|no|nope|sure|cool|"
    r"nice|great|awesome|perfect|lgtm|got it|continue|go ahead|do it|please do|"
    r"proceed|run it|run the tests?|next|stop|wait|hmm+|ah|oh|nvm|never ?mind)"
    r"[\s.!?]*$",
    re.IGNORECASE,
)
_SIGNAL = re.compile(
    r"(?i)\b(prefer|always|never|don'?t|do not|avoid|use\b|using|i like|we should|"
    r"should (?:always|never|use)|remember|note that|going with|decided|rule:|"
    r"important|make sure|ensure|must\b|need to|require|my .+ is\b|the .+ is\b)\b"
)
MIN_WORDS = 4

# System/harness-generated turns are NOT the user speaking — task notifications,
# agent-to-agent mail, slash-command echoes, image-attachment stubs. They are
# worthless as memories (free users have NO server-side enricher to clean them up)
# AND their markup is what pattern-matches Cloudflare WAF rules and gets whole
# deposit batches blocked at the edge. Gate them out at the source.
_SYSTEM_TURN_PREFIXES = (
    "<task-notification>",
    "<teammate-message",
    "<agent-message",
    "<local-command-caveat>",
    "<command-name>",
    "<command-message>",
    "<local-command-stdout>",
    "<system-reminder>",
    "[Image: source:",
    "[Image #",
    # The harness prepends prose BEFORE the tag on inter-agent mail and system
    # notifications — the bare-tag prefixes above never see it (leaked live
    # 2026-07-13: "Another Claude session sent a message: <teammate-message…"
    # rows reached the dashboard).
    "Another Claude session sent a message:",
    "[SYSTEM NOTIFICATION",
)

# Auto-capture size cap. Longer user turns are almost always pasted logs/docs/
# diffs — junk as a memory and hostile to the WAF's body-inspection window. The
# EXPLICIT paths (MCP remember / manual) are not capped by this — only the
# ambient per-turn capture.
MAX_CAPTURE_CHARS = 4000


def is_system_turn(text: str) -> bool:
    t = (text or "").lstrip()
    return any(t.startswith(p) for p in _SYSTEM_TURN_PREFIXES)


def should_deposit(user_text: str) -> tuple[bool, str]:
    t = (user_text or "").strip()
    if not t:
        return False, "empty"
    if is_system_turn(t):
        return False, "system_turn"
    if len(t) > MAX_CAPTURE_CHARS:
        return False, "too_long"
    if _CHATTER.match(t):
        return False, "chatter"
    if _SIGNAL.search(t):
        return True, "signal"
    if len(t.split()) < MIN_WORDS:
        return False, "too_short"
    return True, "substantive"


def heuristic_polarity(user_text: str) -> str:
    t = (user_text or "").lower()
    if re.search(r"\b(never|don'?t|do not|avoid|stop|doesn'?t work|didn'?t work|"
                 r"fails?|failed|broke|broken|bug|wrong|bad)\b", t):
        return "cautionary"
    if re.search(r"\b(prefer|always|use|like|love|want|should|works?|good)\b", t):
        return "positive"
    return "open"


# ── scope router (personal/global vs project) ────────────────────────────────
_PERSONAL = re.compile(
    r"(?i)\b(i (?:prefer|like|love|always|usually|tend to|never|hate|avoid)\b"
    r"|my (?:favou?rite|preferred|default|usual|go-?to|style|setup|workflow)\b"
    r"|for all my (?:projects|repos)\b|i'?m a .*?(?:person|developer|engineer)\b)"
)
_PROJECT = re.compile(
    r"(?i)\b(this (?:project|repo|codebase|app|service)|in this (?:repo|project)"
    r"|the (?:server|database|db|api|endpoint|service|build|deploy(?:ment)?|schema)\b"
    r"|localhost|127\.0\.0\.1|\b\d{1,3}(?:\.\d{1,3}){3}\b)"
    r"|/[\w.\-]+/[\w./\-]+",
)


def classify_scope(user_text: str) -> str:
    t = user_text or ""
    if _PROJECT.search(t):
        return "project"
    if _PERSONAL.search(t):
        return "personal"
    return "project"  # default: contain locally rather than pollute global


# ── secret scrub (defense-in-depth; the server re-scrubs too) ────────────────
_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    ("private_key", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL)),
    ("openai_anthropic_key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    # credentialed URIs: postgres://user:pass@host, redis://:pass@host, etc. —
    # mask only the password in the userinfo, keep the rest of the URL readable.
    ("uri_credential", re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]*):([^\s/@]+)@")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}")),
    ("assignment", re.compile(
        r"(?i)\b([A-Za-z0-9_]*(?:api[_-]?key|secret|token|password|passwd|pwd|"
        r"access[_-]?key|client[_-]?secret|auth[_-]?token)[A-Za-z0-9_]*)"
        r"\s*[:=]\s*[\"']?([^\s\"']{6,})[\"']?")),
]
_BLOB = re.compile(r"\b[A-Za-z0-9+/=_-]{32,}\b")
_ENTROPY_THRESHOLD = 4.2


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def scrub(text: str) -> tuple[str, list[str]]:
    if not text:
        return text, []
    found: list[str] = []
    out = text
    for kind, pat in _PATTERNS:
        def _repl(m: "re.Match[str]", _kind: str = kind) -> str:
            found.append(_kind)
            if _kind == "assignment" and m.lastindex and m.lastindex >= 2:
                return f"{m.group(1)}=[REDACTED]"
            if _kind == "uri_credential":
                return f"{m.group(1)}:[REDACTED]@"  # keep scheme+user+host, mask pass
            return f"[REDACTED:{_kind}]"
        out = pat.sub(_repl, out)

    def _blob_repl(m: "re.Match[str]") -> str:
        tok = m.group(0)
        if "REDACTED" in tok:
            return tok
        if _entropy(tok) >= _ENTROPY_THRESHOLD:
            found.append("high_entropy")
            return "[REDACTED:high_entropy]"
        return tok
    out = _BLOB.sub(_blob_repl, out)
    return out, found


# ── near-duplicate check ─────────────────────────────────────────────────────
def _tokens(s: str) -> set[str]:
    return set(re.findall(r"\w+", (s or "").lower()))


def _bag_similar(new: str, existing: str, jaccard: float = 0.85,
                 containment: float = 0.95) -> bool:
    """The legacy bag-of-words test: high Jaccard (near-twins) or high containment of
    new-in-existing (new ⊆ existing). Blind to word order and to which word changed."""
    tn, te = _tokens(new), _tokens(existing)
    if not tn or not te:
        return False
    inter = len(tn & te)
    return inter / len(tn | te) >= jaccard or inter / len(tn) >= containment


# Words that add no content: a twin that only adds these is still a duplicate
# ("Note that …", "Heads up: …", "… here."). Anything else it adds is new content.
_NO_CONTENT = frozenset((
    "a an the and or but so to of in on at for with by from is are was were be been it its "
    "this that these those we our us i you your my here there now just also note heads up "
    "please remember important rule fyi ok okay").split())
# Words whose neighbours carry the direction of a change ("from A to B").
_DIRECTION = frozenset("from to instead over back replaced replace switched moved".split())
# Past-tense framings: a statement ABOUT an old value, never an adoption of it.
_PAST_FRAMING = re.compile(
    r"\b(?:back when|used to|we had|before (?:we|the) (?:move|moved|switch|switched|migrat\w*)"
    r"|previously|originally)\b", re.I)
_ADOPT_LEAD = frozenset(("to", "use", "using", "adopt", "adopting"))


def value_tokens(s: str) -> list[str]:
    """Tokens that keep - . / : inside a value, so eu-west-1 or /api/v2 stays one token."""
    return re.findall(r"\w[\w\-./:]*\w|\w", (s or "").lower())


def _direction_pairs(s: str) -> set[tuple[str, str]]:
    t = value_tokens(s)
    return {(a, b) for a, b in zip(t, t[1:]) if a in _DIRECTION or b in _DIRECTION}


def near_kind(new: str, existing: str, jaccard: float = 0.85,
              containment: float = 0.95) -> str | None:
    """How `new` relates to `existing`:
      None        — not a near-twin (keep; unrelated or richer);
      "update"    — a near-twin that changes something: (i) it adds a content word the
                    existing memory lacks (a substituted value), or (ii) it reverses a
                    direction ("from B to A" against "from A to B"). Keep it — dropping it
                    would silently lose the change;
      "duplicate" — a near-twin that adds nothing (skip it)."""
    if not _bag_similar(new, existing, jaccard, containment):
        return None
    if (_tokens(new) - _tokens(existing)) - _NO_CONTENT:  # rule (i): new content
        return "update"
    if _direction_pairs(new) - _direction_pairs(existing):  # rule (ii): other direction
        return "update"
    return "duplicate"


def near_dup(new: str, existing: str, jaccard: float = 0.85, containment: float = 0.95) -> bool:
    """True when `new` adds nothing over `existing` (so skip it): bag-similar AND no new
    content word AND no new direction pair. A substituted value or a mirrored change is
    an update and is kept (see near_kind)."""
    return near_kind(new, existing, jaccard, containment) == "duplicate"


_FROM_SLOT = frozenset(("from", "over", "instead", "replaced", "replace"))


def replaced_value(old: str, superseder: str) -> set[str]:
    """The value `superseder` replaced in `old`: the tokens in the superseder's
    "from X" / "over X" / "instead of X" slot that `old` also contains; for a same-shape
    update without such a slot, the content tokens `old` has and the superseder lacks
    ("port 5433" vs "port 55432" -> {"5433"})."""
    t_old, t_sup = set(value_tokens(old)), value_tokens(superseder)
    slot = {b for a, b in zip(t_sup, t_sup[1:]) if a in _FROM_SLOT} & t_old
    slot |= {c for a, b, c in zip(t_sup, t_sup[1:], t_sup[2:])
             if (a, b) == ("instead", "of")} & t_old
    return (slot or (t_old - set(t_sup))) - _NO_CONTENT


def adopts_value(new: str, values: "set[str] | frozenset[str]") -> bool:
    """True when `new` ADOPTS one of `values` ("going back to A", "switch from B
    to A", "use A again"); False for past-tense framings ("back when we used A", "we
    used to use A before …"). Conservative by design: it gates writing a supersedes
    edge, and a false edge hides the current value silently."""
    vals = {v for v in values if v and v not in _NO_CONTENT}
    if not vals or _PAST_FRAMING.search(new or ""):
        return False
    t = value_tokens(new)
    for i, tok in enumerate(t):
        if tok in _ADOPT_LEAD and vals & set(t[i + 1:i + 4]):
            return True
        if tok == "again" and vals & set(t[max(0, i - 4):i]):
            return True
    return False
