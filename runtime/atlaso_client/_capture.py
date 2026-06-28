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


def should_deposit(user_text: str) -> tuple[bool, str]:
    t = (user_text or "").strip()
    if not t:
        return False, "empty"
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


def near_dup(new: str, existing: str, jaccard: float = 0.85, containment: float = 0.95) -> bool:
    """True when `new` adds essentially nothing over `existing` (so skip it). High
    Jaccard = near-twins; high containment of new-in-existing = new ⊆ existing. A
    richer/longer new statement is kept (containment drops below the bar)."""
    tn, te = _tokens(new), _tokens(existing)
    if not tn or not te:
        return False
    inter = len(tn & te)
    jacc = inter / len(tn | te)
    contain_new = inter / len(tn)
    return jacc >= jaccard or contain_new >= containment
