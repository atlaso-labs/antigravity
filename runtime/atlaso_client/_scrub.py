"""Pre-deposit secret scrubbing.

Auto-depositing transcripts will otherwise capture API keys, tokens, and
passwords verbatim, persist them to disk, and re-inject them into future
contexts. We mask anything that looks like a credential BEFORE it reaches the
store. Conservative on shape-matched secrets; cautious (but bounded) on
high-entropy blobs; label-context aware for the credentials people state in
prose, which carry no shape or entropy signature at all.

Passes, in order:
  1. shape patterns (private keys, vendor key formats, JWT, bearer, URI userinfo)
  2. assignment form            NAME = value (the whole value: quoted, or a passphrase
                                to the end of the clause)
  3. long hex                   (entropy provably cannot catch pure hex)
  4. prose credential           "my password is X" / "enter the PIN 4471"
  5. value-before-label         "X is the password"
  6. label-adjacent blob        label word within reach of an opaque run
  7. high-entropy blob          catch-all
  8. residue                    any >=12-char fragment of a redacted key elsewhere

Integrity invariant: every replacement is an offset splice of the original
text — nothing is ever re-located by string search, and nothing outside the
redacted span is dropped.

Known, disclosed limits: label and value in different messages; secrets stated
with no label at all ("just use 4471 at the side door"); non-English labels;
a fragment whose full value never appears in the same text; a bare-pasted
32-hex vendor key with no label nearby; a literal '/' inside a URI password;
a URI password that is 1-5 digits followed by '?' or '#' (reads as port+query);
a duplicated copy of an all-letter random key whose shape reads as camelCase
AND whose entropy is below 4.0 (measured ~1 in 3000 random 24-char keys);
an unquoted assignment passphrase ends at the first function word (`password:
purple and gold` keeps "and gold") or after 25 words, and its plain dictionary
words are not swept where they appear alone elsewhere; a prose-label value that
opens with a quote never closed on its line (`password is "<key>` clipped); a value
written as a placeholder (REDACTED, ***, xxxx, <redacted>; `_is_placeholder`) is taken
as already blanked and left as written, so a real secret spelled exactly that way stays.
"""
from __future__ import annotations

import bisect
import math
import re
import unicodedata
from collections import Counter

# (kind, pattern). Order matters: specific shapes first, generic assignment last.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL)),
    ("openai_anthropic_key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("openai_anthropic_key", re.compile(r"\batbt_[A-Za-z0-9_-]{16,}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    # A Google key may end in "-": no word boundary follows it there, so the shape also ends
    # right after a trailing "-" (every earlier match still matches).
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}(?:\b|(?<=-))")),
    # Google's newer "AQ." authorization key (format undocumented; public reports show "AQ.Ab"):
    # 40+ key characters after AQ.Ab with at least one digit, so AQ.getAirQualityForRegion and
    # long identifiers with no digit are left alone (r33 item 5).
    ("google_aq_key", re.compile(r"\bAQ\.Ab(?=[A-Za-z_-]*[0-9])[A-Za-z0-9_-]{40,}")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    # Stripe secret / restricted / webhook-signing keys (publishable pk_ keys are
    # client-side by design and stay — see _PUBLISHABLE).
    ("stripe_secret_key", re.compile(r"\b(?:[sr]k_(?:live|test)|whsec)_[A-Za-z0-9]{16,}\b")),
    ("jwt", re.compile(r"(?<![A-Za-z0-9_-])(?P<pre>(?:(?!\beyJ)[A-Za-z0-9_-])*)"
                       r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}")),
    # scheme://user:password@host — the most common credential shape in a
    # developer session. The password may itself contain '@' (greedy, backtracks
    # to the last '@'), '?' and '#'. '/' is excluded so host:port/path never
    # reads as a password. Excluding '?'/'#' from the class instead (v5) was
    # FAIL-OPEN: a password containing either simply stopped matching and the
    # whole credential survived. The host:port?query@ false positive is handled
    # as a BOUNDARY rule — a "password" that is 1-5 digits then '?'/'#' is a
    # port followed by a query string, not a credential.
    ("uri_credential", re.compile(
        r"(?i)\b([a-z][a-z0-9+.\-]{1,30}://[^:/@\s\"'`]{0,64}:)(?!\d{1,5}[?#])([^\s\"'`/]{1,128})@(?=[A-Za-z0-9\[])")),
    # The same user:password@host with NO scheme (SecurityEngineer fff4b962 N1), e.g. a
    # remote pasted as `alice:<pw>@github.com/acme/repo`. Same groups and the same
    # replacement as above. The user starts a token: not after a word character, '.', '/',
    # a backslash, '@' or a bracket, so never inside scheme://user:pw@ (the rule above
    # already masked it) nor inside a [REDACTED:kind] marker. The user is never a no-slash
    # URI scheme or mail header (mailto:a@b, sip:, To:/Cc:/From:), a package alias
    # (npm:pkg@1.0), the `project:` tag prefix (`project:team:alice@acme.dev` is a project
    # key, while `project:alice:<pw>@host` still matches from `alice`), all digits
    # (10:30@cafe) or a credential name (the assignment pass masks those whole). The
    # password holds no bracket (it never spans a marker) and no backslash (a Windows path
    # such as C:<backslash>Users<backslash>me@corp). The host is a network host: an IP
    # literal `[`, or a name that has a dot or a port (`ref:main@origin`, `TODO:fix@later`
    # and Gradle's `group:name:1.0@jar` have neither), and never an image digest
    # (nginx:1.25@sha256:...). Group 3 is non-empty when a port or a path follows the host
    # (URL context); without it the password must also look like a secret
    # (`_N1_PLAIN_PASSWORD`), so `author:alice@example.com` is an address, not a credential.
    ("uri_credential", re.compile(
        r"(?i)(?<![A-Za-z0-9_.%+~\\/@\[\]-])"
        r"(?!(?:mailto|sips?|xmpp|tel|im|pres|news|urn|acct|geo|data|npm|jsr|"
        r"to|cc|bcc|from|re|fwd?|reply-to|sender|e-?mail|mail|contact|project):)"
        # Lookaheads stay within the 64-character user: an unbounded run here rescanned a
        # long word once per keyword in it (quadratic: 632 s on "token" x 104858).
        r"(?![0-9]{1,64}:)"
        r"(?![A-Za-z0-9_.%+~-]{0,63}?(?:api[_-]?key|secret|token|password|passwd|pwd|"
        r"access[_-]?key|auth[_-]?token)[A-Za-z0-9_.%+~-]{0,63}:)"
        r"([A-Za-z0-9_.%+~-]{1,64}:)(?!\d{1,5}[?#])([^\s\"'`/\\\[\]]{1,128})"
        r"@(?!sha(?:1|224|256|384|512):)"
        r"(?=\[|[A-Za-z0-9][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9]|:[0-9]))"
        r"(?=(\[|(?:[A-Za-z0-9-]{1,63}\.){0,8}[A-Za-z0-9-]{1,63}(?::[0-9]|/))?)")),
    # key-ish name = value  → keep the name, mask the value.
    ("assignment", re.compile(
        # The name is matched once, atomically (lookahead + backreference): every way to
        # split it around a keyword ends at the same place, so retrying the splits when the
        # value fails can only fail again, and on a long word of keywords it was quadratic.
        r"(?i)\b(?=([A-Za-z0-9_]*(?:api[_-]?key|secret|token|password|passwd|pwd|"
        r"access[_-]?key|client[_-]?secret|auth[_-]?token)[A-Za-z0-9_]*))\1"
        r"\s*[:=]\s*"
        # The value is masked WHOLE (BackendEngineer bb9ce163; field 8b51bc3a): taking only
        # the first word of `password = "purple strawberry mountain"` sent the rest to the
        # model through hosted recall, the brief and `short`.
        #   quoted (groups 2-3): the same quote char closes it, or the line/text ends first
        #     (a value clipped at an excerpt or window edge); 3-256 chars. A closing quote is
        #     glued to the value: one after a space (`password: "abc. key is "xyz`) or before
        #     a word character (`secret = "abc. token = "xyz`) is the NEXT value's opening
        #     quote, so it does not close this one.
        r"(?:([\"'])((?:(?!\2)[^\n]){3,256}?)(?:(?<!\s)\2(?!\w)|(?=\n|$))"
        #   unquoted (groups 4-7): an optional opening quote (no closing one found), the first
        #     token (>= 3 chars; lab round 9: a 3-char credential in assignment form was never
        #     confirmed at all), then the rest of the clause (group 6): space-separated words
        #     up to a newline, clause punctuation followed by a space or the end, a bracket or
        #     quote, a `#` or `//` comment, a credential name or prose label (the next
        #     credential keeps its own label), or a `name:`/`name=` token; at most 24 words.
        #     The replacer masks the tail only for an unquoted plain-word first token (a
        #     passphrase); a key-shaped first token (digits, symbols) is the whole value.
        #     Short values are vetted against the stopword list in the replacer so
        #     `PASSWORD=none` stays prose.
        r"|([\"']?)([^\s\"']{3,})"
        # (?=\S): a word starts only at a non-space, so a run of spaces before a line end
        # is given back in one step (the lookahead below rescanned it on every step).
        r"((?:[ \t]+(?=\S)(?![A-Za-z0-9_.-]*[ \t]*[:=])(?!#|//)"
        r"(?!\S*(?:api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key|auth[_-]?token))"
        r"(?!(?:pass(?:phrase|code|word)?|pin|otp|key|creds?|credentials?|login|cvv2?|cvc|code)(?!\w))"
        r"(?:[^\s.;!?,()\"'`]|[.;!?,](?=\S))+){0,24})"
        r"([\"']?))")),
]

# The scheme-less user:password@host rule (N1) is tried at every position, so text with no
# '@' or no ':' (which it cannot match) skips it: the same result, without that scan.
_URI_NO_SCHEME = next(p for k, p in _PATTERNS if k == "uri_credential" and "://" not in p.pattern)
# A password N1 leaves alone when no port or path follows the host: lowercase letters and
# `._+-`, with at most a capital first letter (`alice`, `bob`, `alice.smith`, `Alice`): the
# local part of an address after a label (`author:alice@example.com`). A digit, any other
# capital or any other character (`!`, `@`, `%`, `:`) reads as a secret. Every suffix of
# such a password is one too, so a match skipped for it can hide no credential inside it.
# Case-sensitive on purpose (the N1 rule itself is not).
_N1_PLAIN_PASSWORD = re.compile(r"[A-Za-z]?[a-z._+-]*")

# Pure hex caps Shannon entropy at log2(16) = 4.0, below the blob threshold, so
# hex secrets need their own pass. Unlabeled hex is only taken at >=48 chars:
# 32-hex (fixture ids, hyphenless UUIDs, md5) and 40-hex (git SHAs) are the
# common non-secrets of developer text. Shorter hex is caught only when a
# credential label sits next to it (label-adjacent pass). Digest prefixes exempt.
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
_HEX = re.compile(r"(?<![A-Za-z0-9])(?:0x)?([0-9a-fA-F]{48,})(?![A-Za-z0-9])")
_DIGEST_PREFIX = re.compile(r"(?i)(?:sha(?:1|256|512)|md5|digest|blake2b?)\s*[:=]?\s*$")

# Catch-all for long high-entropy blobs that escaped the shape patterns.
_BLOB = re.compile(r"\b[A-Za-z0-9+/=_-]{32,}\b")
_ENTROPY_THRESHOLD = 4.2

# --- prose-form credentials -------------------------------------------------
# Strong labels name a thing that is a secret by definition: any value stated
# for them is redacted unless it reads as ordinary sentence continuation.
# Weak labels (token, key, secret, login) are used in ordinary technical prose
# constantly, so their values must additionally look credential-shaped.
_STRONG = (
    r"password|passphrase|pass ?phrase|passcode|pass ?code|pass-?word|passwd|pwd|"
    r"pin(?: ?code| ?number)?|otp|one[- ]time (?:code|password|pin)|2fa code|mfa code|"
    r"verification code|security code|auth(?:entication)? code|access code|"
    r"recovery code|backup code|login code|sms code|cvv|cvc|cvv2"
)
_WEAK = r"api ?key|secret(?: key)?|token|creds?|credentials?|login|key"
_QUAL = r"(?:master |root |admin |temp(?:orary)? |old |new |current |door |wifi |wi-fi |account |db |database |server |ssh |vpn |sudo )?"
_LABEL = rf"\b({_QUAL}(?:{_STRONG}|{_WEAK}))\b"
_TARGET = r"(?: (?:for|to|on|of) (?:my |the |our |his |her |their |your )?[\w.@/-]{1,40})?"
# What can sit between the label and its value. Regex alternation is ORDERED,
# not longest-match: the composed connector ("? it's", "— that's", ": it is")
# must come first, or the bare-punctuation branch wins, leaves "it's X" as the
# candidate, and the value escapes.
_LINK = (
    r"(?:\s*(?:[,(?—:=\-]+\s*)?(?:it'?s|it is|that'?s|that is|which is|would be|should be)\s+"
    r"|\s+(?:is|was|are|were|reads|equals|remains|stays|becomes)(?:\s+(?:set\s+to|still|now|currently|just))?\s*[:=]?\s*"
    r"|\s+(?:will|would|should|must|has to|needs to)\s+be\s*"
    r"|\s*[:=—→]\s*|\s*-+>\s*"
    r"|\s*\?\s+)"
)
# The candidate text after the link is a zero-width lookahead, NOT part of the
# match: the scan resumes right after the value, so a second credential on the
# same line is still seen ("db password is X. vpn password is Y.").
_PROSE = re.compile(rf"(?i){_LABEL}{_TARGET}{_LINK}(?=(?P<rest>[^\n]{{0,96}}))")
_IMPERATIVE = re.compile(
    rf"(?i)\b(?:enter|type|use|try|input|dial|punch in|key in|send|paste|put in|type in|"
    rf"submit|provide|give|share)\s+(?:the |your |my |this |our |a |that )?{_LABEL}{_TARGET}"
    rf"(?:\s+(?:is|of|as|:|=))?\s*(?=(?P<rest>[^\n]{{0,96}}))"
)
_VALUE_FIRST = re.compile(
    rf"(?i)(?:([\"'`])(?P<q>(?:(?!\1)[^\n]){{4,64}})\1|(?<![\w/])(?P<u>[^\s\"'`,;()]{{4,64}}))"
    rf"\s+(?:is|was|=|:)\s+(?:the|my|your|our|his|her|their|a|an)\s+"
    rf"(?:new |current |old |door |admin |root |wifi |account )?(?:{_STRONG}|{_WEAK})\b"
)
# Secondary defense: an opaque run near a credential label. Bare "key"/"login"
# are too generic to trigger this ("cache key namespace userSessionShard42").
_NEAR_LABEL = (
    rf"\b({_QUAL}(?:{_STRONG}|api ?key|secret(?: key)?|access key|private key|"
    rf"signing key|auth token|token|creds?|credentials?))\b"
)
# The gap never crosses a redaction marker: a label whose value is already redacted
# must not reach past it, swallow the NEXT label and then be skipped (BackendEngineer
# bb9ce163: `password=[REDACTED] passcode will be '<key>` left the key).
_LABEL_NEAR_BLOB = re.compile(
    rf"(?i){_NEAR_LABEL}(?:(?!\[REDACTED)[^\n]){{0,40}}?(?<![\w/+=-])([A-Za-z0-9+/=_-]{{16,}})(?![\w/+=-])"
)
# camelCase / snake_case identifiers are code, not credentials. Digits are
# allowed only as a short trailing segment (shard42, retry_count_2): a random
# alphanumeric key that happens to start lowercase reads as camelCase to the
# looser v5 rule (`[A-Z][a-z0-9]*` segments) about one time in three, which
# let a third of duplicated keys through the residue sweep.
_IDENTIFIER_LIKE = re.compile(r"^[a-z]+(?:[A-Z]{1,5}[a-z]+)+\d{0,3}$|^[a-z]+(?:_[a-z]+)+(?:_?\d{1,3})?$")
# Identifiers are made of words, so their letter distribution is skewed; a
# random key that happens to fit the camelCase shape is not. Shape AND entropy.
_IDENTIFIER_ENTROPY_MAX = 4.0
# Residue feed / sweep gate: below this a value is a human-chosen password whose
# fragments are ordinary words. (3.8 in v5 let ~1% of random 24-char keys through.)
_KEYLIKE_ENTROPY = 3.5


def _is_identifier(tok: str) -> bool:
    return bool(_IDENTIFIER_LIKE.match(tok)) and _entropy(tok) < _IDENTIFIER_ENTROPY_MAX
# Stripe publishable keys are designed to be embedded client-side. Vendor-
# anchored and full-token only: a generic prefix or a "=pk_…" suffix must never
# launder an unrelated value past a pass.
_PUBLISHABLE = re.compile(r"^pk_(?:live|test)_[A-Za-z0-9]{8,}$")
# NAME=pk_… as one blob token: the name must be an env-var style identifier
# (uppercase, short) — a mixed-case key glued to "=pk_live_…" is not laundered.
_PUBLISHABLE_ASSIGN = re.compile(r"^[A-Z][A-Z0-9_]{0,40}=pk_(?:live|test)_[A-Za-z0-9]{8,}$")
_FILENAME_LIKE = re.compile(r"\.[A-Za-z0-9]{1,5}$")
_PLAIN_WORDS = re.compile(r"[a-z_ .,;:'\-]+")

_STRONG_RE = re.compile(rf"(?i)^{_QUAL}(?:{_STRONG})$")
_MULTIWORD_RE = re.compile(rf"(?i)^{_QUAL}(?:password|passphrase|pass ?phrase|pass-?word|passwd|pwd)$")
_LEADING_DETERMINER = re.compile(r"(?i)^(?:the|a|an|my|your|our)\s+")
# A quoted value opens and closes with the SAME quote character; other quote
# characters inside it are part of the value.
_QUOTED = re.compile(r"([\"'`])(?P<v>(?:(?!\1)[^\n]){4,64})\1")
_ASSIGN_MARKER = re.compile(r"\[REDACTED(?::[a-z_]+)?\]")

# A value someone already blanked is a placeholder, not a secret (NM-N15 fix round, CodeRedTeam
# a2d8682b): `aws_secret_access_key = REDACTED`, `password: ***`, `token=<redacted>`. It is left as
# written: never masked, never vetted as a prose credential and never swept as residue. "REDACTED"
# sits inside every marker this module writes, so sweeping it lengthened every marker once per copy
# and a 4-line credentials template grew past twice its size. Only these shapes, in any case: the
# word REDACTED, bare or bracketed ([REDACTED], [REDACTED:kind], <redacted>, (redacted)), and runs of
# 3 or more '*', 'x' or U+2022. A value of several words is one only when every word is one.
# Typed markers accept only the kinds actually emitted by this engine. Header words
# fold ASCII case; kind names stay exactly lowercase, as emitted. No Unicode case folds.
_MARKER_KINDS = frozenset(k for k, _ in _PATTERNS if k not in {"uri_credential", "assignment"}) | {
    "hex_secret", "high_entropy", "residue",
}
_PLACEHOLDER = re.compile(
    r"(?ai:redacted|\[redacted\]|<redacted>|\(redacted\)|x{3,})|\*{3,}|\u2022{3,}|"
    r"(?ai:\[redacted:)(?:" + "|".join(sorted(_MARKER_KINDS)) + r")\]"
)


def _is_placeholder(value: str) -> bool:
    if value != value.strip():
        return False
    words = value.split()
    # The parser has already isolated each value: punctuation belongs to the password.
    return bool(words) and all(_PLACEHOLDER.fullmatch(w) for w in words)

# Words that legitimately follow "password is …" etc. without being the secret.
_STOPWORDS = frozenset({
    "wrong", "incorrect", "correct", "invalid", "valid", "expired", "expiring",
    "required", "optional", "missing", "empty", "null", "none", "unset", "nil",
    "disabled", "enabled", "locked", "unlocked", "blocked", "reset", "changed",
    "changing", "rotated", "rotating", "revoked", "compromised", "leaked",
    "exposed", "stolen", "secure", "insecure", "strong", "weak", "safe",
    "unsafe", "hidden", "stored", "saved", "hashed", "salted", "encrypted",
    "redacted", "masked", "managed", "case-sensitive", "different", "identical",
    "unchanged", "temporary", "permanent", "unknown", "forgotten",
    "confidential", "sensitive", "working", "broken", "fine", "okay", "ok",
    "still", "already", "probably", "definitely", "actually", "really", "very",
    "too", "also", "just", "not", "never", "always", "the", "same", "that",
    "this", "what", "available", "unavailable", "mandatory", "deprecated",
    "configured", "generated", "randomly", "automatically", "default",
    "public", "private", "active", "inactive", "production", "example",
    "placeholder", "dummy", "fake", "test", "sample", "sms", "email", "long",
    "short", "simple", "complex", "complicated", "random", "unique", "shared",
    "personal", "global", "local", "usually", "sometimes", "currently", "now",
    "here", "there", "below", "above", "attached", "included", "provided",
    "given", "needed", "used", "set", "sent", "shown", "listed", "defined",
    "documented", "described", "true", "false", "yes", "no", "undefined",
    "in", "on", "at", "a", "an", "my", "your", "our", "his", "her", "their",
    "its", "as", "of", "to", "for", "with", "by", "from", "and", "or", "but",
    "if", "when", "where", "how", "why", "something", "anything", "nothing",
    "whatever", "either", "neither", "both", "all", "only", "about", "like",
    "basically", "literally", "obviously", "apparently",
})
_FUNCTION_WORDS = frozenset({
    "the", "a", "an", "as", "of", "to", "for", "in", "on", "at", "and", "or",
    "not", "is", "was", "are", "with", "that", "this", "it", "by", "from",
    "my", "your", "his", "her", "its", "our", "their", "if", "so", "than",
    "then", "but", "be", "been", "being", "no", "yes",
})
# Values that read as type/spec/scheme descriptors rather than secrets.
_SPEC_VALUE = re.compile(
    r"(?i)^(?:\w+\(\d+(?:,\s*\d+)?\)"          # varchar(64), decimal(10,2)
    r"|\d+\s*-\s*\d+"                            # 0000-9999 ranges
    r"|bearer|basic|digest|hmac|oauth2?|jwt|saml|sso|totp|hotp|ldap"
    r"|<[^>]*>|\{\{.*\}\}|\$\{?\w+\}?"           # <jwt>, {{tpl}}, $VAR
    r"|[a-z]+-(?:only|based|specific|style|free|less)"
    r"|(?:str|string|int|integer|bool|boolean|uuid|text|varchar|char|bytes)\b"
    r")[.,;:!?]*$"
)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _looks_credential_shaped(value: str) -> bool:
    if any(ch.isdigit() for ch in value):
        return True
    if any(ch.isupper() for ch in value) and any(ch.islower() for ch in value):
        return True
    if any(not ch.isalnum() for ch in value):
        return True
    return len(value) >= 8


def _vet_value(value: str, strong: bool) -> bool:
    """Decide whether a prose-position value is a secret worth redacting."""
    v = value.strip().rstrip(".!?,;:")
    if len(v) < 4 or "REDACTED" in v or _is_placeholder(value):
        return False
    if v.lower() in _STOPWORDS or _SPEC_VALUE.match(v) or _PUBLISHABLE.match(v):
        return False
    if strong:
        return True
    return _looks_credential_shaped(v)


def _pick_value(rest: str, strong: bool, multiword: bool = False) -> tuple[int, int] | None:
    """Given the text after a label+link, return the (start, end) offsets in
    `rest` of the value to redact — offsets, never a reconstructed string, so
    the caller splices without re-locating.

    Quoted spans (matching quote pair) are taken whole. Unquoted: the first
    token, or — for password-type labels — the longest run of words with no
    function word in it (passphrases like 'correct horse battery staple'),
    stopping at clause punctuation.
    """
    lead = len(rest) - len(rest.lstrip())
    body = rest[lead:]
    if not body:
        return None
    if strong:
        d = _LEADING_DETERMINER.match(body)
        if d:
            lead += d.end()
            body = body[d.end():]
    m = _QUOTED.match(body)
    if m:
        return (lead + m.start(), lead + m.end()) if _vet_value(m.group("v"), strong) else None
    # clause punctuation only ends the value when followed by space/end, so
    # "Zx9!plum" and "p.a.s.s" stay whole while "Password123. Next" stops.
    clause = re.match(r"(?:[^\n.;!?,()\"'`]|[.;!?,](?=\S)){1,96}", body)
    if not clause:
        return None
    words = list(re.finditer(r"\S+", clause.group(0)))
    if not words:
        return None

    def _span(a: re.Match[str], b: re.Match[str]) -> tuple[int, int]:
        end = b.end()
        while end > a.start() and clause.group(0)[end - 1] in ".,;:!?":
            end -= 1
        return lead + a.start(), lead + end

    # multi-word values are passphrases: dictionary words under a password-type
    # label, at most 6 words. A credential-shaped first token (digits, symbols)
    # is the whole value; PINs/OTPs/codes are single tokens by nature, so
    # "PIN is 4471 tell facilities" must not swallow the sentence.
    if multiword and len(words) >= 2 and words[0].group(0).isalpha():
        run: list[re.Match[str]] = []
        for w in words[:6]:
            lw = w.group(0).lower().rstrip(".,;:!?")
            if lw in _FUNCTION_WORDS or _SPEC_VALUE.match(w.group(0)):
                break
            run.append(w)
        if len(run) >= 2 and not all(w.group(0).lower().rstrip(".,;:!?") in _STOPWORDS for w in run):
            return _span(run[0], run[-1])
    first = words[0]
    return _span(first, first) if _vet_value(first.group(0), strong) else None


def _apply_prose(pattern: re.Pattern[str], out: str, found: list[str],
                 residue: list[tuple[str, bool]]) -> str:
    """Scan for label+link matches and splice the value by offsets. The scan
    resumes right after each redaction (or after the link when no value was
    taken), so every credential on a line is visited. Each value taken is a
    confirmed credential: it feeds the residue sweep for EXACT duplicates
    (fragments only if key-like).

    Linear in the number of redactions: the text is searched left to right and
    joined once (rebuilding the whole text after every redaction was quadratic).
    A redaction changes only one thing the next search can see: the character
    before the resume point is "]" instead of the value's last character. That
    flips a word boundary only when both characters around the resume point are
    word characters (a value clipped mid-token); then the text is rebuilt first,
    exactly as before."""
    parts: list[str] = []
    last = 0
    pos = 0
    while True:
        if parts and pos == last < len(out) and _is_word(out[pos - 1]) and _is_word(out[pos]):
            head = "".join(parts)
            out = head + out[last:]
            parts, last, pos = [head], len(head), len(head)
        m = pattern.search(out, pos)
        if not m:
            parts.append(out[last:])
            return "".join(parts)
        label = m.group(1)
        strong = bool(_STRONG_RE.match(label))
        rest = m.group("rest")
        span = _pick_value(rest, strong, multiword=bool(_MULTIWORD_RE.match(label)))
        if span is None:
            pos = m.end()
            continue
        s, e = span
        found.append("prose_credential")
        residue.append((rest[s:e], _entropy(rest[s:e]) >= _KEYLIKE_ENTROPY))
        parts.append(out[last:m.end()] + rest[:s] + "[REDACTED]")
        last = pos = m.end() + e


def _is_word(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _prose_value_index(text: str) -> tuple[list[int], list[int]]:
    """Where the prose passes would take a value in `text`: (starts, ends) sorted by start,
    with ends[i] the largest end among the first i+1 spans. Used by N1 to leave a
    user:pw@host that is glued inside a labelled value (`pin=1234,bob:<pw>@db.host:5432`)
    for the prose pass, which masks the whole value as it did before N1 (CodeRedTeam
    98b13c3a B1). Every match is scanned (no resume after a value), so this can name a
    span the prose pass later skips; the N1 re-run after the prose pass covers that."""
    spans: list[tuple[int, int]] = []
    for pattern in (_PROSE, _IMPERATIVE):
        for m in pattern.finditer(text):
            label = m.group(1)
            span = _pick_value(m.group("rest"), bool(_STRONG_RE.match(label)),
                               multiword=bool(_MULTIWORD_RE.match(label)))
            if span is not None:
                spans.append((m.end() + span[0], m.end() + span[1]))
    spans.sort()
    starts: list[int] = []
    ends: list[int] = []
    for s, e in spans:
        starts.append(s)
        ends.append(max(e, ends[-1]) if ends else e)
    return starts, ends


def _inside_prose_value(index: tuple[list[int], list[int]], pos: int, end: int | None = None) -> bool:
    """True when a prose span starts before `pos` and covers the entire [pos, end) match."""
    starts, ends = index
    i = bisect.bisect_left(starts, pos) - 1
    return i >= 0 and ends[i] >= (pos + 1 if end is None else end)


class ScrubBudgetExceeded(Exception):
    """The residue sweep would pass the caller's cap (``scrub(max_values=, max_passes=)``).
    Raised before any partial result exists: the caller must not use the text at all."""


# A maximal run of ASCII digits: the only thing a short ASCII pure-digit value can match
# (_sweep_exact matches such a value only between non-[0-9] characters).
_DIGIT_RUN = re.compile(r"[0-9]+")
_RESIDUE_MARK = "[REDACTED:residue]"


def _residue_sweep(out: str, values: list[tuple[str, bool]], *, max_values: int | None = None,
                   max_passes: int | None = None, growth_floor: int | None = None) -> tuple[str, bool]:
    """Redact any >=12-char fragment of an already-redacted key-like value that
    still appears elsewhere in the text (split keys, partial echoes, backup
    copies). Anchored: one substring probe per 12-char window, extended
    greedily on a hit — linear in the value length, not quadratic.

    Cost is bounded by the text size plus one substring scan per HIT, never
    per candidate window: the window index is built once over the original
    text and never rebuilt. After a redaction the index is stale only in the
    direction of false positives (windows that no longer exist), and each such
    entry is verified once against the live text and then dropped. Rebuilding
    the index after every hit (v5) made the sweep superlinear in the number of
    hits — 800 duplicated keys cost ~2s; now ~50ms.

    Repeated values (CodeRedTeam 681ff3e3, F1): the output is exactly the output of
    sweeping every value in list order, but (a) short ASCII pure-digit values are swept
    together in ONE pass over the text's digit runs, run just before the next sweep of
    any other kind (and at the end), and (b) a value whose sweep found nothing is not
    swept again until the text has changed. Both are exact: a short ASCII pure-digit
    value matches only a whole run of ASCII digits, and its marker holds no ASCII digit,
    so these sweeps never change what another of them matches; and a sweep is a function
    of the text and the value alone (the window index only shrinks, which can only turn a
    find into a miss). So 455 copies of "pin=1234" cost one pass, not 455.

    ``max_values`` / ``max_passes`` (None = no cap; ingest passes none): more distinct
    values than ``max_values``, or more passes over the text than ``max_passes``, raises
    ScrubBudgetExceeded (the Gateway leaves that memory out). A pass is a digit regex sweep
    (hit or miss) or any other sweep that changes the text (an exact substring sweep, a
    fragment replacement). With ``max_passes`` set the output may also not grow past twice
    the sweep's input: a value inside the marker ("RED", "ACTED"; CodeRedTeam 832924b6,
    SecurityEngineer d05c720a) is found again in every marker written for it, so each of its
    sweeps hits and lengthens every marker. Counting hits bounds the number of such sweeps
    and the growth bound bounds their size. ``growth_floor`` (code points) lifts that bound to
    at least this size, so a short text whose few markers grow is not refused for growth that
    costs nothing (the brain's stored-text caps); None keeps twice the input. A text that
    raises none of these gets the same output as with no cap. A placeholder value
    (``_is_placeholder``) is never swept and never counted."""
    if max_values is not None:
        distinct = {v.strip() for v, _ in values if not _is_placeholder(v)}
        distinct.discard("")
        if len(distinct) > max_values:
            raise ScrubBudgetExceeded("values")
    hit = False
    win = 12
    windows: set[str] | None = None
    done: set[str] = set()
    epoch = 0                          # bumped whenever `out` changes
    clean: dict[str, int] = {}         # exact-swept value -> epoch at which its sweep found nothing
    walked: dict[str, int] = {}        # fragment-walked value -> epoch at which its walk found nothing
    pending: set[str] = set()          # short ASCII pure-digit values not yet swept
    passes = 0
    grow_cap = max(2 * len(out), growth_floor or 0)   # with max_passes: the output may not grow past this

    def _pass() -> None:
        nonlocal passes
        passes += 1
        if max_passes is not None and passes > max_passes:
            raise ScrubBudgetExceeded("passes")

    def _changed(counted: bool) -> None:
        # a sweep just changed `out`: count it unless it was counted already, and stop a text
        # that grows on its own markers (only when capped: ingest output is never cut short)
        if max_passes is None:
            return
        if not counted:
            _pass()
        if len(out) > grow_cap:
            raise ScrubBudgetExceeded("growth")

    def _flush() -> None:
        # every pending short ASCII pure-digit value, swept at once: a digit run equal to one
        # of them is replaced, as the per-value sweeps in list order would replace it
        nonlocal out, hit, epoch
        if not pending:
            return
        _pass()
        n = 0

        def repl(m: re.Match[str]) -> str:
            nonlocal n
            if m.group(0) in pending:
                n += 1
                return _RESIDUE_MARK
            return m.group(0)
        new = _DIGIT_RUN.sub(repl, out)
        if n:
            out, hit, epoch = new, True, epoch + 1
            _changed(counted=True)
        for d in pending:
            clean[d] = epoch           # no run equals it any more
        pending.clear()

    def _exact(v: str) -> None:
        nonlocal out, hit, epoch
        _flush()
        if clean.get(v) == epoch:
            return                     # found nothing in this very text before
        regex = v.isdigit() and len(v) < win
        if regex:
            _pass()                    # a regex pass, hit or miss
        new, h = _sweep_exact(out, v, windows)
        if h:
            out, hit, epoch = new, True, epoch + 1
            _changed(counted=regex)    # a substring sweep counts only when it changes the text
        else:
            clean[v] = epoch

    for v, fragments_ok in values:
        v = v.strip()
        if not v or len(v) > 256 or _is_placeholder(v):
            continue
        # An exact-only value already swept as a SUBSTRING left no copy behind, and a later
        # marker can rebuild one only if v holds a bracket or sits inside the marker, so
        # sweeping it again is a no-op. Pure-digit values never enter `done` (R125/R126,
        # b76n): they are matched only between non-digits, so another value's sweep can turn
        # the digit beside a copy into a marker and free that copy. Fragment-walked values
        # are re-walked as before.
        exact_only = not (fragments_ok and len(v) >= win and _entropy(v) >= _KEYLIKE_ENTROPY)
        if exact_only and v in done:
            continue
        if (exact_only and not v.isdigit() and "[" not in v and "]" not in v
                and v not in _RESIDUE_MARK):
            done.add(v)
        ent = _entropy(v)
        # DOCTRINE (lab rounds 6+7): nothing may exempt a value once any rule has
        # confirmed it is a credential. Every value here was confirmed by an earlier
        # pass, so an EXACT duplicate elsewhere is swept regardless of shape OR
        # entropy (v7's entropy>=3.0 guard on this path let "password"/"letmein1"
        # echoes through — the guard belongs to the unconfirmed-prose side only).
        # Entropy still decides whether FRAGMENTS are swept (key-like values only).
        if windows is None:
            windows = {out[k:k + win] for k in range(len(out) - win + 1)}
        # ORDER MATTERS FOR COST: the fragment walk runs first, because its first
        # window hit extends to the whole duplicate and replaces it in ONE scan;
        # the exact-duplicate check below is then the safety net for values the
        # fragment walk does not cover (short / non-key-like). Doing the exact
        # check first left 13 stale windows per value for the walk to re-verify
        # (800 keys 2.0s, 3000 keys 30s).
        if not (fragments_ok and len(v) >= win and ent >= _KEYLIKE_ENTROPY):
            if v.isascii() and v.isdigit() and len(v) < win:
                if clean.get(v) != epoch:
                    pending.add(v)     # swept with the others in one pass (_flush)
                continue
            _exact(v)
            continue
        _flush()
        if walked.get(v) == epoch:
            continue                   # walk and safety net found nothing in this very text
        before = epoch
        i = 0
        while i + win <= len(v):
            frag = v[i:i + win]
            # a window that is plain lowercase words/punctuation is prose, not
            # key material. (v5 required a digit instead, which let every
            # all-letter random key — ~1.5% of 24-char alnum keys — through.)
            if "REDACTED" in frag or _PLAIN_WORDS.fullmatch(frag):
                i += 1
                continue
            if frag not in windows:
                i += 1
                continue
            p = out.find(frag)
            if p < 0:
                windows.discard(frag)  # stale entry: verified absent, drop it
                i += 1
                continue
            # extend at the located occurrence: character compare, no rescans
            j = i + win
            while j < len(v) and p + (j - i) < len(out) and out[p + (j - i)] == v[j]:
                j += 1
            frag = v[i:j]
            # no identifier exemption here: the fragment is a slice of a confirmed credential
            out = out.replace(frag, _RESIDUE_MARK)
            hit, epoch = True, epoch + 1
            _changed(counted=False)
            i = j
        # safety net: an exact duplicate the walk could not see (every window of it
        # plain lowercase words, e.g. a diceware key with digits only at the end)
        _exact(v)
        if epoch == before:
            walked[v] = epoch
    _flush()
    return out, hit


def _sweep_exact(out: str, v: str, windows: set[str]) -> tuple[str, bool]:
    """Sweep every exact duplicate of a CONFIRMED credential value. ZERO
    exemptions on confirmed values (lab rounds 7+8): the entropy gate (v7) and
    the stopword exemption (v8) were each the fail-open class in a new costume —
    attacker-controlled dictionary membership must never override confirmed-secret
    provenance (`DB_PASSWORD=production backup copy: production` leaked its echo
    under v8). Prose destruction is real but subordinate: once a value is confirmed
    secret, confidentiality wins. Short values (< 12 chars) are matched as whole
    tokens so "4471" never eats "14471"; longer values as substrings."""
    if not v:
        return out, False
    win = 12
    # NO LENGTH CLIFF (lab round 9): v9 matched values shorter than 12 chars only as whole
    # tokens, so an 11-char credential embedded in an identifier/URI/label
    # (`log=XabcdefghijkY`) survived while a 12-char one was swept — an attacker-
    # selectable confidentiality cliff. Now: any confirmed value that is not a pure
    # digit string is swept as a SUBSTRING at every length; only pure-digit values
    # shorter than 12 (PINs, ports) keep whole-token matching so "4471" never eats
    # "14471". There is no lower length floor.
    if v.isdigit() and len(v) < win:
        pat = re.compile(r"(?<![0-9])" + re.escape(v) + r"(?![0-9])")
        new, n = pat.subn("[REDACTED:residue]", out)
        return (new, True) if n else (out, False)
    if len(v) >= win and v[:win] not in windows:
        return out, False
    if v not in out:
        return out, False
    return out.replace(v, "[REDACTED:residue]"), True


def scrub(text: str, *, max_values: int | None = None, max_passes: int | None = None,
          growth_floor: int | None = None) -> tuple[str, list[str]]:
    """Return (scrubbed_text, kinds_redacted).

    The text is NFC-normalized first (lab round 9): a credential stated in one
    Unicode composition and echoed in another (`pässwörd` NFC vs NFD) is the same
    secret and must match; every pass and the residue sweep then operate on one
    canonical form. The returned text is therefore NFC — a normalization, never a
    content change."""
    if not text:
        return text, []
    text = unicodedata.normalize("NFC", text)
    found: list[str] = []
    # every confirmed credential feeds the residue sweep as (value, fragments_ok):
    # exact duplicates are always swept; >=12-char FRAGMENTS only for key-like
    # values (a human password's fragments are ordinary words)
    residue_values: list[tuple[str, bool]] = []
    out = text

    def _assignment_repl(m: re.Match[str]) -> str:
        quoted = m.group(2) is not None
        value = m.group(3) if quoted else m.group(5)
        tail = "" if quoted else m.group(6)
        # what follows the masked value: the unused rest of the clause, then a quote, which
        # is dropped only when it directly closes the value (as before the whole-value rule)
        rest = tail + m.group(7) if tail else ""
        # An unquoted plain-word first token followed by more words is a passphrase
        # (`password: purple strawberry mountain`): the run of words up to the first
        # function word or the end of the clause is the value, as in the prose
        # passphrase rule (_pick_value), when it has >= 2 words, not all stopwords.
        if tail and not m.group(4) and value.isalpha():
            run = [w for w in re.finditer(r"\S+", tail)]
            end = 0
            words = [value]
            for w in run:
                lw = w.group(0).lower().rstrip(".,;:!?")
                if lw in _FUNCTION_WORDS or _SPEC_VALUE.match(w.group(0)):
                    break
                words.append(w.group(0))
                end = w.end()
            if (value.lower() not in _FUNCTION_WORDS and len(words) >= 2
                    and not all(w.lower().rstrip(".,;:!?") in _STOPWORDS for w in words)):
                while end > 0 and tail[end - 1] in ".,;:!?":
                    end -= 1
                value, rest = value + tail[:end], (tail[end:] + m.group(7) if tail[end:] else "")
        # Recalled content can pass through the ingress scrubber again.
        # Keep only our complete redaction markers stable on that pass.
        if _ASSIGN_MARKER.fullmatch(value) or _is_placeholder(value):
            return m.group(0)
        # schema/type/scheme descriptors and publishable keys are not secrets;
        # a short value that is a plain stop/common word is prose, not a credential
        if _SPEC_VALUE.match(value) or _PUBLISHABLE.match(value):
            return m.group(0)
        if quoted and len(value.split()) > 1:
            # a quoted multiword value made only of stop/function words is prose
            # (`password: "not set"`); anything else in quotes is the secret, whole
            if all(w.lower().strip(".,;:!?") in _STOPWORDS or w.lower().strip(".,;:!?") in _FUNCTION_WORDS
                   for w in value.split()):
                return m.group(0)
        elif len(value.split()) == 1 and len(value) < 6 and value.lower().rstrip(".,;:!?") in _STOPWORDS:
            return m.group(0)
        found.append("assignment")
        # fragments only for key-like values: a human-chosen password or a filename is not
        # a key. Exact duplicates are swept either way. A multiword value is swept whole,
        # and its first token (what this pass took before the whole-value rule) and every
        # non-word token in it (digits, symbols) are swept as values of their own, so an
        # echo of a key that sits inside a longer value is still caught. Plain dictionary
        # words of a passphrase are not: elsewhere they are ordinary prose.
        parts = value.split()
        if len(parts) > 1:  # whole value first: a component sweep would break its echo
            residue_values.append((value, False))
        for i, tok in enumerate(parts):
            if len(parts) == 1 or i == 0 or (len(tok.rstrip(".,;:!?")) >= 3 and not tok.rstrip(".,;:!?").isalpha()):
                tok = tok if len(parts) == 1 or i == 0 else tok.rstrip(".,;:!?")
                residue_values.append((tok, _entropy(tok) >= _KEYLIKE_ENTROPY
                                       and not _FILENAME_LIKE.search(tok.rstrip("!?.,;:"))))
        return f"{m.group(1)}=[REDACTED]{rest}"

    # N1 matches left for the prose pass (glued inside a labelled value): their passwords.
    # A text with none takes exactly the path it took before this rule existed.
    n1_deferred: set[str] = set()
    for kind, pat in _PATTERNS:
        if pat is _URI_NO_SCHEME and ("@" not in out or ":" not in out):
            continue
        prose_index: list[tuple[list[int], list[int]]] = []  # built on N1's first glued match
        if kind == "private_key":
            # Every match ends at an END line, so nothing after the last one can match; a
            # BEGIN with no END after it would otherwise rescan to the end of the text
            # (quadratic on many BEGIN lines). Exact: the same matches, found in linear time.
            last = None
            for last in _PEM_END.finditer(out):
                pass
            if last is None:
                continue
            head, tail_text = out[: last.end()], out[last.end():]
        else:
            head, tail_text = out, ""
        def _repl(m: re.Match[str], _kind: str = kind, _n1: bool = pat is _URI_NO_SCHEME) -> str:
            if _kind == "uri_credential":
                if (_n1 and not m.group(3)
                        and _N1_PLAIN_PASSWORD.fullmatch(m.group(2))):
                    return m.group(0)
                if _is_placeholder(m.group(2)):
                    return m.group(0)          # `user:***@host`: already blanked
                found.append(_kind)
                residue_values.append((m.group(2), True))
                # Glued to text before it (no space) inside the value a prose label takes
                # (`pin=1234,bob:<pw>@db.host:5432`): masking only the password here made the
                # prose pass skip the value (it holds a marker) and the PIN stayed visible.
                # Left whole, the prose pass masks the value; the N1 re-run after it masks
                # whatever the prose pass did not take. The password still feeds the sweep.
                s = m.start()
                if _n1 and s and not m.string[s - 1].isspace():
                    if not prose_index:
                        prose_index.append(_prose_value_index(m.string))
                    if _inside_prose_value(prose_index[0], s, m.end()):
                        n1_deferred.add(m.group(2))
                        return m.group(0)
                return f"{m.group(1)}[REDACTED]@"
            if _kind == "assignment":
                return _assignment_repl(m)
            if _kind == "jwt":
                pre = m.group("pre")
                found.append(_kind)
                residue_values.append((m.group(0)[len(pre):], True))
                return f"{pre}[REDACTED:jwt]"
            found.append(_kind)
            residue_values.append((m.group(0), True))
            return f"[REDACTED:{_kind}]"
        out = pat.sub(_repl, head) + tail_text

    def _hex_repl(m: re.Match[str]) -> str:
        tok = m.group(1)
        if _DIGEST_PREFIX.search(m.string[max(0, m.start() - 12):m.start()]):
            return m.group(0)
        found.append("hex_secret")
        residue_values.append((tok, True))
        return "[REDACTED:hex_secret]"
    out = _HEX.sub(_hex_repl, out)

    out = _apply_prose(_PROSE, out, found, residue_values)
    out = _apply_prose(_IMPERATIVE, out, found, residue_values)

    if n1_deferred:
        # Re-run N1 so a deferred user:pw@host the prose pass did not take is still masked.
        # Its password was already counted and fed to the sweep when it was deferred.
        def _n1_late_repl(m: re.Match[str]) -> str:
            if _is_placeholder(m.group(2)):
                return m.group(0)
            if not m.group(3) and _N1_PLAIN_PASSWORD.fullmatch(m.group(2)):
                return m.group(0)
            if m.group(2) not in n1_deferred:
                found.append("uri_credential")
                residue_values.append((m.group(2), True))
            return f"{m.group(1)}[REDACTED]@"
        out = _URI_NO_SCHEME.sub(_n1_late_repl, out)

    def _value_first_repl(m: re.Match[str]) -> str:
        value = m.group("q") or m.group("u")
        which = "q" if m.group("q") else "u"
        label_text = m.group(0)[m.end(which) - m.start() + (1 if which == "q" else 0):]
        strong = bool(re.search(rf"(?i)\b(?:{_STRONG})\b", label_text))
        if not _vet_value(value, strong):
            return m.group(0)
        found.append("prose_credential")
        residue_values.append((value, _entropy(value) >= _KEYLIKE_ENTROPY))
        return f"[REDACTED]{label_text}"
    out = _VALUE_FIRST.sub(_value_first_repl, out)

    def _near_blob_repl(m: re.Match[str]) -> str:
        blob = m.group(2)
        if "REDACTED" in m.group(0) or _SPEC_VALUE.match(blob):
            return m.group(0)
        if blob.lower() in _STOPWORDS or blob.isalpha() and blob.islower():
            return m.group(0)
        if _is_identifier(blob) or _PUBLISHABLE.match(blob):
            return m.group(0)
        found.append("label_adjacent_blob")
        residue_values.append((blob, True))
        return m.group(0)[: m.start(2) - m.start()] + "[REDACTED]" + m.group(0)[m.end(2) - m.start():]
    out = _LABEL_NEAR_BLOB.sub(_near_blob_repl, out)

    def _blob_repl(m: re.Match[str]) -> str:
        tok = m.group(0)
        if "REDACTED" in tok or _PUBLISHABLE.match(tok) or _PUBLISHABLE_ASSIGN.match(tok):
            return tok
        if _entropy(tok) >= _ENTROPY_THRESHOLD:
            found.append("high_entropy")
            residue_values.append((tok, True))
            return "[REDACTED:high_entropy]"
        return tok
    out = _BLOB.sub(_blob_repl, out)

    out, residue = _residue_sweep(out, residue_values, max_values=max_values,
                                  max_passes=max_passes, growth_floor=growth_floor)
    if residue:
        found.append("residue")

    return out, found
