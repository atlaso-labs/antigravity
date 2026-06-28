"""Reader for Antigravity's session transcript (``transcript_full.jsonl``).

Format VERIFIED live (agy v1.0.x): JSON Lines, one record per line carrying
``source`` / ``type`` / ``content``. A user turn is ``source:"USER_EXPLICIT"``
(``type:"USER_INPUT"``) whose ``content`` wraps the real prompt in
``<USER_REQUEST>…</USER_REQUEST>`` (alongside ``<ADDITIONAL_METADATA>`` /
``<USER_SETTINGS_CHANGE>`` sections we drop). A model turn is ``source:"MODEL"``
(``type:"PLANNER_RESPONSE"``). SYSTEM records (CONVERSATION_HISTORY, CHECKPOINT)
are skipped — they are never a conversational turn.

A generic role/content heuristic is kept as a per-record fallback in case the
format shifts, but the AG schema is the primary path. Never raises — callers fail
open (empty → no recall/capture; the MCP tools + skill still work).
"""
from __future__ import annotations

import json
import re

# ── Antigravity schema ────────────────────────────────────────────────────────
_AG_USER_SRC = {"user_explicit", "user"}
_AG_USER_TYPE = {"user_input"}
_AG_ASST_SRC = {"model", "assistant"}
_AG_ASST_TYPE = {"planner_response", "model_response", "assistant_response"}
_AG_SYS_SRC = {"system"}

# The real prompt is wrapped; pull just the request, else strip metadata sections.
_USER_REQUEST_RE = re.compile(r"<USER_REQUEST>\s*(.*?)\s*</USER_REQUEST>", re.DOTALL | re.IGNORECASE)
_META_RE = re.compile(r"<(ADDITIONAL_METADATA|USER_SETTINGS_CHANGE|SYSTEM_[A-Z_]*)>.*?</\1>", re.DOTALL | re.IGNORECASE)

# ── generic fallback (unknown formats) ────────────────────────────────────────
_ROLE_KEYS = ("role", "sender", "author", "speaker")
_TEXT_KEYS = ("content", "text", "message", "value", "body", "parts")
_LIST_KEYS = ("messages", "transcript", "events", "turns", "history", "items", "steps")
_USER_ALIASES = {"user", "human", "you", "prompt", "input"}
_ASST_ALIASES = {"assistant", "model", "ai", "agent", "bot", "gemini", "response", "output"}


def _flatten(content: object) -> str:
    """Coerce a ``content`` field (string / list of blocks / dict) into plain prose,
    skipping obvious non-text blocks (tool calls, thinking)."""
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, dict):
        btype = str(content.get("type", "")).lower()
        if btype in ("tool_use", "tool_result", "thinking", "tool_call"):
            return ""
        for k in ("text", "content", "value", "parts", "message"):
            if k in content:
                return _flatten(content[k])
        return ""
    if isinstance(content, list):
        return " ".join(t for t in (_flatten(el) for el in content) if t).strip()
    return ""


def _unwrap_user(text: str) -> str:
    """Extract the real prompt from an AG USER_INPUT content blob."""
    if not text:
        return ""
    m = _USER_REQUEST_RE.search(text)
    if m:
        return m.group(1).strip()
    return _META_RE.sub("", text).strip()  # no wrapper → drop metadata sections


def _ag_pair(obj: dict) -> tuple[str, str] | None:
    """(role, text) from an Antigravity record, or None if it isn't one / isn't a turn."""
    src = str(obj.get("source", "")).strip().lower()
    typ = str(obj.get("type", "")).strip().lower()
    if not src and not typ:
        return None
    text = _flatten(obj.get("content"))
    if src in _AG_USER_SRC or typ in _AG_USER_TYPE:
        u = _unwrap_user(text)
        return ("user", u) if u else None
    if src in _AG_ASST_SRC or typ in _AG_ASST_TYPE:
        return ("assistant", text) if text else None
    if src in _AG_SYS_SRC:
        return None  # system / checkpoint / history — never a turn
    return None  # unknown source/type → let the generic fallback try


def _generic_pair(obj: dict) -> tuple[str, str] | None:
    role = ""
    for k in _ROLE_KEYS:
        v = obj.get(k)
        if isinstance(v, str) and v:
            r = v.strip().lower().replace("-", "").replace(" ", "").replace("_", "")
            if r in _USER_ALIASES:
                role = "user"
                break
            if r in _ASST_ALIASES:
                role = "assistant"
                break
    text = ""
    for k in _TEXT_KEYS:
        if k in obj:
            text = _flatten(obj[k])
            if text:
                break
    inner = obj.get("message")
    if not text and isinstance(inner, dict):
        text = _flatten(inner.get("content") if "content" in inner else inner)
    return (role, text) if role and text else None


def _pair(obj: object) -> tuple[str, str] | None:
    if not isinstance(obj, dict):
        return None
    return _ag_pair(obj) or _generic_pair(obj)


def _items(obj: object) -> list:
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for k in _LIST_KEYS:
            v = obj.get(k)
            if isinstance(v, list):
                return v
        return [obj]
    return []


def read_messages(path: str) -> list[tuple[str, str]]:
    """Ordered list of (role, text) from the transcript file, or []. Never raises."""
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except (FileNotFoundError, OSError):
        return []
    if not raw.strip():
        return []
    # JSON Lines (the Antigravity shape): one record per line.
    msgs: list[tuple[str, str]] = []
    jsonl_ok = True
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            jsonl_ok = False
            break
        p = _pair(obj)
        if p:
            msgs.append(p)
    if jsonl_ok:
        return msgs
    # Fallback: a single JSON document (list, or a wrapper object).
    try:
        doc = json.loads(raw)
    except Exception:
        return []
    return [p for p in (_pair(el) for el in _items(doc)) if p]


def last_prompt(path: str) -> str:
    """The most recent USER message text, or '' — what recall queries on (no event
    field carries the raw prompt; it lives in the transcript)."""
    for role, text in reversed(read_messages(path)):
        if role == "user" and text:
            return text
    return ""


def last_exchange(path: str) -> tuple[str, str]:
    """(last_user_text, assistant_reply_to_it); either may be ''. The assistant text
    is only counted AFTER the last user message, so a Stop hook that fires before the
    reply is flushed pairs the new question with '' rather than a stale answer."""
    msgs = read_messages(path)
    last_user_idx = None
    for i, (role, _) in enumerate(msgs):
        if role == "user":
            last_user_idx = i
    if last_user_idx is None:
        return "", ""
    last_user = msgs[last_user_idx][1]
    asst = ""
    for role, text in msgs[last_user_idx + 1:]:
        if role == "assistant":
            asst = text
    return last_user, asst
