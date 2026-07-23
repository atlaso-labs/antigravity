"""Thin HTTP client for the brain's memory API.

One persistent ``httpx.Client`` so a per-turn recall reuses a warm keep-alive
connection (no fresh TLS handshake each call — the single biggest latency lever
per our research). Knows ONLY how to call the documented endpoints; all the smart
logic lives server-side.
"""
from __future__ import annotations

from typing import Any

import httpx


class AuthRejected(Exception):
    """OUR app verifiably rejected the credential (401/403 carrying the Atlaso
    response marker + a state-transition error code). The core switches this
    identity to LOCAL-ONLY (with a TTL, so a wrong verdict self-heals).
    `code` is the server's machine-readable reason: "invalid_token" or
    "reconnect_required"."""

    def __init__(self, message: str, *, code: str = "invalid_token"):
        super().__init__(message)
        self.code = code


class NotEntitled(Exception):
    """OUR app said this tool isn't entitled on the current (free) plan — a plan
    POLICY verdict, not an auth failure. The core parks the tool as not_entitled
    (soft; re-checked on a short TTL). Never treated like a revoked credential."""


class EdgeBlocked(Exception):
    """A 401/403 that is NOT verifiably from our app — most commonly Cloudflare's
    WAF blocking a request whose body pattern-matched an attack (code/markup in a
    legit memory). TRANSIENT by definition: the item stays queued and sticky auth
    state is NEVER touched. Carries edge evidence for telemetry."""

    def __init__(self, message: str, *, status: int = 0,
                 cf_ray: str | None = None, content_type: str | None = None):
        super().__init__(message)
        self.status = status
        self.cf_ray = cf_ray
        self.content_type = content_type


# State-transition codes the client acts on. Anything else on a verified 401/403
# (an unknown future code) fails SAFE: treated as transient, item stays queued.
_AUTH_CODES = ("invalid_token", "reconnect_required")


def _raise(r: httpx.Response) -> None:
    """Classify a non-2xx. 401/403 are only an AUTH verdict when the response is
    POSITIVELY ours (X-Atlaso-Response marker) AND carries a known state-transition
    code — a Cloudflare/edge block page must never masquerade as 'token revoked'
    (the bug that silently killed all sync). Header stripped by a proxy → false
    negative → item stays queued: the correct fail-safe. Every other non-2xx raises
    httpx.HTTPStatusError (transient)."""
    if r.status_code in (401, 403):
        if r.headers.get("x-atlaso-response") == "1":
            code = r.headers.get("x-atlaso-error", "")
            if code == "not_entitled":
                raise NotEntitled(f"tool not entitled ({r.status_code})")
            if code in _AUTH_CODES:
                raise AuthRejected(f"token rejected ({r.status_code}, {code})", code=code)
        raise EdgeBlocked(
            f"unverified {r.status_code} (edge/WAF?)",
            status=r.status_code,
            cf_ray=r.headers.get("cf-ray"),
            content_type=r.headers.get("content-type"),
        )
    r.raise_for_status()


# Hot-path calls (recall/ambient) stay on the short default so a turn never hangs
# on the network. The background SYNC (push the outbox + pull) can legitimately
# take longer for a multi-item batch, so it gets its own generous timeout — a too-
# tight sync timeout makes the client give up while the server is still committing
# (data lands, but the client re-sends next tick; idempotency keys keep it safe).
_SYNC_TIMEOUT = 30.0


class BrainAPI:
    def __init__(self, server: str, token: str, *, timeout: float = 8.0):
        self._client = httpx.Client(
            base_url=server.rstrip("/"),
            timeout=timeout,
            headers={"Authorization": f"Bearer {token}"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "BrainAPI":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def recall(self, query: str, limit: int = 5, project: str | None = None,
               session: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"q": query, "limit": limit}
        if project:
            params["project"] = project  # per-project scope filter
        if session:
            params["session"] = session  # for server-side recall-usefulness logging
        r = self._client.get("/v1/recall", params=params)
        _raise(r)
        return r.json()

    def deposit_batch(self, items: list[dict[str, Any]],
                      capture_stats: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Push a batch of outbox items. `capture_stats` (optional) rides along as a
        content-free top-level field: the last ≤35 days of cumulative capture
        counters ([{day, attempts, accepted, drops}]). Additive + backward-compatible
        — a server that ignores the field must not break the client, and it is only
        included in the body when present so the wire shape is unchanged without it.
        The server max-merges the counters, so re-sending is idempotent."""
        body: dict[str, Any] = {"items": items}
        if capture_stats is not None:
            body["capture_stats"] = capture_stats
        r = self._client.post("/v1/memories/batch", json=body, timeout=_SYNC_TIMEOUT)
        _raise(r)
        return r.json()

    def sync(self, since: int, tomb_since: int = 0, limit: int = 500,
             changes_cursor: int | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"since": since, "tomb_since": tomb_since, "limit": limit}
        if changes_cursor is not None:
            # Opt-in change stream: the server re-sends the full current state of
            # memories UPDATED in place (polarity/tags/evidence) since this cursor.
            params["changes_cursor"] = changes_cursor
        r = self._client.get("/v1/memories/sync", params=params, timeout=_SYNC_TIMEOUT)
        _raise(r)
        return r.json()

    def recent(self, limit: int = 20) -> dict[str, Any]:
        r = self._client.get("/v1/memories", params={"limit": limit})
        _raise(r)
        return r.json()

    def health(self) -> dict[str, Any]:
        r = self._client.get("/v1/health")
        _raise(r)
        return r.json()

    def delete(self, deposit_id: str) -> dict[str, Any]:
        r = self._client.delete(f"/v1/memories/{deposit_id}")
        _raise(r)
        return r.json()

    def ambient(self) -> dict[str, Any]:
        """Fetch the Ambient Memory orientation block (the single source every tool
        injects). Paid-only server-side: a 402 means not-paid → {block: None}
        rather than an error the caller must handle."""
        r = self._client.get("/v1/ambient")
        if r.status_code == 402:
            return {"block": None}
        _raise(r)
        return r.json()

    # ── plan / tool entitlement ────────────────────────────────────────────────
    def entitlement(self) -> dict[str, Any]:
        """This device's tool policy: {device_id, active_tool, multi_tool,
        needs_reconnect}. Device-authed (the bearer token identifies the device)."""
        r = self._client.post("/v1/entitlement")
        _raise(r)
        return r.json()

    def claim_tool(self, tool: str) -> dict[str, Any]:
        """First-use claim: register this tool on the device and, if no tool is
        active yet, claim the (free) active slot for it. Returns {active_tool,
        multi_tool}. A no-op once some tool is already active."""
        r = self._client.post("/v1/devices/claim-tool", json={"tool": tool})
        _raise(r)
        return r.json()
