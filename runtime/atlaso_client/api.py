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
    """The brain was REACHED and rejected the token (HTTP 401/403) — the device
    was disconnected, or the token expired/revoked. Distinct from a transport
    error (offline / timeout / 5xx), which is transient. The core treats this as
    the authoritative signal to switch to LOCAL-ONLY until the user reconnects."""


def _raise(r: httpx.Response) -> None:
    """Turn a 401/403 into AuthRejected (a reachable server said 'no'); let every
    other non-2xx raise the usual httpx.HTTPStatusError (treated as transient)."""
    if r.status_code in (401, 403):
        raise AuthRejected(f"token rejected ({r.status_code})")
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

    def deposit_batch(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        r = self._client.post("/v1/memories/batch", json={"items": items}, timeout=_SYNC_TIMEOUT)
        _raise(r)
        return r.json()

    def sync(self, since: int, tomb_since: int = 0, limit: int = 500) -> dict[str, Any]:
        r = self._client.get(
            "/v1/memories/sync",
            params={"since": since, "tomb_since": tomb_since, "limit": limit},
            timeout=_SYNC_TIMEOUT,
        )
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
