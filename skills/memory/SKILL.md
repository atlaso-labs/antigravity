---
name: memory
description: >-
  Atlaso long-term memory for Antigravity. Use to RECALL relevant past context
  before answering, and to REMEMBER durable facts, decisions, preferences, and
  gotchas worth keeping across sessions. Unlike some tools, Antigravity does NOT
  auto-inject memories — you must call recall yourself when prior context would help.
when_to_use: >-
  starting a task where past decisions/preferences likely matter; the user
  references something decided earlier; you're about to make a choice that could
  contradict an earlier one; something durable was just decided and should persist;
  the user asks to forget or correct a memory.
---

# Using Atlaso memory in Antigravity

Atlaso is the user's long-term memory, shared across every tool and project. On
Antigravity, memory is **model-driven**: there is no automatic per-turn injection,
so reach for the `Atlaso` MCP tools deliberately.

The `Atlaso` MCP server exposes: `recall`, `remember`, `forget`, `recent`, `status`.

## Recall before you answer (the one habit that matters)

Because nothing is auto-injected here, **call `recall` at the start of a task** when
prior context would plausibly help:
- the user references a past decision ("what did we decide about X?"),
- you're starting unfamiliar work in this project,
- you're about to make a choice that could contradict an earlier one.

Don't over-search: one good `recall` beats five speculative ones. Skip it for
trivial, self-contained turns.

## What's worth remembering (default: don't)

Save **durable** things via `remember`:
- decisions **and the reason** behind them,
- the user's stable preferences and working style,
- hard-won gotchas ("X silently fails unless Y"),
- stable facts/commands (ports, endpoints, conventions).

Don't save: transient state ("ran the tests just now"), secrets/tokens, restatements
of files already in the repo, or anything that's only relevant this turn.

## Personal vs project — Atlaso's dual memory

Atlaso keeps two memories and routes by content. Rule of thumb: *would this still be
true in a different project?*
- **Yes → personal** (cross-project preferences, identity, working style).
- **No → project** (architecture, repo-specific decisions and gotchas).

## Fixing memory

A memory is wrong or outdated → `recall` to find its id, then `forget` it (or
`remember` the correction). Supersede rather than piling up contradictions. Only
`forget` when the user asks.

## Good vs skip

- ✅ "Use pnpm, never npm — the user's standard across all projects." *(personal)*
- ✅ "Brain server runs on port 8800; recall is `GET /v1/recall`." *(project)*
- ✅ "Tauri signing key must be single-line in CI or it errors." *(hard-won gotcha)*
- ⏭️ "Compiled the app and the tests passed." *(ephemeral — skip)*
