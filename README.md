# Atlaso × Google Antigravity

The [Atlaso](https://atlaso.ai) memory connector for **Google Antigravity** — the
IDE, the CLI (`agy`), and Antigravity 2.0 — shipped as a **native Antigravity
plugin**: one self-contained `plugin.json` bundle that groups the MCP server, the
auto recall/capture hooks, the memory skill, and the rules in a single package.

Like every Atlaso connector, the memory logic is deliberately thin: the plugin
registers the shared MCP server (`platform/mcp/atlaso_mcp`) backed by the
tool-agnostic client (`platform/client/atlaso_client`). No memory engine lives
here — it stays on the server. The plugin only adds the Antigravity-native
packaging + lifecycle hooks.

## A native plugin, not loose files

Antigravity has a real third-party plugin format: a namespaced bundle marked by a
`plugin.json` at its root, grouping **skills, rules, MCP servers, and hooks** in
ONE package. On **agy 1.0.14** a plugin must be **registered** — `agy plugin install
<dir>` copies the bundle into `~/.gemini/config/plugins/atlaso/` and records it in
`~/.gemini/config/import_manifest.json` (a raw file-drop into the plugins dir is
**not** auto-loaded, and there is no git-URL / `owner/repo` install form — both are
read as directory paths and fail). There is no public plugin marketplace to submit
to. One install covers the IDE and the `agy` CLI (they share `~/.gemini`).

`install.py` builds the self-contained bundle and registers it via `agy plugin
install`; the `atlaso` CLI does the same headlessly (materialises the embedded
bundle to a temp dir, then `agy plugin install <dir>`). Installed at:

| Scope | Plugin directory |
|---|---|
| **Global** | `~/.gemini/config/plugins/atlaso/` |
| **Project** | `<workspace>/.agents/plugins/atlaso/` |

### What's in the bundle

```
~/.gemini/config/plugins/atlaso/
  plugin.json                REQUIRED marker  {"name":"atlaso", ...}
  mcp_config.json            the Atlaso MCP server (recall/remember/forget/recent/status)
  hooks.json                 PreInvocation → recall.sh, Stop → capture.sh
  skills/memory/SKILL.md     model-driven memory skill (when to recall/deposit)
  rules/atlaso.md            standing recall-before-answering / remember-durable rule
  bin/atlaso-memory-mcp      MCP launcher (self-contained via uv)
  hooks/                     recall.sh + capture.sh + _resolve.sh (lifecycle launchers)
  runtime/                   vendored atlaso_client + atlaso_mcp + atlaso_ag + dep env
```

Everything (MCP, hooks, skill, rules) now lives **inside the plugin** — we no
longer merge into your shared `~/.gemini/config/{mcp_config.json,hooks.json}` or
your `AGENTS.md`.

Antigravity exposes **no plugin-root variable** for hook/MCP `command` paths, so
those must be absolute. The bundled `mcp_config.json` + `hooks.json` ship with a
`__ATLASO_PLUGIN_DIR__` placeholder, and `install.py` substitutes the real absolute
install path at copy time so the launchers always resolve.

## Install

```bash
python install.py
```

This builds (if needed) and copies the plugin bundle into
`~/.gemini/config/plugins/atlaso/`, then rewrites the absolute launcher paths into
the installed `mcp_config.json` + `hooks.json`. It's idempotent — re-running
replaces the whole plugin directory atomically. Then **restart Antigravity / `agy`**
so it re-scans plugins.

```bash
python install.py --dry-run    # preview, write nothing
python install.py --uninstall  # remove ~/.gemini/config/plugins/atlaso/
```

**Requirements:** `uv` (runs the self-contained vendored runtime). The `agy` CLI
installs via `curl -fsSL https://antigravity.google/cli/install.sh | bash`.

## How memory works here — honestly

There are **two layers**, and we're explicit about how solid each one is:

**1. MCP + skill/rules — the guaranteed path (model-driven).**
The agent calls `recall`/`remember`/`forget` through the plugin's MCP server; the
skill + rules tell it when. This path rests on confirmed, primary-source surfaces
(the `mcpServers` schema is the stable cross-tool MCP standard; the skill + rules
are plain plugin content Antigravity loads). It works regardless of anything below.

**2. Hooks — auto-recall + auto-capture (corroborated, NOT smoke-tested).**
The plugin's `hooks.json` registers:

- **Auto-recall** (`PreInvocation`, fires before the model call): `hooks/recall.sh`
  → `atlaso_ag/recall.py` recovers the user's latest prompt from the hook's
  `transcriptPath`, calls `client.recall`, and prints
  `{"injectSteps":[{"ephemeralMessage": "=== Atlaso Memory === …"}]}` to STDOUT so
  Antigravity injects the recalled block as ephemeral context.
- **Auto-capture** (`Stop`, fires when the loop terminates): `hooks/capture.sh` →
  `atlaso_ag/capture.py` reads `transcriptPath`, extracts the last user/assistant
  exchange, saves it locally (`remember(push=False)`), then best-effort `sync_once`.

> ⚠️ **The hook field contract is corroborated but NOT first-party smoke-tested by
> us.** The PreInvocation injection field (`injectSteps`/`ephemeralMessage` — there
> is no `additionalContext`/`systemMessage`), the presence of `transcriptPath` on the
> Stop payload, and the transcript file's on-disk format are all consistent across
> the official docs + danicat.dev + the GCP migration article + antigravityide.help,
> but we have not verified them on a live Antigravity install. **They must be
> validated there.** Everything is designed to **fail open**: if a field name is
> wrong, recall just prints nothing and capture just no-ops — the turn always
> proceeds and the MCP + skill path keeps working unchanged. Antigravity uses a
> `decision` field for control (NOT Claude Code's exit-2-to-block); our hooks never
> set it, so they can't gate a turn.

### What still needs live Antigravity validation
- That a plugin's bundled `hooks.json` `PreInvocation` reads our STDOUT and that
  `injectSteps`/`ephemeralMessage` actually injects the recalled block.
- That the `Stop` payload includes `transcriptPath` and that the transcript file's
  format is parseable by `atlaso_ag/transcript.py` (its parser is format-tolerant —
  JSONL / single-JSON / wrapper object — but the real shape is undocumented).
- The exact plugin `hooks.json` group/`enabled`/event-key schema once loaded from
  inside a plugin bundle (vs. the shared `~/.gemini/config/hooks.json`).

## Free vs paid

Same as every Atlaso connector: a free plan is 1 active tool per device. The MCP
entry sets `ATLASO_TOOL=antigravity` (literal) so the server can scope this device's
entitlement. A revoked/non-entitled tool keeps working **locally** (never deletes
memories) and re-links when you upgrade — that whole state machine lives in
`atlaso_client`, reused unchanged.

> Note: as of this writing the shared MCP server (`atlaso_mcp/server.py`) constructs
> its `Client()` without forwarding `ATLASO_TOOL`, so the literal is currently
> forward-compatible — it tags the process correctly for when the server starts
> reading it. No behavior change is needed in this connector.

## Layout (source tree)

```
tools/antigravity/
  plugin.json                      plugin marker {"name":"atlaso", ...}
  bin/atlaso-memory-mcp            MCP launcher (dual-mode: built runtime / dev venv)
  atlaso_ag/                       lifecycle hook logic (mirrors claude-code/atlaso_cc)
    recall.py                      PreInvocation → injectSteps/ephemeralMessage
    capture.py                     Stop → save last exchange + sync
    transcript.py                  format-tolerant session-log reader
    _shim.py                       read_payload / make_client / log
  hooks/                           shell launchers (dual-mode resolver)
    _resolve.sh  recall.sh  capture.sh
  config/mcp_config.template.json  → bundle's mcp_config.json (with __ATLASO_PLUGIN_DIR__)
  config/hooks.template.json       → bundle's hooks.json (with __ATLASO_PLUGIN_DIR__)
  skills/memory/SKILL.md           model-driven memory skill (→ plugin skills/)
  rules/ATLASO.md                  rules section (→ plugin rules/atlaso.md)
  install.py                       copy bundle → ~/.gemini/config/plugins/atlaso/ (idempotent)
  package.py                       assemble the plugin bundle into dist/plugins/atlaso/
```

## Dev / test

`package.py` is the single source of truth for the bundle layout; `install.py`
calls it automatically when run from the dev tree (no built bundle present), then
copies the result. The launcher + hooks auto-detect a built `runtime/`
(self-contained, via `uv`) or, in-repo, the SDK venv + platform siblings.

Build the bundle explicitly:

```bash
python package.py          # → dist/plugins/atlaso/
```

Offline smoke test against a throwaway HOME:

```bash
export GEMINI_HOME=/tmp/atlaso-agy-test     # redirect ~/.gemini
python install.py --dry-run
python install.py
ls -R /tmp/atlaso-agy-test/config/plugins/atlaso
python install.py --uninstall
```
