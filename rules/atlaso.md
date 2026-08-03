## Atlaso memory

You have an `atlaso` MCP server for the user's long-term memory (shared across
their tools and projects). Antigravity does **not** auto-inject memories, so use it
deliberately:

- **Recall first** when prior context would help — at the start of a task, when the
  user references a past decision, or before a choice that might contradict an
  earlier one. Tool: `recall(query)`.
- **Remember** durable facts, decisions (with their reason), stable preferences, and
  hard-won gotchas. Tool: `remember(text)`. Skip transient state and secrets.
- `recent`, `status`, and `forget` (only when the user asks) are also available.

One good recall beats five speculative ones. Prefer a small, high-signal memory
over volume. See the `memory` skill for the full judgment guide.
