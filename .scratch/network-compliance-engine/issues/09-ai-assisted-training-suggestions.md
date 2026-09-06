# 09: AI-assisted training suggestions with self-verification

**What to build:** Use a local Ollama model to propose a category for each unrecognized line in the training queue, with a second self-critique pass cross-checking the proposal before it's shown to the admin. The admin's confirmation step from ticket 08 is unchanged — this only improves the quality of the starting suggestion.

**Blocked by:** 08

**Status:** ready-for-agent

- [ ] For each queued unrecognized line, a local LLM call proposes a security category using local reasoning only (no network access required).
- [ ] A second local LLM pass, using an adversarial/critique-style prompt, checks the first proposal against the known facts, existing rules, and category taxonomy before it's surfaced.
- [ ] The training GUI shows the (verified) suggestion pre-filled, but the admin can accept, edit, or reject it — no suggestion is ever auto-applied.
- [ ] This works fully offline; the LLM calls never depend on internet access.
- [ ] Both LLM roles run via the same local, quantized model, selected to fit the target hardware, using two different prompts/roles rather than two separately loaded models.
