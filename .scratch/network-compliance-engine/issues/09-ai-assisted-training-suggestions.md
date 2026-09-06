# 09: AI-assisted training suggestions with self-verification

**What to build:** Use a local Ollama model to propose a category for each unrecognized line in the training queue, with a second self-critique pass cross-checking the proposal before it's shown to the admin. The admin's confirmation step from ticket 08 is unchanged — this only improves the quality of the starting suggestion.

**Blocked by:** 08

**Status:** done

- [x] For each queued unrecognized line, a local LLM call proposes a security category using local reasoning only (no network access required).
- [x] A second local LLM pass, using an adversarial/critique-style prompt, checks the first proposal against the known facts, existing rules, and category taxonomy before it's surfaced.
- [x] The training GUI shows the (verified) suggestion pre-filled, but the admin can accept, edit, or reject it — no suggestion is ever auto-applied. (Satisfied at the API boundary per the scope decision: the endpoint returns the verified suggestion read-only for a future frontend to prefill from; the admin still calls `POST /api/training/mappings` themselves.)
- [x] This works fully offline; the LLM calls never depend on internet access. (Goes through the existing `LlmClient` seam only; no new network code added.)
- [x] Both LLM roles run via the same local, quantized model, selected to fit the target hardware, using two different prompts/roles rather than two separately loaded models. (Both `interpret` and `verify` calls go through the one injected `LlmClient`, exactly like `chat.py`.)

## Comments

Built `GET /api/training/suggestions?vendor=<name>&line=<line>` in a new
`backend/app/training_suggestions.py`, wired into `main.py` with one import
and one `app.include_router(...)` line (same pattern as the chat/training
routers). Requires a session like every other endpoint.

**Flow:** load existing confirmed rules for the vendor from
`TrainingRuleStore` (context for both passes) -> build an `interpret` prompt
containing the raw line, the full `fact_id: title` taxonomy (from
`rules.CIS_CONTROLS`, validated against `training.FACT_IDS`, the same set
`POST /api/training/mappings` already validates against), and the vendor's
existing rules -> parse the response -> if parseable, build a `verify`
claim ("this line maps to fact X with value Y") and context (the line, the
fact's title/meaning, and existing rules, so a proposal contradicting an
established rule can be caught) -> return
`{vendor, line, fact_id, value, rationale, verified, error}`.

**Prompt/parsing judgment call:** asked the model for a simple three-line
format (`FACT_ID: ...` / `VALUE: true|false` / `RATIONALE: ...`) rather than
JSON, per the ticket's own suggestion that a small quantized model won't
reliably produce well-formed JSON. Parsed with tolerant regexes (case-
insensitive, ignores surrounding prose) rather than strict line splitting.
A response that's missing a field, or whose `fact_id` isn't a real
`training.FACT_IDS` entry, is rejected by the parser (returns `None`) rather
than raising or trusting it -- the endpoint then responds `200` with
`fact_id: null`, `verified: false`, and an `error` message, never a 500 and
never a fabricated category presented as real.

**Verification-is-load-bearing judgment call:** even a well-formed, in-
taxonomy proposal is only returned as `verified: true` if `llm_client.verify`
agrees; a `False` result still returns the proposed fields (for transparency
about what the model guessed) but with `verified: false`, so a frontend can
never mistake an unverified guess for a trustworthy one -- mirrors
`chat.py`'s "never surface an unverified draft as-is" rule, adapted since
here the raw guess is still informational value to a human reviewer (unlike
chat's free-text answer, which gets replaced by a safe fallback string).

**Nothing is ever written:** the endpoint only reads from `TrainingRuleStore`
(for context) and calls the read-only `LlmClient` methods -- it never calls
`TrainingRuleStore.add` or `TrainingQueueStore.remove`. Confirmed by a test
that a suggestion request leaves `GET /api/training/queue` unchanged.

Tests added in `backend/tests/test_training_suggestions_api.py` (6 new,
all API-boundary style with `FakeLlmClient` per `test_chat_api.py`'s
pattern): 401 without a session, a real-taxonomy `fact_id` proposal on a
good response, `verified: false` surfaced (not hidden) on a failed verify
pass, no queue/rule side effects from a suggestion request, and two
graceful-failure cases (out-of-taxonomy `fact_id`, and a response with no
parseable fields at all) -- both return 200 with `verified: false` rather
than crashing.

`cd backend && uv run pytest -q`: 191 passed (185 baseline + 6 new), 3
deselected (llm_smoke). `uv run mypy app`: clean, no issues.
