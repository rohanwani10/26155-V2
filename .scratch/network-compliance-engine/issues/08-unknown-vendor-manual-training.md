# 08: Unknown-vendor queue + manual training GUI

**What to build:** Handle a vendor the system doesn't recognize by queuing its unrecognized lines and letting the admin manually map them to security categories, with confirmed mappings becoming permanent deterministic rules. No AI involved yet — this ticket proves the human-confirmed learning loop mechanics first.

**Blocked by:** 04

**Status:** done

- [x] Uploading a config from an unrecognized vendor doesn't fail the upload; recognized-shape lines (if any) are still evaluated, and unrecognized lines are placed into an unknown-vendor queue rather than silently dropped.
- [x] A training GUI lists queued unrecognized lines for a given vendor and lets the admin assign each to a security category from the existing taxonomy (the same categories used by the fact model). (Per the codebase's established scope decision — see ticket 05 — this ships as an HTTP API only, no new React screens; a future frontend ticket can build a GUI on top of it.)
- [x] Confirming a mapping creates a permanent, reusable rule for that vendor: future uploads from the same vendor evaluate that line deterministically, with no further manual mapping needed for the same pattern.
- [x] Newly-created rules feed into the same multi-framework evaluation engine as the built-in vendor parsers — no separate code path.
- [x] This entire flow works with no network connectivity.

## Comments

**Design:**

- New module `backend/app/training.py` holds the whole mechanism:
  - `TrainingQueueStore` / `TrainingRuleStore` — two encrypted-at-rest sqlite stores (`training_queue.db`, `training_rules.db`) following `storage.py`'s `DeviceStore` pattern exactly: JSON payload, Fernet-encrypted with the session's `data_key`, no exceptions. The only plaintext column is `vendor` (an admin-chosen label, not sensitive config content) — everything else about an entry (the line text, and for rules the fact_id/value) stays encrypted.
  - `build_trained_facts(redacted_config, rules) -> (CiscoIosFacts, unrecognized_lines)` — the matching engine. Reuses `CiscoIosFacts` itself (it's already documented as "the shared fact model", not Cisco-specific) rather than inventing a second fact dataclass, so it flows through the exact same `evaluate_all`/`evaluate_iso` every built-in vendor uses. Every fact starts `False` (the same fail-safe-when-unproven stance `parse_cisco_ios_facts` already uses); a config line matches a rule and flips that rule's fact, or is unrecognized and returned for the caller to queue. Blank lines and lines starting with `!` or `#` are skipped before matching/queuing.
  - `build_training_router` exposes `GET /api/training/queue?vendor=<name>` (returns `{"vendor", "lines": [...]}`) and `POST /api/training/mappings` (body `{vendor, line, fact_id, value}`, returns `{"ok": true}`). Both gated behind `Depends(require_session)` like every other device-data endpoint.
- `devices.py`'s `_process_device_upload` now takes `vendor_hint`, `queue_store`, `rule_store`. When `detect_vendor()` returns `None`, it uses `vendor_hint` (stripped) or falls back to `"unknown"`, looks up that vendor's confirmed rules, builds facts via `build_trained_facts`, queues whatever didn't match, and proceeds through the identical `evaluate_all`/`evaluate_iso` → `DeviceStore.save` path recognized vendors use. `DeviceIdentity` for a trained vendor is all-`None` fields (no identity parser exists for an unknown vendor). Removed the now-dead `UnknownVendorError` and its raise — that branch is what got replaced.
- Both `/api/devices` and `/api/devices/bulk` gained `vendor_hint: str | None = Form(default=None)`. For the bulk endpoint this is one hint applied to the whole batch (not one per device) — simplest shape that satisfies the ticket; a per-device hint list would need a third positionally-paired list with no clear naming convention, and nothing in the ticket asks for per-device hints in one batch.
- `main.py` constructs the two training stores once and passes them into both `build_devices_router` and `build_training_router` so the upload path and the training endpoints share the same underlying data.

**Dedup / matching approach (judgment calls):**

- **Dedup key:** a queue/rule row's id is `sha256(f"{vendor}\x00{line}")` — computed from plaintext before encryption. This lets `INSERT OR IGNORE` (queue) / `INSERT OR REPLACE` (rules) dedupe or re-target a row without ever decrypting existing rows first, and means confirming a mapping can delete the exact matching queue row by recomputing its id, no decrypt-and-scan needed. The hash isn't a secrecy measure — it's a stable identity for a semantically-identical entry across uploads/devices.
- **Line matching is exact-string, not regex/fuzzy:** a config line matches a rule only if it's equal (after `.strip()`) to the rule's stored line. This is the simplest thing that satisfies "future uploads... evaluate that line deterministically" and keeps the mechanism auditable (an admin sees literally the same line they mapped). Fuzzier pattern matching (regex, prefix, token-based) is a natural extension for ticket 09's AI-assisted layer, not needed here.
- **Re-confirming a line already mapped replaces the rule** (`INSERT OR REPLACE`) rather than erroring — lets an admin correct a bad mapping without a separate "update" endpoint.
- **Existing test `test_upload_from_unrecognized_vendor_is_rejected`** (which asserted a 400) was renamed to `test_upload_from_unrecognized_vendor_succeeds_and_queues_lines` and rewritten to assert the new 200-and-queue behavior, since the old assertion is exactly the behavior this ticket replaces.

**Tests:** `backend/tests/test_training_api.py` (new) covers: auth-gating on both new endpoints, unrecognized lines queued under the right vendor key (and not under another vendor), duplicate lines across multiple uploads collapsing to one queue entry, unknown `fact_id` rejected with 400, confirming a mapping both creating the rule and clearing the queue, a re-upload after confirmation evaluating the mapped fact deterministically with the line no longer queued, and a shape check that trained-vendor findings carry the same `control_id`/`framework`/`severity`/`status` shape as built-in-vendor findings. `test_devices_api.py`'s single test above was updated for the new upload behavior.

**Verification:** `uv run pytest -q` → 114 passed. `uv run mypy app` → clean (strict). No `httpx`/`requests`/socket usage anywhere in `training.py` or the touched parts of `devices.py`/`main.py`.
