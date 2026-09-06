# 08: Unknown-vendor queue + manual training GUI

**What to build:** Handle a vendor the system doesn't recognize by queuing its unrecognized lines and letting the admin manually map them to security categories, with confirmed mappings becoming permanent deterministic rules. No AI involved yet — this ticket proves the human-confirmed learning loop mechanics first.

**Blocked by:** 04

**Status:** ready-for-agent

- [ ] Uploading a config from an unrecognized vendor doesn't fail the upload; recognized-shape lines (if any) are still evaluated, and unrecognized lines are placed into an unknown-vendor queue rather than silently dropped.
- [ ] A training GUI lists queued unrecognized lines for a given vendor and lets the admin assign each to a security category from the existing taxonomy (the same categories used by the fact model).
- [ ] Confirming a mapping creates a permanent, reusable rule for that vendor: future uploads from the same vendor evaluate that line deterministically, with no further manual mapping needed for the same pattern.
- [ ] Newly-created rules feed into the same multi-framework evaluation engine as the built-in vendor parsers — no separate code path.
- [ ] This entire flow works with no network connectivity.
