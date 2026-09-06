# 11: Online vendor-doc retrieval and knowledge promotion

**What to build:** When connectivity is available, enrich the unknown-vendor training queue by fetching official vendor documentation from an explicit allowlist, validating extracted semantics against the existing fact model, and promoting only verified knowledge into the shared vector store.

**Blocked by:** 09, 10

**Status:** ready-for-agent

- [ ] A per-vendor allowlist of official documentation domains is stored as data (not code) and is the only source ever fetched from.
- [ ] For queued unknown-vendor items, when online, the system fetches relevant documentation from the allowlist and extracts candidate semantics for the unrecognized line(s).
- [ ] Extracted semantics are validated against the existing fact model (via the same interpret/verify pipeline from ticket 09) before being trusted.
- [ ] Only validated knowledge is promoted into the local vector store introduced in ticket 10, improving future suggestion quality.
- [ ] This enrichment never bypasses the admin confirmation step from tickets 08/09 — it only improves the suggestion shown, never auto-creates a rule.
- [ ] When offline, queued items are simply left for the ticket 08/09 flow, with no error or blocking behavior.
