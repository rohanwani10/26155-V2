# 11: Online vendor-doc retrieval and knowledge promotion

**What to build:** When connectivity is available, enrich the unknown-vendor training queue by fetching official vendor documentation from an explicit allowlist, validating extracted semantics against the existing fact model, and promoting only verified knowledge into the shared vector store.

**Blocked by:** 09, 10

**Status:** done

- [x] A per-vendor allowlist of official documentation domains is stored as data (not code) and is the only source ever fetched from.
- [x] For queued unknown-vendor items, when online, the system fetches relevant documentation from the allowlist and extracts candidate semantics for the unrecognized line(s).
- [x] Extracted semantics are validated against the existing fact model (via the same interpret/verify pipeline from ticket 09) before being trusted.
- [x] Only validated knowledge is promoted into the local vector store introduced in ticket 10, improving future suggestion quality.
- [x] This enrichment never bypasses the admin confirmation step from tickets 08/09 — it only improves the suggestion shown, never auto-creates a rule.
- [x] When offline, queued items are simply left for the ticket 08/09 flow, with no error or blocking behavior.

## Comments

**Allowlist format** (`backend/app/data/vendor_doc_allowlist.json`): a flat
JSON object, vendor name -> list of allowed official doc hostnames, e.g.
`{"cisco_ios": ["www.cisco.com"], "juniper_srx": ["www.juniper.net"],
"aws_security_groups": ["docs.aws.amazon.com"]}`. Any vendor not present
(any live-trained/unknown vendor, by definition) simply gets `[]` -> no
enrichment attempted, no error. Host matching is case-sensitive (a plain
`host in list` check) -- documented in `doc_fetcher.py`'s module docstring;
this is fine because the allowlist is admin-curated data, not attacker input
that could smuggle a case variant past a stricter check.

**`DocFetcher` (`backend/app/doc_fetcher.py`)**: mirrors `LlmClient`'s
Protocol-plus-fake pattern exactly. `DocFetcher.fetch(url) -> str | None`.
`HttpDocFetcher` validates the URL's host against the *union* of every
vendor's allowlisted hosts (`is_allowlisted_host`) before making any
request -- this is the single choke point every fetch passes through, since
the Protocol's `fetch` takes no vendor argument. Vendor scoping happens one
layer up (`urls_for_vendor`): the only code path that ever turns "vendor X"
into a URL, and it only ever emits that vendor's own allowlisted URL(s). Every
`httpx` exception is caught and turned into `None` (offline/unavailable),
never raised. `FakeDocFetcher` is deterministic/settable and is the only
fetcher used anywhere in the test suite -- no test makes a real network call
(verified for the allowlist-rejection test by patching `httpx.get` and
asserting it's never called).

**`VendorKnowledgeStore` (`backend/app/vendor_knowledge_store.py`)**: a
Chroma-backed store analogous to `vectorstore.py`'s `DeviceVectorStore`, but
collection-per-*vendor* (`vendor_knowledge_<vendor>`) instead of
per-device, since documentation knowledge describes a vendor's syntax in
general, not any one device -- shoving it into a per-device collection would
be a conceptual mismatch. Reuses the same `chromadb.PersistentClient`
machinery rooted at the same `data_dir / "vectorstore"` path as a sibling
collection namespace (Chroma already isolates by collection name, so no
separate directory was needed). `promote(vendor, fact_id, text, source_url)`
embeds `text` via `LlmClient.embed` and `upsert`s it, deduped on a
deterministic id from `(fact_id, source_url)` so repeated enrichment runs
update in place rather than duplicating. `query(vendor, text, k=3)` returns
the top-k chunks, `[]` for a vendor with no collection/entries yet.

**Enrichment flow** (`training_suggestions.py`, additive): before the
existing propose/verify call, `_enrich_from_docs` tries each of the vendor's
allowlisted URLs in turn via `DocFetcher.fetch`; on the first successful
fetch, it builds a doc-grounded extraction prompt (config line + a trimmed
2000-char excerpt of the fetched page + the fact taxonomy) and calls
`llm_client.interpret`, then adversarially checks the result via
`llm_client.verify` against the doc excerpt -- only a verified candidate is
promoted into `VendorKnowledgeStore`. Independently of whether a fresh fetch
happened, `VendorKnowledgeStore.query(vendor, line)` is always called and its
results folded into both the main suggestion's `interpret` prompt and its
`verify` context, so promoted knowledge keeps paying off on later requests
(online or offline) without needing to refetch. When there's nothing to
fetch and nothing previously promoted, the extra context is empty and the
prompt built is byte-identical to ticket 09's original -- so the offline case
is provably unchanged, not just "close enough." A `doc_enrichment_used`
boolean was added to the response body (additive field, doesn't change any
existing key) so callers/tests can see whether *this* request freshly
promoted something. Nothing here ever writes a training rule --
`POST /api/training/mappings` remains the only path that does.

**Scoping decision (search vs. direct fetch):** enrichment fetches the
vendor's known official doc URL(s) directly (currently one root URL per
allowlisted host, e.g. `https://www.cisco.com/`) rather than performing any
real web search or crawling. There's no search engine or crawler in this
system, and building one wasn't asked for; "try the vendor's known doc
page(s) directly" is an honestly-scoped, small implementation that satisfies
the acceptance criteria without inventing an unrequested search feature. A
future ticket could deepen this (crawl linked pages, use a real search API)
without changing the `DocFetcher`/`VendorKnowledgeStore` seams.

**Wiring**: `create_app` gained an optional `doc_fetcher: DocFetcher | None`
parameter (defaults to `HttpDocFetcher()`), same shape as the existing
`llm_client` parameter. `VendorKnowledgeStore` is constructed once in
`create_app` (like `DeviceVectorStore` is in `chat.py`) and threaded into
`build_training_suggestions_router` alongside `doc_fetcher`.

**Tests** (`backend/tests/test_vendor_doc_retrieval_api.py`, 7 new tests, all
API-boundary + `FakeLlmClient`/`FakeDocFetcher`, no real network calls
anywhere): successful fetch verifies and promotes; offline fetch (`None`) is
behaviorally identical to ticket 09; an unregistered/untrained vendor never
even attempts a fetch; a non-allowlisted host is rejected by `HttpDocFetcher`
before `httpx.get` is ever called (asserted via mock); a failed `verify`
blocks promotion even after a successful fetch; promoted knowledge persists
across a fresh app/session pointed at the same data dir and is folded in
without refetching; and enrichment never touches `/api/training/queue` or
creates a rule. `cd backend && uv run pytest -q` -> 198 passed, 3 deselected
(baseline was 191 passed, 3 deselected -- 7 new tests, 0 regressions).
`uv run mypy app` -> clean (strict) across 24 source files.
