"""Vendor-scoped local Chroma store of confirmed training mappings (ticket
16), sitting in front of ticket 09's LLM propose-and-verify suggestion flow.

Every mapping an admin confirms via POST /api/training/mappings (training.py)
is embedded and stored here immediately (see `add`, called from
training.py's `create_mapping`), so a later *similar but not byte-identical*
line from the same vendor can resolve via a close embedding match
(`find_close_match`, called from training_suggestions.py before it ever
calls the LLM) instead of a fresh LLM call. training.py's own exact-string
rule matching (build_trained_facts) is untouched by this -- this is a
second, additive path, never a replacement for it, and never a replacement
for the admin confirming the resulting suggestion.

Deliberately a separate collection from both vectorstore.py's per-device
DeviceVectorStore (RAG chunks, scoped to one device's findings) and
vendor_knowledge_store.py's VendorKnowledgeStore (doc-derived knowledge):
this is confirmed admin decisions about *this vendor's config-line syntax*,
keyed by vendor the same way VendorKnowledgeStore is. Same
chromadb.PersistentClient pattern, rooted at the same
data_dir / "vectorstore" path -- a sibling collection namespace, not a
sibling directory.

Collections use cosine distance (not Chroma's l2 default) so "close match"
reads directly as a similarity score in [0, 1] via similarity = 1 - distance.
"""

from hashlib import sha256
from pathlib import Path
from typing import Any

import chromadb

from .llm import LlmClient

# Chosen so a config line that differs from a confirmed one by a single
# token (a changed IP/interface/argument, or pure whitespace) still counts
# as a close match, while two lines sharing no real vocabulary don't -- see
# the acceptance test in test_training_embedding_precheck_api.py. Exposed as
# a constructor parameter (not just this module constant) since the right
# cut for a real embedding model's similarity distribution may differ from
# what suits FakeLlmClient's hashing-trick vectors in tests.
DEFAULT_SIMILARITY_THRESHOLD = 0.7


class TrainingMappingStore:
    def __init__(
        self,
        data_dir: Path,
        llm_client: LlmClient,
        similarity_threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
    ) -> None:
        self._client = chromadb.PersistentClient(path=str(data_dir / "vectorstore"))
        self._llm = llm_client
        self._threshold = similarity_threshold

    def _collection(self, vendor: str) -> Any:
        # Same reasoning as VendorKnowledgeStore._collection: vendor is
        # always one of our own registered/admin-typed identifiers, never
        # arbitrary user text, so a fixed prefix is sanitizing enough.
        return self._client.get_or_create_collection(
            name=f"training_mappings_{vendor}",
            metadata={"hnsw:space": "cosine"},
        )

    def add(self, vendor: str, line: str, fact_id: str, value: bool) -> None:
        """Embed and upsert one confirmed mapping. Deterministic id from
        (vendor, line) -- the same pair training.py's rule store keys rules
        by -- so re-confirming a line updates this entry in place instead of
        piling up duplicates."""
        entry_id = sha256(f"{vendor}\x00{line}".encode("utf-8")).hexdigest()
        embedding = self._llm.embed(line)
        self._collection(vendor).upsert(
            ids=[entry_id],
            documents=[line],
            embeddings=[embedding],
            metadatas=[{"fact_id": fact_id, "value": value}],
        )

    def find_close_match(self, vendor: str, line: str) -> dict[str, Any] | None:
        """The nearest confirmed mapping for `vendor`, if its similarity to
        `line` clears this store's threshold -- else None. Never errors on
        an empty/not-yet-created collection (a brand new vendor)."""
        collection = self._collection(vendor)
        if collection.count() == 0:
            return None
        query_embedding = self._llm.embed(line)
        results = collection.query(query_embeddings=[query_embedding], n_results=1)
        distance = results["distances"][0][0]
        similarity = 1.0 - distance
        if similarity < self._threshold:
            return None
        metadata = results["metadatas"][0][0]
        return {
            "line": results["documents"][0][0],
            "fact_id": metadata["fact_id"],
            "value": bool(metadata["value"]),
            "similarity": similarity,
        }
