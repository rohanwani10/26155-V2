"""Vendor-scoped local Chroma store for documentation-derived training
knowledge (ticket 11).

Deliberately a *separate* store from vectorstore.py's DeviceVectorStore, not
a reuse of it: that store is one collection per *device* (RAG chat, scoped to
one device's findings). This knowledge is about a *vendor's syntax in
general* -- e.g. "this Juniper SRX line means SSHv2-only" -- so it belongs to
the vendor, not any one device, and shoving it into a per-device collection
would be a conceptual mismatch (per ticket 11's own framing). Same
`chromadb.PersistentClient` machinery/pattern as vectorstore.py, rooted at
the same `data_dir / "vectorstore"` path -- a sibling collection namespace,
not a sibling directory, since Chroma collections are already isolated by
name and a single persistent client is enough.

Only verified knowledge (already checked by the caller's interpret/verify
pass in training_suggestions.py -- this store trusts its caller, same as
DeviceVectorStore trusts its findings input) ever reaches `promote`.
"""

from pathlib import Path
from hashlib import sha256
from typing import Any

import chromadb

from .llm import LlmClient


class VendorKnowledgeStore:
    def __init__(self, data_dir: Path, llm_client: LlmClient) -> None:
        self._client = chromadb.PersistentClient(path=str(data_dir / "vectorstore"))
        self._llm = llm_client

    def _collection(self, vendor: str) -> Any:
        # Chroma collection names must start/end alphanumeric and be
        # otherwise fairly restrictive; a vendor name here is always one of
        # our own registered/admin-typed identifiers (e.g. "cisco_ios",
        # "acme_widgetos"), never arbitrary user text, so no sanitizing
        # beyond the fixed "vendor_" prefix is needed.
        return self._client.get_or_create_collection(name=f"vendor_knowledge_{vendor}")

    def promote(self, vendor: str, fact_id: str, text: str, source_url: str) -> None:
        """Store one piece of verified, doc-derived knowledge for `vendor`.
        Deduped on (fact_id, source_url): a deterministic id from that pair,
        upserted -- so re-running enrichment (e.g. the same suggestion
        requested twice) updates the entry in place rather than piling up
        duplicates."""
        entry_id = sha256(f"{fact_id}\x00{source_url}".encode("utf-8")).hexdigest()
        embedding = self._llm.embed(text)
        self._collection(vendor).upsert(
            ids=[entry_id],
            documents=[text],
            embeddings=[embedding],
            metadatas=[{"fact_id": fact_id, "source_url": source_url}],
        )

    def query(self, vendor: str, text: str, k: int = 3) -> list[dict[str, Any]]:
        """Top-k promoted knowledge chunks for `vendor`, most relevant to
        `text` first. Empty list if the vendor has no collection/entries
        yet -- never an error."""
        collection = self._collection(vendor)
        count = collection.count()
        if count == 0:
            return []
        query_embedding = self._llm.embed(text)
        results = collection.query(
            query_embeddings=[query_embedding], n_results=min(k, count)
        )
        documents = results["documents"][0]
        metadatas = results["metadatas"][0]
        return [
            {"text": doc, "metadata": dict(meta)}
            for doc, meta in zip(documents, metadatas)
        ]
