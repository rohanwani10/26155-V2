"""Per-device local Chroma vector store for RAG chat.

One Chroma collection per device (named by device_id) -- not one shared
collection filtered by a device_id field -- so retrieval for one device
structurally cannot return another device's chunks; there's no filter to get
wrong. Persistent client rooted at `data_dir / "vectorstore"`, so the index
survives a process restart same as everything else in this app.

Findings and remediation text are pre-authored/static (see rules.py) and
facts/findings are already redacted upstream at ingestion (see redaction.py)
-- so chunks built from them structurally can't carry raw secret values.
"""

import threading
from pathlib import Path
from typing import Any

import chromadb
from chromadb.errors import DuplicateIDError

from .llm import LlmClient


def _finding_chunks(record: dict[str, Any]) -> list[dict[str, Any]]:
    """One chunk per CIS/NIST/STIG finding -- the "reasonable granularity"
    the ticket calls out. Each chunk carries enough metadata to cite it back:
    control_id, framework, title."""
    chunks = []
    findings_by_framework: dict[str, list[dict[str, Any]]] = record.get("findings", {})
    for framework, findings in findings_by_framework.items():
        # NIST/STIG map several facts to the same control_id (many-to-one,
        # unlike CIS's 1:1), so `findings` can contain repeated control_ids
        # -- the chunk id needs the list position too, not just the
        # framework+control_id pair, to stay unique.
        for index, finding in enumerate(findings):
            control_id = finding["control_id"]
            text = (
                f"[{framework}] {control_id}: {finding['title']}\n"
                f"Status: {finding['status']} (severity: {finding['severity']})\n"
                f"Remediation: {finding['remediation'] or 'not applicable, control passes'}"
            )
            chunks.append(
                {
                    "id": f"{framework}:{control_id}:{index}",
                    "text": text,
                    "metadata": {
                        "control_id": control_id,
                        "framework": framework,
                        "title": finding["title"],
                        "status": finding["status"],
                    },
                }
            )
    return chunks


def _iso_evidence_chunks(record: dict[str, Any]) -> list[dict[str, Any]]:
    """One chunk per fact-level piece of ISO Annex A evidence -- ISO findings
    aren't pass/fail line items (see evaluate.py), so each chunk is scoped to
    one fact's contribution to one Annex A control's evidence, not the whole
    control."""
    chunks = []
    for annex in record.get("iso_evidence", []):
        control_id = annex["control_id"]
        for evidence in annex.get("evidence", []):
            fact_id = evidence["fact_id"]
            satisfied = "satisfied" if evidence["satisfied"] else "not satisfied"
            text = (
                f"[ISO/IEC 27001] {control_id}: {annex['title']}\n"
                f"Evidence ({evidence['title']}): {satisfied}\n"
                f"Remediation: {evidence['remediation'] or 'not applicable, evidence satisfied'}"
            )
            chunks.append(
                {
                    "id": f"ISO/IEC 27001:{control_id}:{fact_id}",
                    "text": text,
                    "metadata": {
                        "control_id": control_id,
                        "framework": "ISO/IEC 27001",
                        "title": evidence["title"],
                        "status": "satisfied" if evidence["satisfied"] else "not_satisfied",
                    },
                }
            )
    return chunks


def _build_chunks(record: dict[str, Any]) -> list[dict[str, Any]]:
    return _finding_chunks(record) + _iso_evidence_chunks(record)


class DeviceVectorStore:
    def __init__(self, data_dir: Path, llm_client: LlmClient) -> None:
        self._client = chromadb.PersistentClient(path=str(data_dir / "vectorstore"))
        self._llm = llm_client
        # The count()==0 "not yet indexed" check below isn't atomic with the
        # add() that follows it -- two concurrent first-chat requests for the
        # same never-yet-indexed device could otherwise both pass the check
        # and both insert the same chunk ids. One process-wide lock (same
        # reasoning as ChatHistoryStore's append lock) closes that window.
        self._index_lock = threading.Lock()

    def _collection(self, device_id: str) -> Any:
        # Chroma collection names must start/end alphanumeric; prefixing a
        # uuid4 device_id (which already satisfies that) keeps the name
        # unambiguous without needing to sanitize it.
        return self._client.get_or_create_collection(name=f"device_{device_id}")

    def ensure_indexed(self, device_id: str, record: dict[str, Any]) -> None:
        """Lazy indexing: a no-op once the device's collection already has
        entries, so this is safe to call on every chat request."""
        with self._index_lock:
            collection = self._collection(device_id)
            if collection.count() > 0:
                return
            chunks = _build_chunks(record)
            if not chunks:
                return
            embeddings = [self._llm.embed(chunk["text"]) for chunk in chunks]
            try:
                collection.add(
                    ids=[chunk["id"] for chunk in chunks],
                    documents=[chunk["text"] for chunk in chunks],
                    metadatas=[chunk["metadata"] for chunk in chunks],
                    embeddings=embeddings,
                )
            except DuplicateIDError:
                # Another process (or a call that raced ahead of the lock in
                # a future multi-process deployment) already indexed this
                # device -- same end state as the count()>0 early return.
                pass

    def query(self, device_id: str, question: str, k: int = 4) -> list[dict[str, Any]]:
        collection = self._collection(device_id)
        count = collection.count()
        if count == 0:
            return []
        query_embedding = self._llm.embed(question)
        results = collection.query(
            query_embeddings=[query_embedding], n_results=min(k, count)
        )
        documents = results["documents"][0]
        metadatas = results["metadatas"][0]
        return [
            {"text": doc, "metadata": dict(meta)}
            for doc, meta in zip(documents, metadatas)
        ]
