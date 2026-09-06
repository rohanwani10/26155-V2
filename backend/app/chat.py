"""Per-device RAG chat endpoints.

Flow per question: load the device record (404 if missing, same convention
as devices.py) -> lazily index that device's findings/evidence into its own
vector-store collection -> retrieve the top-k most relevant chunks from THAT
device's index only -> ask the LLM client to interpret a draft answer from
the question plus retrieved context -> adversarially verify the draft
against that same context -> only on success return the answer plus
citations (the finding/control metadata each retrieved chunk carries); on
verification failure, return a safe fallback instead of the unverified
draft. Every exchange (verified or not) is persisted to that device's
encrypted chat history so `GET .../chat` reflects exactly what the admin was
shown.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .chat_store import ChatHistoryStore
from .llm import LlmClient
from .storage import DeviceRecordCorrupted, DeviceStore
from .vectorstore import DeviceVectorStore

UNVERIFIED_FALLBACK = (
    "I'm unable to verify an answer to that question from this device's "
    "recorded findings and control text."
)

TOP_K = 4


class ChatRequest(BaseModel):
    question: str


def build_chat_router(
    data_dir: Path,
    require_session: Callable[..., bytes],
    llm_client: LlmClient,
) -> APIRouter:
    router = APIRouter()
    # Own DeviceStore instance pointed at the same devices.db devices.py
    # writes to -- sqlite is safe to open from multiple instances/processes,
    # and this keeps the chat router decoupled from devices.py's router
    # rather than threading a shared store instance through main.py.
    device_store = DeviceStore(data_dir / "devices.db")
    history_store = ChatHistoryStore(data_dir / "chat_history.db")
    vector_store = DeviceVectorStore(data_dir, llm_client)

    def _load_device(device_id: str, data_key: bytes) -> dict[str, Any]:
        try:
            record = device_store.get(device_id, decrypt=Fernet(data_key).decrypt)
        except DeviceRecordCorrupted:
            raise HTTPException(
                status_code=500, detail="Device record is corrupted or unreadable"
            )
        if record is None:
            raise HTTPException(status_code=404, detail="Device not found")
        return record

    @router.post("/api/devices/{device_id}/chat")
    def chat(
        device_id: str,
        body: ChatRequest,
        data_key: bytes = Depends(require_session),
    ) -> dict[str, Any]:
        record = _load_device(device_id, data_key)
        vector_store.ensure_indexed(device_id, record)
        chunks = vector_store.query(device_id, body.question, k=TOP_K)

        context = "\n\n".join(chunk["text"] for chunk in chunks)
        prompt = (
            "Answer the question below about one network device's compliance "
            "report, using only the context provided. If the context doesn't "
            "answer the question, say so.\n\n"
            f"Question: {body.question}\n\nContext:\n{context}"
        )
        draft_answer = llm_client.interpret(prompt)
        verified = bool(chunks) and llm_client.verify(draft_answer, context)

        if verified:
            answer = draft_answer
            citations = [chunk["metadata"] for chunk in chunks]
        else:
            answer = UNVERIFIED_FALLBACK
            citations = []

        fernet = Fernet(data_key)
        exchange = {
            "question": body.question,
            "answer": answer,
            "citations": citations,
        }
        history_store.append(
            device_id, exchange, encrypt=fernet.encrypt, decrypt=fernet.decrypt
        )
        return exchange

    @router.get("/api/devices/{device_id}/chat")
    def get_chat_history(
        device_id: str, data_key: bytes = Depends(require_session)
    ) -> dict[str, Any]:
        _load_device(device_id, data_key)  # 404s on a nonexistent device
        history = history_store.get_all(device_id, decrypt=Fernet(data_key).decrypt)
        return {"history": history}

    return router
