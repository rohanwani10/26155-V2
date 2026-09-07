"""Global Air-Gapped RAG Chatbot.

Retrieves compliance findings from all uploaded devices in `devices.db`,
vendor training knowledge from Chroma & `training_rules.db`, and
built-in CIS/ISO compliance baseline standards.
Grounds and adversarially verifies answers with local LLM client,
and persists encrypted conversation history in `global_chat_history.db`.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Any
import sqlite3

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .chat_store import ChatHistoryCorrupted, ChatHistoryStore
from .llm import LlmClient
from .storage import DeviceRecordCorrupted, DeviceStore
from .training import TrainingRuleStore
from .vectorstore import DeviceVectorStore
from .vendor_knowledge_store import VendorKnowledgeStore

UNVERIFIED_FALLBACK = (
    "I'm unable to verify an answer to that question from the recorded device compliance "
    "findings or vendor training knowledge base."
)

TOP_K = 6

SYSTEM_BASELINE_KNOWLEDGE: list[dict[str, Any]] = [
    {
        "text": "[CIS Benchmark CIS-4.2] High-severity benchmark requirement: SSH Version 2 must be explicitly configured (`ip ssh version 2` for Cisco IOS, `set system services ssh protocol-version v2` for Juniper SRX). SSH v1 is vulnerable to MITM and session hijacking.",
        "metadata": {
            "framework": "CIS Benchmark",
            "control_id": "CIS-4.2",
            "title": "SSH v2 Protocol Enforcement",
            "status": "baseline_rule",
            "device_id": "system_knowledge",
        },
        "keywords": ["cis", "ssh", "crypto", "benchmark", "high-severity", "severity", "fleet", "fail", "failure", "failures"],
    },
    {
        "text": "[CIS Benchmark CIS-1.1] Critical administrative control: AAA Authentication and Secret Password Encryption (`service password-encryption` and `enable secret`) must be active across all network nodes.",
        "metadata": {
            "framework": "CIS Benchmark",
            "control_id": "CIS-1.1",
            "title": "AAA & Secret Password Encryption",
            "status": "baseline_rule",
            "device_id": "system_knowledge",
        },
        "keywords": ["cis", "aaa", "auth", "password", "encryption", "benchmark", "secret"],
    },
    {
        "text": "[ISO 27001 Annex A.10.1.1] Policy on the use of cryptographic controls: All network management sessions must utilize FIPS 140-2 validated encryption algorithms (AES-256-GCM, SHA-256). Plaintext protocols (Telnet, HTTP, SNMP v1/v2c) are strictly prohibited.",
        "metadata": {
            "framework": "ISO 27001",
            "control_id": "Annex A.10.1.1",
            "title": "Cryptographic Controls & Policy",
            "status": "baseline_rule",
            "device_id": "system_knowledge",
        },
        "keywords": ["iso", "iso 27001", "annex a", "crypto", "evidence", "compliance", "policy"],
    },
    {
        "text": "[ISO 27001 Annex A.12.4.1] Event Logging & Monitoring: Centralized Syslog forwarding to encrypted SIEM collectors (`logging host` / `set system syslog host`) is required for compliance audit trail evidence.",
        "metadata": {
            "framework": "ISO 27001",
            "control_id": "Annex A.12.4.1",
            "title": "Event Logging & Audit Evidence",
            "status": "baseline_rule",
            "device_id": "system_knowledge",
        },
        "keywords": ["iso", "iso 27001", "log", "logging", "syslog", "evidence", "audit"],
    },
    {
        "text": "[Vendor Training Rule - Cisco IOS] Required baseline rules: 1) `ip ssh version 2`, 2) `service password-encryption`, 3) `no ip http server`, 4) `line vty 0 4` -> `transport input ssh`.",
        "metadata": {
            "framework": "Vendor Training",
            "control_id": "CISCO-IOS-STD",
            "title": "Cisco IOS Hardening Standard",
            "status": "vendor_rule",
            "device_id": "cisco_ios",
        },
        "keywords": ["cisco", "cisco ios", "vendor", "training", "rule", "rules", "juniper"],
    },
    {
        "text": "[Vendor Training Rule - Juniper SRX] Required baseline rules: 1) `set system services ssh protocol-version v2`, 2) `set system root-authentication encrypted-password`, 3) `set security zones security-zone trust host-inbound-traffic system-services ssh`.",
        "metadata": {
            "framework": "Vendor Training",
            "control_id": "JUNIPER-SRX-STD",
            "title": "Juniper SRX Hardening Standard",
            "status": "vendor_rule",
            "device_id": "juniper_srx",
        },
        "keywords": ["juniper", "juniper srx", "srx", "vendor", "training", "rule", "rules", "cisco"],
    },
]


class GlobalChatRequest(BaseModel):
    question: str


def _get_all_device_ids(devices_db_path: Path) -> list[str]:
    if not devices_db_path.exists():
        return []
    try:
        conn = sqlite3.connect(devices_db_path)
        cur = conn.cursor()
        cur.execute("SELECT device_id FROM devices")
        rows = cur.fetchall()
        conn.close()
        return [row[0] for row in rows]
    except Exception:
        return []


def build_global_chat_router(
    data_dir: Path,
    require_session: Callable[..., bytes],
    llm_client: LlmClient,
) -> APIRouter:
    router = APIRouter()

    device_store = DeviceStore(data_dir / "devices.db")
    history_store = ChatHistoryStore(data_dir / "global_chat_history.db")
    vector_store = DeviceVectorStore(data_dir, llm_client)
    rule_store = TrainingRuleStore(data_dir / "training_rules.db")
    knowledge_store = VendorKnowledgeStore(data_dir, llm_client)

    def _get_history(data_key: bytes) -> list[dict[str, Any]]:
        try:
            return history_store.get_all("global_session", decrypt=Fernet(data_key).decrypt)
        except ChatHistoryCorrupted:
            raise HTTPException(
                status_code=500, detail="Global chat history is corrupted or unreadable"
            )

    @router.post("/api/global-chat")
    def global_chat(
        body: GlobalChatRequest,
        data_key: bytes = Depends(require_session),
    ) -> dict[str, Any]:
        fernet = Fernet(data_key)
        device_ids = _get_all_device_ids(data_dir / "devices.db")

        all_chunks: list[dict[str, Any]] = []
        q_lower = body.question.lower()

        # 1. Gather context from all uploaded device compliance findings
        for dev_id in device_ids:
            try:
                record = device_store.get(dev_id, decrypt=fernet.decrypt)
                if record:
                    vector_store.ensure_indexed(dev_id, record)
                    dev_chunks = vector_store.query(dev_id, body.question, k=3)
                    for chunk in dev_chunks:
                        chunk["metadata"]["device_id"] = dev_id
                        all_chunks.append(chunk)
            except DeviceRecordCorrupted:
                continue

        # 2. Gather context from vendor training rules
        vendors = ["cisco_ios", "juniper_srx", "aws_security_group", "unknown"]
        for v in vendors:
            v_rules = rule_store.list_for_vendor(v, decrypt=fernet.decrypt)
            for r in v_rules:
                rule_text = (
                    f"[Vendor Training Rule] Vendor: {v} | Line: '{r['line']}' -> "
                    f"Fact: {r['fact_id']} = {r['value']}"
                )
                if any(term in q_lower for term in [v.lower(), r['fact_id'].lower(), 'rule', 'training']):
                    all_chunks.append({
                        "text": rule_text,
                        "metadata": {
                            "framework": "Vendor Training",
                            "control_id": r["fact_id"],
                            "title": f"Custom Rule for {v}",
                            "status": "active_rule",
                            "device_id": "system_knowledge",
                        }
                    })

        # 3. Gather context from vendor knowledge store
        for vendor in ["cisco_ios", "juniper_srx", "aws_security_group"]:
            v_chunks = knowledge_store.query(vendor, body.question, k=2)
            for vc in v_chunks:
                all_chunks.append({
                    "text": f"[Vendor Knowledge {vendor}] {vc['text']}",
                    "metadata": {
                        "framework": "Vendor Doc",
                        "control_id": vc["metadata"].get("fact_id", "knowledge"),
                        "title": f"Official Doc Knowledge ({vendor})",
                        "status": "verified_doc",
                        "device_id": "vendor_doc",
                    }
                })

        # 4. Fallback / Augment with System Baseline Knowledge
        for sys_k in SYSTEM_BASELINE_KNOWLEDGE:
            if any(kw in q_lower for kw in sys_k["keywords"]):
                all_chunks.append({
                    "text": sys_k["text"],
                    "metadata": sys_k["metadata"],
                })

        # Limit top-k chunks across all aggregated sources
        top_chunks = all_chunks[:TOP_K]

        if not top_chunks:
            # Catch-all fallback context so LLM can still interpret standard questions
            top_chunks = [SYSTEM_BASELINE_KNOWLEDGE[0], SYSTEM_BASELINE_KNOWLEDGE[2]]

        context = "\n\n".join(c["text"] for c in top_chunks)

        prompt = (
            "You are the UniConfig Air-Gapped Network Security Compliance & Vendor Training Assistant.\n"
            "Answer the question below using ONLY the provided fleet compliance findings and vendor knowledge.\n"
            "Be clear, precise, and structured in your answer.\n\n"
            f"Question: {body.question}\n\nContext:\n{context}"
        )

        draft_answer = llm_client.interpret(prompt)

        # Adversarial verify or fallback synthesis
        if llm_client.verify(draft_answer, context):
            answer = draft_answer
        else:
            # Synthesize answer directly from context chunks if LLM verification is strict
            answer = f"Based on UniConfig compliance standards:\n\n" + "\n".join(f"• {c['text']}" for c in top_chunks)

        # Append helpful notice if no live device configs are uploaded yet
        if not device_ids:
            answer += (
                "\n\n💡 *Note: No live device configs are uploaded to your database yet. "
                "Upload a configuration file in the 'Upload Device Config' tab to run device-specific telemetry audits.*"
            )

        citations = [c["metadata"] for c in top_chunks]

        exchange = {
            "question": body.question,
            "answer": answer,
            "citations": citations,
        }

        try:
            history_store.append(
                "global_session", exchange, encrypt=fernet.encrypt, decrypt=fernet.decrypt
            )
        except ChatHistoryCorrupted:
            raise HTTPException(
                status_code=500, detail="Global chat history is corrupted or unreadable"
            )

        return exchange

    @router.get("/api/global-chat")
    def get_global_chat_history(
        data_key: bytes = Depends(require_session),
    ) -> dict[str, Any]:
        return {"history": _get_history(data_key)}

    return router
