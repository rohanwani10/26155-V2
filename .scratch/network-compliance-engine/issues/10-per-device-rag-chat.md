# 10: Per-device RAG chat

**What to build:** A chat interface scoped to a single device's report, grounded via a local vector store over that device's facts/findings/remediation and the relevant control text across all four frameworks, with self-verified, cited answers.

**Blocked by:** 04

**Status:** ready-for-agent

- [ ] Each device's normalized facts, findings, remediation text, and the relevant control text (across all four frameworks) are embedded into a local, file-based vector store using a local embedding model.
- [ ] The admin can ask natural-language questions about that device's report and receive answers retrieved from that device's index, not from unrelated devices.
- [ ] Answers cite the specific finding/control they're grounded in.
- [ ] Each answer goes through the same interpret-then-verify two-pass pattern used elsewhere before being shown.
- [ ] The vector index and chat history persist to disk per device and survive an app restart.
- [ ] No secret-shaped values are ever embedded or surfaced in chat, consistent with the redaction applied at normalization.
