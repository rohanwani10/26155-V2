# Vendor-Agnostic Network Compliance Engine

Status: ready-for-agent

## Problem Statement

Network administrators managing heterogeneous fleets of firewalls, routers, and switches from many vendors (Cisco, Juniper, Palo Alto, FortiGate, cloud-native security groups, white-box/SONiC, and others) must align every device with security hardening frameworks such as CIS Benchmarks, NIST SP 800-53, DISA STIGs, and ISO/IEC 27001. Today they have no good way to do this at scale:

- Manual, checklist-based auditing doesn't scale across a heterogeneous fleet and is error-prone.
- Existing enterprise management suites are expensive, vendor-locked, and can't interpret the config syntax of a vendor they weren't built for.
- Every vendor has its own CLI/API syntax and hierarchical structure, so a hardening setting that's a single line on one platform ("ssh version 2") is structurally unrecognizable on another.
- New or unusual vendors (white-box networking, cloud-native security groups, AI/hyperscale fabric gear) break traditional hard-coded parsers entirely, and there's no way to teach a hard-coded tool a new vendor's syntax without a code change and a redeploy.
- The data involved (device configs) routinely contains passwords, pre-shared keys, and other secrets, so any tool that touches it has to be trustworthy about where that data goes and how it's stored.

Administrators need a single tool that can ingest a config from *any* vendor, tell them precisely what's out of compliance against the frameworks they care about, hand them an exact fix, and get better at handling new vendors over time — without waiting on a vendor update from the tool's own maker.

## Solution

An on-premises, air-gap-capable compliance platform (Python backend, React frontend) built around one core idea: **configs are normalized into a shared, vendor-neutral fact model, and everything else — compliance evaluation, multi-framework mapping, remediation — is deterministic logic and data sitting on top of that shared model.** AI (two local Ollama-served roles, one model) is used only where determinism genuinely can't reach: interpreting a line from a vendor the system has never seen, and explaining findings conversationally. AI never issues a compliance verdict and never authors a remediation command; a human always confirms before newly-learned vendor knowledge becomes a trusted rule.

Concretely, the platform:

- Ingests one or many device config bundles (running-config + version/hardware output) through a web dashboard.
- Runs each known vendor's config through a deterministic parser into the shared fact model, then evaluates it against CIS, NIST SP 800-53, DISA STIG, and ISO/IEC 27001 (the first three at precise per-control granularity, ISO at the coarser control-objective level it's actually designed for).
- Produces a per-device PDF report: device identification, pass/fail findings with severity per framework, and pre-authored, tested, step-by-step remediation commands.
- Provides fleet-level bulk upload and an aggregate dashboard view across devices.
- Handles a vendor it doesn't recognize via a training loop: an admin maps unrecognized config lines to security categories in a GUI, assisted by a local LLM that proposes and self-verifies its own suggestions; when online, the system additionally retrieves official vendor documentation (from an explicit allowlist) to improve its suggestions, promoting only verified knowledge into a local knowledge base. Confirmed mappings become permanent, reusable, deterministic rules for that vendor.
- Offers a per-device RAG chat, grounded in that device's own findings and the relevant framework control text, so an admin can ask "why did this fail and how do I fix it" in natural language, with every answer self-verified by a second LLM pass before being shown.
- Runs entirely locally: local Ollama models for all AI, a local vector store, and a local encrypted database — the whole system works fully air-gapped, with internet only ever used opportunistically to improve vendor-knowledge quality.
- Protects the sensitive data it inherently handles: a login-gated single local admin account, an app-level encrypted data directory (with a one-time recovery key), and automatic redaction of secrets (passwords, PSKs, SNMP strings, hashes) out of anything that reaches the LLM, the vector store, chat history, or the PDF.

## User Stories

### Ingestion

1. As a network administrator, I want to upload a single device's config and version/hardware output together, so that the system can identify the device (serial, model, OS version) as well as evaluate it.
2. As a network administrator, I want to upload configs for many devices in one batch, so that I don't have to process my fleet one device at a time.
3. As a network administrator, I want clear feedback when an uploaded file isn't recognized as a valid config or version dump, so that I can fix the upload instead of getting a silently wrong report.
4. As a network administrator, I want to see which vendor and OS the system detected for each uploaded device, so that I can confirm it parsed the right thing before trusting the results.

### Deterministic parsing and normalization

5. As a network administrator, I want my Cisco IOS, Juniper/FortiGate-style, and cloud-native (AWS Security Groups/SONiC-style) configs each converted into the same normalized set of security facts, so that the same compliance logic can evaluate any of them.
6. As a network administrator, I want config lines the parser fully understands to be evaluated without any AI involvement, so that the bulk of my fleet's evaluation is fast, deterministic, and reproducible.
7. As a network administrator, I want the normalized fact model to capture the ~30-35 security-relevant settings that matter for hardening (SSH/crypto, insecure services, AAA/auth, logging, SNMP, ACLs/banners, timeouts), so that compliance evaluation is grounded in real, well-understood checks rather than an arbitrary subset.

### Multi-framework compliance evaluation

8. As a network administrator, I want to evaluate a device against CIS Benchmarks, NIST SP 800-53, DISA STIGs, and ISO/IEC 27001 from the same uploaded config, so that I don't have to re-audit the same device once per framework.
9. As a network administrator, I want CIS, NIST, and STIG findings to cite the exact control ID and requirement text they're checking, so that I can defend the finding to an auditor.
10. As a network administrator, I want ISO/IEC 27001 findings to be presented as supporting evidence toward the relevant Annex A control objective (since ISO isn't a line-item technical checklist like the others), so that the report doesn't overstate precision it doesn't have.
11. As a network administrator, I want each finding to carry a severity rating, so that I can prioritize remediation.
12. As a network administrator, I want to see which frameworks are actually supported before I pick one, so that I'm never offered a framework the system can't really evaluate.

### Remediation and reporting

13. As a network administrator, I want every failed control to come with a pre-tested, exact CLI command sequence to fix it, so that I can remediate with confidence instead of guessing at syntax.
14. As a network administrator, I want remediation commands to never be generated on the fly by an LLM, so that I never apply an AI-hallucinated command to a production device.
15. As a network administrator, I want a single PDF report per device containing device identification, all findings across all evaluated frameworks, and remediation steps, so that I have one artifact to hand to an auditor or a colleague.
16. As a network administrator, I want an aggregate dashboard view across all devices in a bulk upload, so that I can see fleet-wide compliance posture at a glance.
17. As a network administrator, I want any secret values that originally appeared in the config (passwords, PSKs, SNMP community strings, hashes) to never appear in plaintext in the PDF report, so that the report itself isn't a security liability.

### Training loop for unrecognized vendors

18. As a network administrator, I want to upload a config from a vendor the system has never seen, so that I'm not blocked from evaluating my whole fleet just because one device is unusual.
19. As a network administrator, I want unrecognized config lines to be queued for training rather than silently ignored, so that I know exactly what wasn't evaluated and why.
20. As a network administrator, I want the system to propose a security category for each unrecognized line, so that mapping it is fast rather than starting from a blank page.
21. As a network administrator, I want that proposal to be independently double-checked by a second AI pass before I see it, so that I'm reviewing a higher-quality suggestion, not a raw first guess.
22. As a network administrator, I want to always be the one who confirms a new vendor mapping before it's trusted, so that no compliance verdict is ever based on unreviewed AI output.
23. As a network administrator, I want a confirmed mapping to become a permanent, deterministic rule for that vendor, so that the system never needs AI to interpret that same line again.
24. As a network administrator, I want the training loop to work fully offline, so that an air-gapped deployment is never blocked from onboarding a new vendor.
25. As a network administrator, I want the system to opportunistically fetch official vendor documentation when I'm online, so that its training suggestions get better without any manual research from me.
26. As a network administrator, I want vendor documentation to only ever be fetched from an explicit, known-good list of official vendor domains, so that untrusted internet content can never become the basis of a security finding.
27. As a network administrator, I want documentation-derived knowledge to be independently validated against the existing fact model before it's stored, so that only verified knowledge — never raw scraped content — ends up informing future suggestions.

### Conversational report exploration (RAG chat)

28. As a network administrator, I want to ask natural-language questions about a specific device's report ("why did the SSH check fail?", "how do I fix this?"), so that I can understand findings without cross-referencing framework documents myself.
29. As a network administrator, I want chat answers to cite the specific finding and control text they're grounded in, so that I can verify the answer rather than trust it blindly.
30. As a network administrator, I want chat answers to be independently self-checked before being shown to me, so that the chat doesn't casually assert something the facts don't support.
31. As a network administrator, I want a device's chat history and knowledge to persist across app restarts, so that I don't lose context I built up in an earlier session.

### Security and access

32. As a network administrator, I want to log into the tool with a master password before I can see any device data, so that a compliance tool holding sensitive configs isn't wide open on my machine.
33. As a network administrator, I want the app's stored data (configs, database, vector store) encrypted at rest using a key derived from my master password, so that the data directory isn't plainly readable outside the app.
34. As a network administrator, I want a one-time recovery key generated at first setup, so that I have a way to recover my data if I lose my master password, without relying on any cloud recovery service.
35. As a network administrator, I want secret-looking values in configs (passwords, PSKs, SNMP strings, hashes) automatically redacted before they reach any AI model, the vector store, chat history, or the report, so that using the tool doesn't itself leak my devices' secrets.
36. As a network administrator, I want the app to run entirely on my own machine with no required network exposure, so that I can deploy it in an air-gapped environment with confidence.

## Implementation Decisions

**Architecture backbone**
- A vendor-neutral, shared "security fact model" is the single normalization target for every vendor parser. All downstream logic (compliance evaluation, framework mapping, remediation, training) operates on this fact model, not on raw vendor syntax.
- Framework support is a data layer, not code: each fact maps to zero or more framework controls (framework name, control ID, requirement text, severity, pre-authored remediation). Adding a framework or updating a benchmark version is a data change.
- Vendor support is a parser module targeting the same fact model. Adding a vendor is an additive module, not a change to the compliance/reporting logic.

**Vendor and framework coverage (initial build)**
- Three fully-built deterministic parsers: Cisco IOS (base/reference vendor), one structurally different traditional CLI vendor (Juniper SRX or FortiGate — exact pick made during implementation), and one cloud-native/software-defined target (AWS Security Groups or SONiC — exact pick made during implementation).
- A fourth, genuinely unseen vendor is handled live via the training loop rather than a pre-built parser, to demonstrate the adaptation path.
- ~30-35 curated facts, corresponding to the CIS Level 1 profile's technically-parseable controls (auth/AAA, SSH/crypto, insecure services, logging, SNMP, ACLs/banners, timeouts). Each fact is fully implemented (parsing + evaluation + remediation), not partially stubbed.
- All four frameworks (CIS, NIST SP 800-53, DISA STIG, ISO/IEC 27001) are mapped against this fact set. CIS/NIST/STIG map 1:1 at the technical-control level. ISO/IEC 27001 maps many-facts-to-one-Annex-A-control, at the control-objective/evidentiary level, and is presented as such rather than as a false line-item pass/fail.
- Remediation commands are pre-authored and tested per (vendor, control) pair as part of the same data layer used for framework mapping. No remediation command is ever LLM-generated.

**AI pipeline**
- All AI runs on local Ollama models. One small, quantized local model serves two distinct roles via prompting (not two separate model weights, to fit modest local GPU hardware): an "interpret/explain" role and an adversarial "verify this interpretation against the facts/rules/docs" role. Architecture allows swapping in two genuinely distinct models later without a redesign.
- Known-vendor pipeline is fully deterministic; AI is not in the evaluation path at all for recognized vendors.
- Unknown-vendor lines go into an unknown-vendor queue. Offline: the interpret role proposes a category from local reasoning alone, the verify role cross-checks it, and the admin confirms/corrects via a training GUI — this path never requires connectivity. Online: the queued item can additionally be enriched by fetching vendor documentation from an explicit per-vendor allowlist of official domains (stored as data), extracting and verifying semantics against the existing fact model, and promoting only verified knowledge into the local vector store — which improves the suggestion shown to the admin, but does not bypass the admin's confirmation step.
- No confidence-threshold auto-apply exists anywhere: every new vendor mapping requires explicit human confirmation before it becomes a trusted rule affecting compliance verdicts.
- RAG chat is scoped per device: a local, file-based vector store (Chroma) plus a local embedding model, indexing that device's facts/findings/remediation and the relevant control text across all four frameworks. Chat responses go through the same interpret-then-verify two-pass pattern before being shown. Chat history and the per-device vector index persist to disk across restarts.

**Ingestion**
- Per-device upload is two-part: running-config plus a version/hardware-info dump (or vendor equivalent), so serial/model/OS version can be reliably extracted rather than guessed from config comments. Cloud-native targets substitute their own identifiers (resource ID/ARN, account, region) for serial/model where those don't apply.
- Bulk upload processes multiple devices through the same per-device pipeline and produces both individual per-device PDFs and an aggregate fleet dashboard view (the aggregate view is UI-only; the PDF deliverable remains per-device, matching the original ask).

**Security**
- Single local admin account, login-gated, app bound to localhost only (no multi-user/network-facing auth in this build).
- App-level encryption of the entire data directory (database, vector store, stored config files), keyed off the master password.
- A one-time recovery key is generated and shown once at first-run setup; there is no other password-recovery mechanism.
- Secret-shaped values (passwords, PSKs, SNMP community strings, hashes) are detected and redacted into typed placeholders at the normalization boundary — the single point every vendor parser passes through — so redaction is enforced once, not re-implemented per vendor or per consumer (LLM, vector store, chat, PDF).

**Stack**
- Python backend, React frontend, moderate (not extensive) UI design investment — functional coverage of every major flow takes priority over visual polish.
- Local Ollama for all LLM/embedding calls; local file-based vector store (Chroma) for RAG.

## Testing Decisions

A good test here asserts on external behavior only — given a real fixture config file, what does the API return or what does the generated PDF contain — never on which internal function got called or how many times.

Two seams, chosen because this is a from-scratch build with no prior art to anchor to:

1. **HTTP API boundary (primary seam).** The large majority of the system — parsing, normalization, multi-framework evaluation, remediation lookup, device identification, redaction, encryption-at-rest, bulk orchestration — is deterministic and gets tested by calling real API endpoints with real fixture config files (one fixture per supported vendor, including edge cases like partially-hardened and fully-hardened configs) and asserting on the resulting JSON/PDF content. No internals are mocked for this seam.
2. **LLM client interface (secondary seam).** A thin interface (`interpret`, `verify`, `embed`, `chat`) that all training-loop and RAG-chat code calls through. The main test suite fakes this interface so the queue/propose/confirm/promote workflow and the chat's retrieve/verify orchestration are tested deterministically and fast, without a running Ollama instance. A small, separate set of smoke tests exercises the real Ollama-backed implementation to catch integration drift, but these aren't part of the main suite's fast feedback loop.

No prior art exists in this repo yet (greenfield); these two seams are the established pattern going forward for every subsequent ticket that touches parsing, evaluation, the training loop, or chat.

## Out of Scope

- Multi-user accounts, role-based access control, and any network-facing authentication or TLS — this build is single local admin, localhost-bound only.
- Cloud/SaaS deployment of any kind.
- Password recovery beyond the single one-time recovery key (no email-based or cloud-based reset flow).
- Vendor coverage beyond the three fully-built parsers plus the one live-trained demo vendor.
- CIS Level 2 and other non-technical/organizational controls that no config file could ever answer.
- A separate fleet-level PDF report (the aggregate view is UI-only; PDF remains per-device as originally specified).
- Live device polling/collection (e.g. via Netmiko/NAPALM) — configs are uploaded as files, never pulled from a live device.
- Any confidence-based auto-apply of AI-proposed vendor mappings.
- LLM-authored remediation commands, in any form.

## Further Notes

- Originated as a hackathon problem statement, but is intended to become a real product afterward — architecture decisions above were made with that extension in mind (data-driven vendor/framework support, no hard-coded shortcuts that would need to be ripped out later).
- Target timeline: roughly one month, team of two.
- The development machine has a modest local GPU (4GB VRAM), which is why the AI pipeline is specified as one small quantized local model in two roles rather than two large models.
- Separate deliverables (README, a 2-page architecture document, a 2-minute demo video, a 5-slide technical presentation) are required for evaluation but are documentation/presentation artifacts, not implementation tickets — they should be produced once the build below is functional, referencing this spec and the tickets it's broken into.
