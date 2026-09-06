# 04: Multi-framework mapping (NIST 800-53, DISA STIG, ISO/IEC 27001)

**What to build:** Map the existing (full) fact set to three more frameworks on top of CIS, so the same device evaluation produces findings across all four.

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] Each fact maps to its corresponding NIST SP 800-53 and DISA STIG control (ID, requirement text, severity), at the same precise 1:1 technical granularity as CIS.
- [ ] Each fact maps to the relevant ISO/IEC 27001 Annex A control objective at a coarser, many-facts-to-one level, explicitly presented as evidentiary rather than a line-item pass/fail.
- [ ] The results view and PDF report show findings broken out per framework for a single device.
- [ ] The framework selector in the UI shows all four frameworks as real, working options — nothing shown as disabled or "coming soon."
- [ ] Remediation steps are reused or extended per framework as appropriate; no framework's remediation is ever LLM-generated.
