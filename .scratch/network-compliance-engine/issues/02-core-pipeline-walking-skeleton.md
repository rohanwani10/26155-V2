# 02: Core compliance pipeline — walking skeleton (Cisco IOS × CIS, small control set)

**What to build:** The full ingest → parse → normalize → evaluate → remediate → report path, proven end to end for Cisco IOS against a foundational subset (~8-10) of CIS controls. This proves the pipeline shape before broadening content.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] Admin uploads a Cisco IOS running-config plus a version/hardware-info dump for one device.
- [ ] The config is parsed into a vendor-neutral fact model covering the initial control set (e.g. SSH version, Telnet disabled, password encryption, banner, logging enabled, SNMP community strings, AAA, exec timeout).
- [ ] Each fact is evaluated against the CIS control it maps to, producing a pass/fail with severity.
- [ ] Any secret-shaped value encountered while parsing (passwords, PSKs, SNMP strings, hashes) is redacted into a typed placeholder at the point of normalization, before it reaches storage, any report, or any other consumer.
- [ ] Each failed control comes with a pre-authored, tested CLI remediation command sequence specific to Cisco IOS.
- [ ] Device identification (serial, model, OS version) is extracted from the version/hardware dump and shown in the results.
- [ ] A single PDF report is generated per device containing device identification, findings (pass/fail + severity), and remediation steps.
- [ ] No secret value appears anywhere in the stored data, the UI, or the PDF — verified by a test that asserts on report content, not on internal function calls.
