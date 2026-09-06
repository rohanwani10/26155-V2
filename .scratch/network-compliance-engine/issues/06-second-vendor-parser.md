# 06: Second vendor parser (Juniper SRX or FortiGate)

**What to build:** A deterministic parser for a structurally different vendor, targeting the same shared fact model, fully evaluated across all four frameworks.

**Blocked by:** 04

**Status:** ready-for-agent

- [ ] A config from the chosen second vendor (final pick made during implementation: Juniper SRX or FortiGate) is parsed into the same fact model used by Cisco IOS, with no vendor-specific branching outside the parser module itself.
- [ ] Device identification is extracted from that vendor's equivalent of a version/hardware dump.
- [ ] The parsed facts are evaluated against all four frameworks and produce a PDF report identical in shape to the Cisco IOS one.
- [ ] Vendor-specific parsing edge cases (this vendor's syntax for at least the controls covered in ticket 03) are covered by tests using real fixture configs.
