# 07: Third vendor parser (cloud-native: AWS Security Groups or SONiC)

**What to build:** A deterministic parser for a cloud-native/software-defined target, proving the fact model normalizes across CLI and non-CLI (JSON/API-style) configuration sources.

**Blocked by:** 04

**Status:** ready-for-agent

- [ ] A config from the chosen cloud-native target (final pick made during implementation: AWS Security Groups or SONiC) is parsed into the same fact model used by the CLI vendors.
- [ ] Device identification substitutes the equivalent cloud-native identifiers (resource ID/ARN, account, region) where serial/model don't apply.
- [ ] The parsed facts are evaluated against all four frameworks and produce a report in the same shape as the CLI vendors, with fields adapted for a non-physical target.
- [ ] Tests use real fixture configs for this target, covering at least the controls that meaningfully apply to a cloud-native security group / fabric config.
