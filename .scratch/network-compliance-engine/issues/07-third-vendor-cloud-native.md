# 07: Third vendor parser (cloud-native: AWS Security Groups or SONiC)

**What to build:** A deterministic parser for a cloud-native/software-defined target, proving the fact model normalizes across CLI and non-CLI (JSON/API-style) configuration sources.

**Blocked by:** 04

**Status:** done

- [x] A config from the chosen cloud-native target (final pick made during implementation: AWS Security Groups or SONiC) is parsed into the same fact model used by the CLI vendors.
- [x] Device identification substitutes the equivalent cloud-native identifiers (resource ID/ARN, account, region) where serial/model don't apply.
- [x] The parsed facts are evaluated against all four frameworks and produce a report in the same shape as the CLI vendors, with fields adapted for a non-physical target.
- [x] Tests use real fixture configs for this target, covering at least the controls that meaningfully apply to a cloud-native security group / fabric config.

## Comments

Final pick: **AWS Security Groups** (the JSON/API-style target, per the ticket's own steer toward the target that best demonstrates JSON/API normalization vs. SONiC's CLI-shaped config).

Built:
- `backend/app/vendor_aws_security_groups.py` -- `AwsSecurityGroupFacts` (exact same 33 field names as `CiscoIosFacts`) + `parse_aws_security_group_facts()` (parses `describe-security-groups`-shaped JSON, either wrapped in `{"SecurityGroups": [...]}` or a bare SG object) + `parse_aws_security_group_identity()` (reads a GroupId/OwnerId/Region metadata JSON dump).
- `backend/app/version_info.py`: `DeviceIdentity` gained `resource_id`/`account`/`region`, all `str | None = None`, so existing Cisco construction sites are unaffected.
- `backend/app/report.py`: the identity section now branches -- cloud-native identity (any of resource_id/account/region set) renders "Resource ID / Account / Region"; otherwise the original "Model / Serial Number / OS Version" lines, unchanged. Verified with `test_pdf_report_for_cisco_device_is_unaffected`.
- `backend/app/vendors.py`: one import + one `register_vendor(...)` call for `aws_security_groups`, detecting on `'"IpPermissions"' in raw_config and '"GroupId"' in raw_config`. Registered after Cisco IOS; confirmed it never matches Cisco fixtures and Cisco's detector never matches AWS uploads.
- Fixtures: `backend/tests/fixtures/aws_security_groups/{vulnerable_security_group.json, hardened_security_group.json, identity_metadata.json}`.
- Tests: `backend/tests/test_vendor_aws_security_groups.py` (parser unit tests, including a field-name-parity check against `CiscoIosFacts` and an N/A-defaults-always-pass check) and `backend/tests/test_aws_security_groups_api.py` (API-boundary tests mirroring `test_devices_api.py`: vendor detection, all-frameworks findings, ISO evidence, PDF generation with cloud-native identity rendered, remediation overrides, and a Cisco-regression guard).

### Fact-mapping judgment calls

A security group is just an ingress/egress ACL -- it has no privileged-mode secret, AAA subsystem, console port, or legacy CLI services, so most of the 33 Cisco-centric facts have no real analog. Implemented for real (6 facts, driven by the uploaded JSON):

- `telnet_enabled` -- ingress rule allowing TCP 23 from `0.0.0.0/0`/`::/0`. Literal match to the Cisco meaning.
- `ssh_version_2` -- **repurposed**: a security group has no SSH protocol-version concept, so this fact instead captures "SSH access is not broadly exposed" (passes when TCP 22 isn't open to the world). Closest available slot for the ticket's suggested "SSH-exposure-related" check; documented inline since the rendered title ("Use SSH version 2 only") doesn't literally match anymore.
- `http_server_enabled` -- ingress rule allowing TCP 80 from `0.0.0.0/0`/`::/0`, treated as an exposed unencrypted HTTP management surface.
- `logging_host_configured` -- satisfied when the config JSON's `FlowLogs` array has an entry with `FlowLogStatus: "ACTIVE"` (VPC Flow Logs associated/enabled). `FlowLogs` isn't a real `describe-security-groups` field; it's this project's own signal, documented in the parser as "pair the SG dump with `describe-flow-logs` output for the VPC."
- `logging_trap_configured` -- satisfied when an ACTIVE flow log additionally has `TrafficType: "ALL"` (captures both accepted and rejected traffic), analogous to a broader syslog trap severity vs. an ACCEPT-only capture.
- `vty_access_class_configured` -- satisfied when no ingress rule allows unrestricted `0.0.0.0/0`/`::/0` exposure on a remote-management port (SSH 22, Telnet 23, RDP 3389) -- the ticket's own suggested mapping.

All other facts (banners, enable secret, AAA, exec-timeout, SNMP community, min password length, console login, CDP/BOOTP/finger/small-servers/PAD/source-route/domain-lookup, logging buffer size, service timestamps, etc.) have no meaningful analog for an ingress/egress ACL. Each is hardcoded in the parser to whichever value satisfies that fact's `passes_when` in `rules.py`, with a one-line "N/A: ... defaults to compliant" comment on the field -- verified by a dedicated test (`test_na_facts_default_to_a_harmless_pass`) that checks every non-implemented fact against both fixtures.

Vendor-specific remediation (`remediation_overrides` in `vendors.py`) is AWS CLI-style (`aws ec2 revoke-security-group-ingress` / `aws ec2 authorize-security-group-ingress` / `aws ec2 create-flow-logs`) for the 6 real facts.

Verification: `cd backend && uv run pytest -q` -- 122 passed. `uv run mypy app` -- clean (strict).
