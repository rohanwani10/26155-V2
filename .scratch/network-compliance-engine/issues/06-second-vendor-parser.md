# 06: Second vendor parser (Juniper SRX or FortiGate)

**What to build:** A deterministic parser for a structurally different vendor, targeting the same shared fact model, fully evaluated across all four frameworks.

**Blocked by:** 04

**Status:** done

- [x] A config from the chosen second vendor (final pick made during implementation: Juniper SRX or FortiGate) is parsed into the same fact model used by Cisco IOS, with no vendor-specific branching outside the parser module itself.
- [x] Device identification is extracted from that vendor's equivalent of a version/hardware dump.
- [x] The parsed facts are evaluated against all four frameworks and produce a PDF report identical in shape to the Cisco IOS one.
- [x] Vendor-specific parsing edge cases (this vendor's syntax for at least the controls covered in ticket 03) are covered by tests using real fixture configs.

## Comments

Vendor pick: **Juniper SRX** (Junos `set`-style CLI), per the "final pick made during implementation" note above.

Implementation is purely additive: `app/vendor_juniper_srx.py` (facts dataclass + parser + identity parser + remediation overrides + its own `register_redaction_rule()` calls, all at import time) plus a 2-block addition to the bottom of `app/vendors.py` (one import, one `register_vendor(...)` call). `devices.py`, `report.py`, and `evaluate.py` were not touched.

Notable judgment calls (Junos has no literal equivalent for several Cisco-specific concepts, so each was mapped to the closest real Junos mechanism serving the same security intent):

- **CDP -> LLDP** (`set protocols lldp interface ...`): Junos has no CDP. LLDP is the closest analogous discovery protocol. Direction note: Junos LLDP defaults *off*, so unlike Cisco's CDP (defaults on, fails safe when unconfigured), the Juniper fact defaults to *compliant* when absent -- this is a real behavioral difference between the vendors, not a parser bug.
- **BOOTP server -> `forwarding-options helpers bootp`**; **Finger -> `system services finger`** (Junos genuinely still supports Finger); **TCP small servers -> `system services xnm-clear-text`** (legacy cleartext XML-RPC management API); **UDP small servers -> `system services dhcp-local-server`**; **PAD -> `system services ssh root-login allow`** (Junos has no X.25 PAD at all; this substitutes another real, meaningfully insecure "if you don't need it, don't enable it" toggle). All five default off on Junos, same direction note as CDP/LLDP above.
- **`aaa new-model` -> `system authentication-order` including `radius`/`tacplus`**; **`aaa authorization exec` -> `system login user remote class <permission-class>`** (the real Junos "remote template user" mechanism for authorizing externally-authenticated sessions); **`aaa accounting exec` -> `system accounting events [login ...]` + `system accounting destination tacplus`** (genuine Junos TACACS+ accounting syntax).
- **`exec-timeout` -> `system login idle-timeout`** (global, since Junos has no per-line/per-session block the way IOS's `line con`/`line vty` do) vs **`ip ssh time-out` -> `system services ssh client-alive-interval`** (SSH-protocol-level keepalive/disconnect, a distinct real knob from the general login idle timeout).
- **`login block-for` and `ip ssh authentication-retries` both map onto `system login retry-options`** (`tries-before-disconnect` + `lockout-period`) -- Junos doesn't separate "SSH-specific retry limit" from "general account lockout" the way IOS does, so both CIS controls are evidenced from the same stanza, checked at different thresholds.
- **Cisco's three banner types (`banner login`/`motd`/`exec`) -> Junos's two** (`system login message`, shown pre-auth, mapped to both `banner_configured`/`banner_motd_configured`; `system login announcement`, shown post-auth, mapped to `banner_exec_configured`).
- **`access-class ... in` on VTY lines -> a `lo0` (Routing Engine loopback) firewall filter** (`interfaces lo0 unit 0 family inet filter input <name>` + a `firewall filter <name> term ... from source-address ...`), the standard real Junos/SRX "protect-RE" pattern for restricting management-plane access by source address.
- **`service password-encryption` -> "no `plain-text-password` anywhere in the config"** (root-authentication or local user authentication), since Junos has no single toggle for obscuring stored passwords -- it's an all-or-nothing property of which authentication form was used per secret.
- **`ip domain-lookup` -> presence of `system name-server`**: direction also flips vs. Cisco (Junos performs no DNS resolution unless a name-server is configured, vs. Cisco's on-by-default unqualified-command lookup), flagged as a low-severity CIS-7.8 hygiene item either way.
- **`service timestamps log datetime` -> `system syslog time-format`**: Junos syslog messages always carry a timestamp by default, so this fact is really tracking "explicitly configured *enhanced-precision* (year/millisecond) timestamps," not "timestamps present at all" -- kept the same fail-safe-if-absent direction as Cisco's fact for consistency, even though the underlying default behavior differs.

Vendor-specific redaction rules were added for: `root-authentication encrypted-password`/`plain-text-password`, `login user ... authentication encrypted-password`/`plain-text-password`, `radius-server`/`tacplus-server ... secret`, and `snmp community <name>` (tagging default `public`/`private` vs. custom, mirroring the Cisco SNMP redaction).

Tests: `backend/tests/test_vendor_juniper_srx.py` (parser unit tests, mirroring `test_facts.py`) and `backend/tests/test_juniper_srx_api.py` (API-boundary tests through `/api/devices`, mirroring `test_devices_api.py`) -- vendor identification, hardened-fixture-passes-all-controls across CIS/NIST/STIG, vulnerable-fixture-fails-expected-controls, ISO evidence production, Junos-syntax (not Cisco-syntax) remediation text, PDF generation, and secret redaction. Fixtures live under `backend/tests/fixtures/juniper_srx/` (`vulnerable_running_config.txt`, `hardened_running_config.txt`, `version_output.txt`).

`uv run pytest -q`: 145 passed. `uv run mypy app`: clean (strict mode).
