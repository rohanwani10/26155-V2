# 05: Bulk upload + fleet aggregate dashboard

**What to build:** Allow uploading multiple devices' bundles at once, running each through the existing per-device pipeline, and viewing an aggregate fleet-wide summary alongside each device's own report.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] Admin can select and upload multiple device bundles (config + version dump pairs) in one action.
- [ ] Each device is processed through the same per-device pipeline independently; a failure on one device doesn't block the others.
- [ ] Each device still gets its own PDF report, unchanged from the single-device flow.
- [ ] A fleet dashboard view shows aggregate compliance posture across all uploaded devices (e.g. pass/fail counts, most common failures).
- [ ] No separate fleet-level PDF is produced — the aggregate view is UI-only.
