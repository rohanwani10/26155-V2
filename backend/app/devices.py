"""Upload -> parse -> evaluate -> report, for one or many Cisco IOS devices."""

import dataclasses
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile

from .evaluate import FRAMEWORK_NAMES, evaluate_all, evaluate_iso
from .redaction import redact_config
from .report import generate_pdf_report
from .storage import DeviceRecordCorrupted, DeviceStore
from .training import TrainingQueueStore, TrainingRuleStore, build_trained_facts
from .vendors import detect_vendor
from .version_info import DeviceIdentity


class DeviceUploadError(Exception):
    """Raised when one device's config/version pair can't be processed.
    Caught per-device in the bulk endpoint so one bad upload never blocks the
    rest of the batch."""


def _process_device_upload(
    raw_config: str,
    raw_version: str,
    vendor_hint: str | None,
    data_key: bytes,
    store: DeviceStore,
    queue_store: TrainingQueueStore,
    rule_store: TrainingRuleStore,
) -> dict[str, Any]:
    """The core single-device pipeline: redact -> detect vendor -> parse ->
    evaluate -> identity -> save. Shared by the single-upload and bulk-upload
    endpoints so there is exactly one place that does this, not two copies
    that can drift apart."""
    if not raw_config.strip():
        raise DeviceUploadError("Config file is empty")
    if not raw_version.strip():
        raise DeviceUploadError("Version info file is empty")

    profile = detect_vendor(raw_config, raw_version)
    redacted_config = redact_config(raw_config)

    if profile is not None:
        vendor_name = profile.name
        facts: Any = profile.parse_facts(redacted_config)
        identity = profile.parse_identity(raw_version)
        remediation_overrides = profile.remediation_overrides
    else:
        # Unrecognized vendor (see training.py): no fixed parser exists, so
        # instead of failing the upload, the fact model is built from this
        # vendor's admin-confirmed rules -- every fact defaults False, lines
        # that match a rule flip that rule's fact, and lines that match no
        # rule are queued for the admin to map later. Same evaluate_all/
        # evaluate_iso machinery from here on, no separate code path.
        vendor_name = (vendor_hint or "").strip() or "unknown"
        rules = rule_store.list_for_vendor(vendor_name, decrypt=Fernet(data_key).decrypt)
        facts, unrecognized_lines = build_trained_facts(redacted_config, rules)
        for line in unrecognized_lines:
            queue_store.add(vendor_name, line, encrypt=Fernet(data_key).encrypt)
        identity = DeviceIdentity(model=None, serial_number=None, os_version=None)
        remediation_overrides = {}

    findings = evaluate_all(facts, remediation_overrides)
    iso_evidence = [
        dataclasses.asdict(f) for f in evaluate_iso(facts, remediation_overrides)
    ]

    record = {
        "vendor": vendor_name,
        "redacted_config": redacted_config,
        "identity": dataclasses.asdict(identity),
        "findings": findings,
        "iso_evidence": iso_evidence,
    }

    device_id = store.save(record, encrypt=Fernet(data_key).encrypt)

    return {
        "device_id": device_id,
        "identity": record["identity"],
        "findings": findings,
        "iso_evidence": iso_evidence,
    }


def build_devices_router(
    data_dir: Path,
    require_session: Callable[..., bytes],
    queue_store: TrainingQueueStore,
    rule_store: TrainingRuleStore,
) -> APIRouter:
    router = APIRouter()
    store = DeviceStore(data_dir / "devices.db")

    def _load_record(device_id: str, data_key: bytes) -> dict[str, Any]:
        try:
            record = store.get(device_id, decrypt=Fernet(data_key).decrypt)
        except DeviceRecordCorrupted:
            raise HTTPException(
                status_code=500, detail="Device record is corrupted or unreadable"
            )
        if record is None:
            raise HTTPException(status_code=404, detail="Device not found")
        return record

    # Plain `def`, not `async def`: FastAPI runs sync handlers in a
    # threadpool, so the blocking regex/crypto/sqlite work here doesn't tie
    # up the event loop the way it would inside an `async def` with no real
    # awaits. `UploadFile.file` is the underlying sync file object.
    @router.post("/api/devices")
    def upload_device(
        config: UploadFile = File(...),
        version_info: UploadFile = File(...),
        vendor_hint: str | None = Form(default=None),
        data_key: bytes = Depends(require_session),
    ) -> dict[str, Any]:
        raw_config = config.file.read().decode("utf-8", errors="replace")
        raw_version = version_info.file.read().decode("utf-8", errors="replace")
        try:
            return _process_device_upload(
                raw_config, raw_version, vendor_hint, data_key, store, queue_store, rule_store
            )
        except DeviceUploadError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    # Multipart shape: two same-length lists, `configs` and `version_infos`,
    # paired positionally (configs[0] goes with version_infos[0], etc). This
    # is the simplest shape a plain HTML multi-file form can produce -- two
    # `<input type="file" multiple>` fields -- and validating the pairing is
    # just a length check, no per-device field naming scheme required.
    #
    # Synchronous loop over N devices in one request, same as the
    # single-device handler: no job queue or background-task machinery, since
    # this is "process N files in one request", not a long-running workflow.
    # Worth flagging (not solving here): a very large batch risks the
    # deployment's request body size / timeout limits before it risks the
    # in-process loop itself.
    @router.post("/api/devices/bulk")
    def upload_devices_bulk(
        configs: list[UploadFile] = File(...),
        version_infos: list[UploadFile] = File(...),
        vendor_hint: str | None = Form(default=None),
        data_key: bytes = Depends(require_session),
    ) -> dict[str, Any]:
        if not configs:
            raise HTTPException(status_code=400, detail="No device bundles provided")
        if len(configs) != len(version_infos):
            raise HTTPException(
                status_code=400,
                detail=(
                    "configs and version_infos must contain the same number of "
                    "files, paired positionally"
                ),
            )

        results: list[dict[str, Any]] = []
        for config, version_info in zip(configs, version_infos):
            raw_config = config.file.read().decode("utf-8", errors="replace")
            raw_version = version_info.file.read().decode("utf-8", errors="replace")
            try:
                results.append(
                    _process_device_upload(
                        raw_config,
                        raw_version,
                        vendor_hint,
                        data_key,
                        store,
                        queue_store,
                        rule_store,
                    )
                )
            except DeviceUploadError as exc:
                results.append({"error": str(exc), "config_filename": config.filename})

        return {"results": results}

    @router.get("/api/devices/{device_id}")
    def get_device(
        device_id: str, data_key: bytes = Depends(require_session)
    ) -> dict[str, Any]:
        return _load_record(device_id, data_key)

    @router.get("/api/devices/{device_id}/report.pdf")
    def get_report(
        device_id: str, data_key: bytes = Depends(require_session)
    ) -> Response:
        record = _load_record(device_id, data_key)
        try:
            identity = DeviceIdentity(**record["identity"])
        except (TypeError, KeyError):
            raise HTTPException(status_code=500, detail="Stored device data is invalid")
        pdf_bytes = generate_pdf_report(
            identity, record["findings"], record.get("iso_evidence", [])
        )
        return Response(content=pdf_bytes, media_type="application/pdf")

    # Fleet scope = every currently-stored device, not just one bulk batch:
    # the spec's own "across all uploaded devices" phrasing, and there's no
    # concept of a "batch" persisted anywhere to scope to even if we wanted
    # to -- devices from single-upload and bulk-upload are indistinguishable
    # once stored, which is the right amount of state for what's asked here.
    #
    # Findings are broken out per framework (see evaluate.py), so the
    # aggregate is too: each of CIS/NIST SP 800-53/DISA STIG gets its own
    # pass/fail totals and most-common-failures list, the same "never
    # collapse frameworks together" rule the results view and PDF follow.
    # ISO/IEC 27001 evidence isn't pass/fail, so it has no place in a
    # pass/fail fleet aggregate.
    @router.get("/api/fleet/summary")
    def fleet_summary(data_key: bytes = Depends(require_session)) -> dict[str, Any]:
        records = store.list_all(decrypt=Fernet(data_key).decrypt)

        devices: list[dict[str, Any]] = []
        pass_totals = {name: 0 for name in FRAMEWORK_NAMES}
        fail_totals = {name: 0 for name in FRAMEWORK_NAMES}
        control_fail_counts: dict[str, dict[str, dict[str, Any]]] = {
            name: {} for name in FRAMEWORK_NAMES
        }

        for device_id, record in records:
            findings_by_framework = record.get("findings", {})
            device_pass_counts: dict[str, int] = {}
            device_fail_counts: dict[str, int] = {}

            for framework in FRAMEWORK_NAMES:
                findings = findings_by_framework.get(framework, [])
                pass_count = sum(1 for f in findings if f["status"] == "pass")
                fail_count = sum(1 for f in findings if f["status"] == "fail")
                device_pass_counts[framework] = pass_count
                device_fail_counts[framework] = fail_count
                pass_totals[framework] += pass_count
                fail_totals[framework] += fail_count

                for f in findings:
                    if f["status"] != "fail":
                        continue
                    entry = control_fail_counts[framework].setdefault(
                        f["control_id"],
                        {
                            "control_id": f["control_id"],
                            "title": f["title"],
                            "severity": f["severity"],
                            "fail_count": 0,
                        },
                    )
                    entry["fail_count"] += 1

            devices.append(
                {
                    "device_id": device_id,
                    "identity": record.get("identity"),
                    "pass_counts": device_pass_counts,
                    "fail_counts": device_fail_counts,
                }
            )

        frameworks = {
            framework: {
                "total_pass_count": pass_totals[framework],
                "total_fail_count": fail_totals[framework],
                "most_common_failures": sorted(
                    control_fail_counts[framework].values(),
                    key=lambda entry: entry["fail_count"],
                    reverse=True,
                ),
            }
            for framework in FRAMEWORK_NAMES
        }

        return {
            "device_count": len(records),
            "devices": devices,
            "frameworks": frameworks,
        }

    return router
