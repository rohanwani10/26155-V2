"""Upload -> parse -> evaluate -> report, for a single Cisco IOS device."""

import dataclasses
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile

from .evaluate import evaluate_cis
from .facts import parse_cisco_ios_facts
from .redaction import redact_config
from .report import generate_pdf_report
from .storage import DeviceRecordCorrupted, DeviceStore
from .version_info import DeviceIdentity, parse_cisco_ios_version


def build_devices_router(
    data_dir: Path, require_session: Callable[..., bytes]
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
        data_key: bytes = Depends(require_session),
    ) -> dict[str, Any]:
        raw_config = config.file.read().decode("utf-8", errors="replace")
        raw_version = version_info.file.read().decode("utf-8", errors="replace")

        redacted_config = redact_config(raw_config)
        facts = parse_cisco_ios_facts(redacted_config)
        identity = parse_cisco_ios_version(raw_version)
        findings = [dataclasses.asdict(f) for f in evaluate_cis(facts)]

        record = {
            "vendor": "cisco_ios",
            "redacted_config": redacted_config,
            "identity": dataclasses.asdict(identity),
            "findings": findings,
        }

        device_id = store.save(record, encrypt=Fernet(data_key).encrypt)

        return {
            "device_id": device_id,
            "identity": record["identity"],
            "findings": findings,
        }

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
        pdf_bytes = generate_pdf_report(identity, record["findings"])
        return Response(content=pdf_bytes, media_type="application/pdf")

    return router
