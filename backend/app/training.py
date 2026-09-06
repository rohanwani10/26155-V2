"""Unknown-vendor training loop (ticket 08, no AI involved).

An upload from a vendor the registry doesn't recognize (see vendors.py)
doesn't fail: instead, every non-blank/non-comment line of the (already
redacted -- see redaction.py) config is checked against that vendor's
confirmed rules. A matching line sets the rule's fact to the rule's value; an
unmatched line is "unrecognized" and gets queued for an admin to map via
POST /api/training/mappings. Confirming a mapping creates a permanent rule
and clears the now-covered line from the queue -- future uploads from that
vendor evaluate it deterministically, with no further manual step, through
the exact same evaluate_all/evaluate_iso machinery every built-in vendor
parser uses (see devices.py).

Both stores follow storage.py's DeviceStore pattern: JSON payload,
Fernet-encrypted with the caller's session data_key, one row per record --
same encryption discipline, no exceptions, since a queued/mapped line is a
real (if redacted) config line. `vendor` is kept as a plaintext column
(unlike the payload) since it's an admin-chosen label, not sensitive config
content, and it's how both stores filter -- everything else about the entry
stays encrypted.
"""

import dataclasses
import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .facts import CiscoIosFacts
from .rules import CIS_CONTROLS

# The "existing taxonomy... used by the fact model" a queued line gets mapped
# into -- the real ~33 fact_ids, not something the admin can freely invent.
FACT_IDS = frozenset(f.name for f in dataclasses.fields(CiscoIosFacts))

# Fail-safe default per fact: an unproven fact must default to whichever
# value FAILS that fact's control, never to whichever value happens to be
# `False`. Facts where the insecure state is `True` (e.g. telnet_enabled)
# would otherwise default to a silent, unproven "pass" the moment a
# trained-vendor line hasn't been mapped yet -- the opposite of fail-safe.
_FAIL_SAFE_DEFAULTS: dict[str, bool] = {
    control.fact_id: not control.passes_when for control in CIS_CONTROLS
}


def _entry_id(vendor: str, line: str) -> str:
    """Deterministic id from the plaintext (vendor, line) pair -- lets
    INSERT OR IGNORE/REPLACE dedupe and re-target rows without ever having to
    decrypt existing rows first. Not a secrecy measure (a hash of a config
    line is not sensitive on its own); purely a dedup key."""
    return sha256(f"{vendor}\x00{line}".encode("utf-8")).hexdigest()


@contextmanager
def _connection(db_path: Path) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(db_path)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


class TrainingQueueStore:
    def __init__(self, db_path: Path):
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with _connection(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS queue_entries (
                    id TEXT PRIMARY KEY,
                    vendor TEXT NOT NULL,
                    encrypted_payload BLOB NOT NULL
                )
                """
            )

    def add(self, vendor: str, line: str, encrypt: Callable[[bytes], bytes]) -> None:
        payload = encrypt(json.dumps({"line": line}).encode("utf-8"))
        with _connection(self._db_path) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO queue_entries (id, vendor, encrypted_payload) "
                "VALUES (?, ?, ?)",
                (_entry_id(vendor, line), vendor, payload),
            )

    def list_for_vendor(
        self, vendor: str, decrypt: Callable[[bytes], bytes]
    ) -> list[str]:
        with _connection(self._db_path) as conn:
            rows = conn.execute(
                "SELECT encrypted_payload FROM queue_entries WHERE vendor = ?",
                (vendor,),
            ).fetchall()
        lines = []
        for (payload,) in rows:
            try:
                lines.append(json.loads(decrypt(payload).decode("utf-8"))["line"])
            except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError):
                continue  # a corrupted queue entry shouldn't break the listing
        return lines

    def remove(self, vendor: str, line: str) -> None:
        with _connection(self._db_path) as conn:
            conn.execute(
                "DELETE FROM queue_entries WHERE id = ?", (_entry_id(vendor, line),)
            )


class TrainingRuleStore:
    def __init__(self, db_path: Path):
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with _connection(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rules (
                    id TEXT PRIMARY KEY,
                    vendor TEXT NOT NULL,
                    encrypted_payload BLOB NOT NULL
                )
                """
            )

    def add(
        self,
        vendor: str,
        line: str,
        fact_id: str,
        value: bool,
        encrypt: Callable[[bytes], bytes],
    ) -> None:
        """INSERT OR REPLACE: re-confirming a mapping for a line already
        ruled on updates it in place rather than erroring or duplicating."""
        payload = encrypt(
            json.dumps({"line": line, "fact_id": fact_id, "value": value}).encode(
                "utf-8"
            )
        )
        with _connection(self._db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO rules (id, vendor, encrypted_payload) "
                "VALUES (?, ?, ?)",
                (_entry_id(vendor, line), vendor, payload),
            )

    def list_for_vendor(
        self, vendor: str, decrypt: Callable[[bytes], bytes]
    ) -> list[dict[str, Any]]:
        with _connection(self._db_path) as conn:
            rows = conn.execute(
                "SELECT encrypted_payload FROM rules WHERE vendor = ?", (vendor,)
            ).fetchall()
        rules = []
        for (payload,) in rows:
            try:
                rules.append(dict(json.loads(decrypt(payload).decode("utf-8"))))
            except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError):
                continue  # a corrupted rule shouldn't break evaluation
        return rules


def build_trained_facts(
    redacted_config: str, rules: list[dict[str, Any]]
) -> tuple[CiscoIosFacts, list[str]]:
    """The core matching mechanism for a vendor with no fixed parser. Every
    fact starts at its fail-safe default (whichever value FAILS that fact's
    control -- see _FAIL_SAFE_DEFAULTS) -- the same fail-safe-when-unproven
    convention parse_cisco_ios_facts already uses -- and only flips when a
    confirmed rule's line matches exactly (after stripping); every fact
    naturally still evaluates correctly through evaluate_all/evaluate_iso's
    passes_when logic, so there's no "not applicable" case to invent. Blank
    lines and comment lines (`!` or `#`) are skipped before matching -- never
    queued, never matched. Everything else that doesn't match a rule is
    returned as "unrecognized" for the caller to queue."""
    rule_by_line = {rule["line"]: rule for rule in rules}
    fact_values: dict[str, bool] = dict(_FAIL_SAFE_DEFAULTS)
    unrecognized: list[str] = []
    for raw_line in redacted_config.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        rule = rule_by_line.get(line)
        if rule is None:
            unrecognized.append(line)
        else:
            fact_values[rule["fact_id"]] = rule["value"]
    return CiscoIosFacts(**fact_values), unrecognized


class MappingRequest(BaseModel):
    vendor: str
    line: str
    fact_id: str
    value: bool


def build_training_router(
    require_session: Callable[..., bytes],
    queue_store: TrainingQueueStore,
    rule_store: TrainingRuleStore,
) -> APIRouter:
    router = APIRouter()

    @router.get("/api/training/queue")
    def get_training_queue(
        vendor: str, data_key: bytes = Depends(require_session)
    ) -> dict[str, Any]:
        # Must match devices.py's `(vendor_hint or "").strip() or "unknown"`
        # normalization exactly -- otherwise a vendor value that differs only
        # by incidental whitespace looks up a different storage key than the
        # one uploads actually queue/rule against.
        vendor = vendor.strip() or "unknown"
        lines = queue_store.list_for_vendor(vendor, decrypt=Fernet(data_key).decrypt)
        return {"vendor": vendor, "lines": lines}

    @router.post("/api/training/mappings")
    def create_mapping(
        body: MappingRequest, data_key: bytes = Depends(require_session)
    ) -> dict[str, bool]:
        if body.fact_id not in FACT_IDS:
            raise HTTPException(
                status_code=400, detail=f"Unknown fact_id: {body.fact_id}"
            )
        vendor = body.vendor.strip() or "unknown"
        line = body.line.strip()
        rule_store.add(
            vendor, line, body.fact_id, body.value, encrypt=Fernet(data_key).encrypt
        )
        queue_store.remove(vendor, line)
        return {"ok": True}

    return router
