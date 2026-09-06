"""Encrypted-at-rest device storage.

Every record is serialized to JSON and encrypted with the caller-supplied
Fernet key (the vault's unlocked data key) before it ever touches disk -- the
DB file itself holds nothing but opaque ciphertext blobs.
"""

import json
import sqlite3
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cryptography.fernet import InvalidToken


class DeviceRecordCorrupted(Exception):
    pass


class DeviceStore:
    def __init__(self, db_path: Path):
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        # sqlite3's own context-manager protocol only commits/rolls back on
        # exit -- it does NOT close the connection, so every call site would
        # otherwise leak one. This wraps that gap.
        conn = sqlite3.connect(self._db_path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY,
                    encrypted_payload BLOB NOT NULL
                )
                """
            )

    def save(self, record: dict[str, Any], encrypt: Callable[[bytes], bytes]) -> str:
        device_id = str(uuid.uuid4())
        payload = encrypt(json.dumps(record).encode("utf-8"))
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO devices (id, encrypted_payload) VALUES (?, ?)",
                (device_id, payload),
            )
        return device_id

    def get(
        self, device_id: str, decrypt: Callable[[bytes], bytes]
    ) -> dict[str, Any] | None:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT encrypted_payload FROM devices WHERE id = ?", (device_id,)
            ).fetchone()
        if row is None:
            return None
        payload: bytes = row[0]
        try:
            return dict(json.loads(decrypt(payload).decode("utf-8")))
        except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DeviceRecordCorrupted() from exc
