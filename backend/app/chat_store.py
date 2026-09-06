"""Encrypted-at-rest, per-device chat history.

Mirrors storage.DeviceStore's JSON-payload-encrypted-with-Fernet pattern, but
keyed directly by device_id with upsert semantics, rather than
DeviceStore's generate-a-new-uuid-per-save shape -- chat history is one
growing list per device, not one independent record per save.
"""

import json
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cryptography.fernet import InvalidToken


class ChatHistoryCorrupted(Exception):
    pass


class ChatHistoryStore:
    def __init__(self, db_path: Path):
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        # FastAPI runs sync handlers in a threadpool, so two concurrent chat
        # requests for the same device can otherwise both read the same prior
        # history before either writes back, and the second write silently
        # drops the first exchange. One process-wide lock around the
        # read-modify-write is enough for this single-local-admin app -- no
        # per-device lock table needed for this traffic level.
        self._append_lock = threading.Lock()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
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
                CREATE TABLE IF NOT EXISTS chat_history (
                    device_id TEXT PRIMARY KEY,
                    encrypted_payload BLOB NOT NULL
                )
                """
            )

    def get_all(
        self, device_id: str, decrypt: Callable[[bytes], bytes]
    ) -> list[dict[str, Any]]:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT encrypted_payload FROM chat_history WHERE device_id = ?",
                (device_id,),
            ).fetchone()
        if row is None:
            return []
        payload: bytes = row[0]
        try:
            return list(json.loads(decrypt(payload).decode("utf-8")))
        except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ChatHistoryCorrupted() from exc

    def append(
        self,
        device_id: str,
        exchange: dict[str, Any],
        encrypt: Callable[[bytes], bytes],
        decrypt: Callable[[bytes], bytes],
    ) -> None:
        with self._append_lock:
            history = self.get_all(device_id, decrypt)
            history.append(exchange)
            payload = encrypt(json.dumps(history).encode("utf-8"))
            with self._connection() as conn:
                conn.execute(
                    """
                    INSERT INTO chat_history (device_id, encrypted_payload)
                    VALUES (?, ?)
                    ON CONFLICT(device_id) DO UPDATE SET encrypted_payload = excluded.encrypted_payload
                    """,
                    (device_id, payload),
                )
