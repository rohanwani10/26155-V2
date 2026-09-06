"""Envelope encryption for the app's local data.

A single random data key is generated once at setup and is what actually
encrypts device data on disk (see crypto.py callers elsewhere). That data key
is never stored directly; instead it's wrapped twice, independently, by a key
derived from the admin's password and by a key derived from a one-time
recovery key. Either credential can unwrap the same data key. Losing both
credentials means the data key -- and everything it encrypted -- is
unrecoverable by design.
"""

import json
import os
import threading
import uuid
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .crypto import derive_fernet_key, generate_recovery_key, generate_salt


class VaultAlreadySetUp(Exception):
    pass


class VaultNotSetUp(Exception):
    pass


class InvalidCredential(Exception):
    pass


class VaultCorrupted(Exception):
    pass


class Vault:
    def __init__(self, vault_path: Path):
        self._vault_path = vault_path
        # Guards the check-then-write in setup(): this app runs as a single
        # process for a single local admin, so a plain in-process lock is
        # enough to make "two near-simultaneous first-run setups" resolve to
        # exactly one winner instead of a silently overwritten vault file.
        self._lock = threading.Lock()

    def is_set_up(self) -> bool:
        return self._vault_path.exists()

    def setup(self, password: str) -> str:
        with self._lock:
            if self.is_set_up():
                raise VaultAlreadySetUp()

            data_key = Fernet.generate_key()
            recovery_key = generate_recovery_key()

            password_salt = generate_salt()
            recovery_salt = generate_salt()
            password_kek = Fernet(derive_fernet_key(password, password_salt))
            recovery_kek = Fernet(derive_fernet_key(recovery_key, recovery_salt))

            record = {
                "password_salt": password_salt.hex(),
                "wrapped_key_by_password": password_kek.encrypt(data_key).decode(
                    "ascii"
                ),
                "recovery_salt": recovery_salt.hex(),
                "wrapped_key_by_recovery": recovery_kek.encrypt(data_key).decode(
                    "ascii"
                ),
            }

            self._vault_path.parent.mkdir(parents=True, exist_ok=True)
            # Write to a sibling temp file and rename into place, so a crash
            # mid-write can never leave a truncated/corrupt vault.json behind.
            tmp_path = self._vault_path.with_name(
                f"{self._vault_path.name}.{uuid.uuid4().hex}.tmp"
            )
            tmp_path.write_text(json.dumps(record))
            os.replace(tmp_path, self._vault_path)

            return recovery_key

    def unlock(self, credential: str) -> bytes:
        if not self.is_set_up():
            raise VaultNotSetUp()

        try:
            record = json.loads(self._vault_path.read_text())
            unwrap_pairs = [
                (
                    bytes.fromhex(record["password_salt"]),
                    record["wrapped_key_by_password"],
                ),
                (
                    bytes.fromhex(record["recovery_salt"]),
                    record["wrapped_key_by_recovery"],
                ),
            ]
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            # A syntactically-valid-but-incomplete file (missing/renamed
            # keys, bad hex) is just as unusable as invalid JSON -- both mean
            # the vault can't be trusted, not that the credential is wrong.
            raise VaultCorrupted() from exc

        for salt, wrapped in unwrap_pairs:
            kek = Fernet(derive_fernet_key(credential, salt))
            try:
                return kek.decrypt(wrapped.encode("ascii"))
            except InvalidToken:
                continue

        raise InvalidCredential()
