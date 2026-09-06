"""Password/recovery-key based key derivation, used to wrap the vault's data key."""

import base64
import hashlib
import os

PBKDF2_ITERATIONS = 390_000
SALT_BYTES = 16
RECOVERY_KEY_BYTES = 20


def generate_salt() -> bytes:
    return os.urandom(SALT_BYTES)


def derive_fernet_key(secret: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from a low-entropy secret (password or recovery key)
    and base64-urlsafe-encode it, since that's the form Fernet requires."""
    raw = hashlib.pbkdf2_hmac(
        "sha256", secret.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32
    )
    return base64.urlsafe_b64encode(raw)


def generate_recovery_key() -> str:
    """A human-typeable, high-entropy secret shown once at setup."""
    raw = os.urandom(RECOVERY_KEY_BYTES)
    encoded = base64.b32encode(raw).decode("ascii").rstrip("=")
    return "-".join(encoded[i : i + 4] for i in range(0, len(encoded), 4))
