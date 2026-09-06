import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.fernet import Fernet

from app.vault import (
    InvalidCredential,
    Vault,
    VaultAlreadySetUp,
    VaultCorrupted,
    VaultNotSetUp,
)


def test_setup_and_unlock_with_password(tmp_path):
    vault = Vault(tmp_path / "vault.json")
    vault.setup("correct horse battery staple")

    data_key = vault.unlock("correct horse battery staple")

    assert data_key


def test_unlock_with_recovery_key_yields_same_data_key_as_password(tmp_path):
    vault = Vault(tmp_path / "vault.json")
    recovery_key = vault.setup("correct horse battery staple")

    via_password = vault.unlock("correct horse battery staple")
    via_recovery = vault.unlock(recovery_key)

    assert via_password == via_recovery


def test_wrong_password_is_rejected(tmp_path):
    vault = Vault(tmp_path / "vault.json")
    vault.setup("correct horse battery staple")

    with pytest.raises(InvalidCredential):
        vault.unlock("wrong password")


def test_wrong_recovery_key_is_rejected(tmp_path):
    vault = Vault(tmp_path / "vault.json")
    vault.setup("correct horse battery staple")

    with pytest.raises(InvalidCredential):
        vault.unlock("NOTA-REAL-RECO-VERY-KEY0")


def test_cannot_set_up_twice(tmp_path):
    vault = Vault(tmp_path / "vault.json")
    vault.setup("first password")

    with pytest.raises(VaultAlreadySetUp):
        vault.setup("second password")


def test_unlock_before_setup_raises(tmp_path):
    vault = Vault(tmp_path / "vault.json")

    with pytest.raises(VaultNotSetUp):
        vault.unlock("anything")


def test_is_set_up_reflects_state(tmp_path):
    vault = Vault(tmp_path / "vault.json")
    assert vault.is_set_up() is False

    vault.setup("correct horse battery staple")

    assert vault.is_set_up() is True


def test_recovery_key_is_never_stored_in_plaintext_in_the_vault_file(tmp_path):
    vault_path = tmp_path / "vault.json"
    vault = Vault(vault_path)
    recovery_key = vault.setup("correct horse battery staple")

    on_disk = vault_path.read_text()

    assert recovery_key not in on_disk


def test_valid_json_missing_expected_fields_raises_vault_corrupted(tmp_path):
    vault_path = tmp_path / "vault.json"
    vault = Vault(vault_path)
    vault.setup("correct horse battery staple")

    incomplete = json.loads(vault_path.read_text())
    del incomplete["wrapped_key_by_recovery"]
    vault_path.write_text(json.dumps(incomplete))

    with pytest.raises(VaultCorrupted):
        vault.unlock("correct horse battery staple")


def test_data_key_encrypts_and_decrypts_arbitrary_data(tmp_path):
    vault = Vault(tmp_path / "vault.json")
    vault.setup("correct horse battery staple")
    data_key = vault.unlock("correct horse battery staple")

    fernet = Fernet(data_key)
    plaintext = b"sensitive device config data: enable secret 5 $1$abc$def"
    ciphertext = fernet.encrypt(plaintext)

    assert fernet.decrypt(ciphertext) == plaintext
    assert b"sensitive" not in ciphertext
    assert b"enable secret" not in ciphertext


def test_concurrent_setup_has_exactly_one_winner(tmp_path):
    vault = Vault(tmp_path / "vault.json")

    def try_setup(password: str) -> str | Exception:
        try:
            return vault.setup(password)
        except VaultAlreadySetUp as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(try_setup, ["password one!!", "password two!!"]))

    successes = [r for r in results if isinstance(r, str)]
    failures = [r for r in results if isinstance(r, VaultAlreadySetUp)]
    assert len(successes) == 1
    assert len(failures) == 1

    # The file left behind must be internally consistent: the winning
    # recovery key still unlocks it.
    winning_recovery_key = successes[0]
    assert vault.unlock(winning_recovery_key)


def test_corrupted_vault_file_raises_a_clear_error_instead_of_crashing(tmp_path):
    vault_path = tmp_path / "vault.json"
    vault = Vault(vault_path)
    vault.setup("correct horse battery staple")

    vault_path.write_text("{not valid json")

    with pytest.raises(VaultCorrupted):
        vault.unlock("correct horse battery staple")


def test_setup_never_leaves_a_partial_file_visible(tmp_path):
    vault_path = tmp_path / "vault.json"
    vault = Vault(vault_path)
    vault.setup("correct horse battery staple")

    # The file that exists must always be fully valid JSON with all fields,
    # never a temp/partial artifact.
    record = json.loads(vault_path.read_text())
    assert set(record.keys()) == {
        "password_salt",
        "wrapped_key_by_password",
        "recovery_salt",
        "wrapped_key_by_recovery",
    }
    assert not list(tmp_path.glob("*.tmp"))
