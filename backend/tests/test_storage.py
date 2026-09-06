import pytest
from cryptography.fernet import Fernet

from app.storage import DeviceRecordCorrupted, DeviceStore


def test_save_and_get_roundtrip(tmp_path):
    store = DeviceStore(tmp_path / "devices.db")
    fernet = Fernet(Fernet.generate_key())

    device_id = store.save({"hello": "world"}, encrypt=fernet.encrypt)

    assert store.get(device_id, decrypt=fernet.decrypt) == {"hello": "world"}


def test_get_returns_none_for_missing_device(tmp_path):
    store = DeviceStore(tmp_path / "devices.db")
    fernet = Fernet(Fernet.generate_key())

    assert store.get("does-not-exist", decrypt=fernet.decrypt) is None


def test_get_raises_clear_error_on_wrong_key(tmp_path):
    store = DeviceStore(tmp_path / "devices.db")
    right_key = Fernet(Fernet.generate_key())
    wrong_key = Fernet(Fernet.generate_key())

    device_id = store.save({"hello": "world"}, encrypt=right_key.encrypt)

    with pytest.raises(DeviceRecordCorrupted):
        store.get(device_id, decrypt=wrong_key.decrypt)


def test_list_all_returns_every_saved_record(tmp_path):
    store = DeviceStore(tmp_path / "devices.db")
    fernet = Fernet(Fernet.generate_key())

    id_a = store.save({"name": "a"}, encrypt=fernet.encrypt)
    id_b = store.save({"name": "b"}, encrypt=fernet.encrypt)

    records = dict(store.list_all(decrypt=fernet.decrypt))
    assert records == {id_a: {"name": "a"}, id_b: {"name": "b"}}


def test_list_all_skips_records_that_fail_to_decrypt(tmp_path):
    # A fleet-wide listing shouldn't fail entirely because one stored record
    # is unreadable -- it's skipped, the same fail-isolated stance bulk
    # upload takes toward one bad device in a batch.
    store = DeviceStore(tmp_path / "devices.db")
    right_key = Fernet(Fernet.generate_key())
    wrong_key = Fernet(Fernet.generate_key())

    good_id = store.save({"name": "good"}, encrypt=right_key.encrypt)
    store.save({"name": "unreadable"}, encrypt=wrong_key.encrypt)

    records = dict(store.list_all(decrypt=right_key.decrypt))
    assert records == {good_id: {"name": "good"}}
