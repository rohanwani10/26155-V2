from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.llm import FakeLlmClient
from app.main import create_app

FIXTURES = Path(__file__).parent / "fixtures" / "cisco_ios"


def _make_app(tmp_path, llm_client=None):
    return create_app(tmp_path, llm_client=llm_client or FakeLlmClient())


def _authed_client(tmp_path, llm_client=None):
    app = _make_app(tmp_path, llm_client)
    client = TestClient(app)
    client.post("/api/setup", json={"password": "correct horse battery staple"})
    client.post("/api/login", json={"credential": "correct horse battery staple"})
    return client


@pytest.fixture
def fake_llm():
    return FakeLlmClient()


@pytest.fixture
def authed_client(tmp_path, fake_llm):
    return _authed_client(tmp_path, fake_llm)


def _upload(client, config_filename: str, version_filename: str = "version_output.txt"):
    config_bytes = (FIXTURES / config_filename).read_bytes()
    version_bytes = (FIXTURES / version_filename).read_bytes()
    return client.post(
        "/api/devices",
        files={
            "config": ("running-config.txt", config_bytes, "text/plain"),
            "version_info": ("version.txt", version_bytes, "text/plain"),
        },
    )


def test_chat_requires_authentication(tmp_path):
    client = TestClient(_make_app(tmp_path))
    resp = client.post("/api/devices/does-not-exist/chat", json={"question": "why?"})
    assert resp.status_code == 401


def test_chat_history_requires_authentication(tmp_path):
    client = TestClient(_make_app(tmp_path))
    resp = client.get("/api/devices/does-not-exist/chat")
    assert resp.status_code == 401


def test_chat_returns_404_for_unknown_device(authed_client):
    resp = authed_client.post(
        "/api/devices/does-not-exist/chat", json={"question": "why?"}
    )
    assert resp.status_code == 404


def test_chat_history_returns_404_for_unknown_device(authed_client):
    resp = authed_client.get("/api/devices/does-not-exist/chat")
    assert resp.status_code == 404


def test_chat_answer_cites_a_real_control_from_the_devices_findings(authed_client):
    upload_resp = _upload(authed_client, "vulnerable_running_config.txt")
    device_id = upload_resp.json()["device_id"]
    upload_body = upload_resp.json()
    real_control_ids = {
        f["control_id"]
        for framework_findings in upload_body["findings"].values()
        for f in framework_findings
    }
    real_control_ids |= {evidence["control_id"] for evidence in upload_body["iso_evidence"]}

    resp = authed_client.post(
        f"/api/devices/{device_id}/chat",
        json={"question": "Why did the SSH check fail?"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["answer"] == "Fake interpreted answer."
    assert body["citations"], "expected at least one citation"
    for citation in body["citations"]:
        assert citation["control_id"] in real_control_ids


def test_two_devices_chat_indexes_are_isolated(authed_client):
    # Vulnerable and hardened fixtures share the same set of CIS control_ids
    # but disagree on status for most of them -- so if a citation ever came
    # from the *other* device's collection, its (control_id, status) pair
    # would mismatch that device's own actual findings.
    vulnerable_resp = _upload(authed_client, "vulnerable_running_config.txt")
    hardened_resp = _upload(authed_client, "hardened_running_config.txt")
    vulnerable_id = vulnerable_resp.json()["device_id"]
    hardened_id = hardened_resp.json()["device_id"]

    vulnerable_status_by_control = {
        f["control_id"]: f["status"] for f in vulnerable_resp.json()["findings"]["CIS"]
    }
    hardened_status_by_control = {
        f["control_id"]: f["status"] for f in hardened_resp.json()["findings"]["CIS"]
    }
    # Sanity: the fixtures really do disagree on at least one control, or
    # this test wouldn't be able to detect cross-device leakage at all.
    assert vulnerable_status_by_control != hardened_status_by_control

    vulnerable_chat = authed_client.post(
        f"/api/devices/{vulnerable_id}/chat", json={"question": "What failed?"}
    ).json()
    hardened_chat = authed_client.post(
        f"/api/devices/{hardened_id}/chat", json={"question": "What failed?"}
    ).json()

    assert vulnerable_chat["citations"], "expected at least one citation"
    assert hardened_chat["citations"], "expected at least one citation"

    for citation in vulnerable_chat["citations"]:
        if citation["control_id"] in vulnerable_status_by_control:
            assert citation["status"] == vulnerable_status_by_control[citation["control_id"]]
    for citation in hardened_chat["citations"]:
        if citation["control_id"] in hardened_status_by_control:
            assert citation["status"] == hardened_status_by_control[citation["control_id"]]


def test_verify_failure_returns_safe_fallback_not_the_raw_draft(tmp_path):
    llm = FakeLlmClient(interpret_response="This is an unverified draft.", verify_result=False)
    client = _authed_client(tmp_path, llm)
    device_id = _upload(client, "vulnerable_running_config.txt").json()["device_id"]

    resp = client.post(
        f"/api/devices/{device_id}/chat", json={"question": "How do I fix this?"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "unable to verify" in body["answer"].lower()
    assert body["answer"] != "This is an unverified draft."
    assert body["citations"] == []


def test_chat_history_persists_across_app_restart(tmp_path):
    llm = FakeLlmClient()
    client = _authed_client(tmp_path, llm)
    device_id = _upload(client, "vulnerable_running_config.txt").json()["device_id"]
    client.post(f"/api/devices/{device_id}/chat", json={"question": "Why did SSH fail?"})

    history_before = client.get(f"/api/devices/{device_id}/chat").json()["history"]
    assert len(history_before) == 1

    # Simulate an app restart: a brand new app/session pointed at the same
    # data_dir must see the same accumulated history.
    restarted_client = _authed_client(tmp_path, FakeLlmClient())
    history_after = restarted_client.get(f"/api/devices/{device_id}/chat").json()[
        "history"
    ]
    assert history_after == history_before

    restarted_client.post(
        f"/api/devices/{device_id}/chat", json={"question": "How do I fix it?"}
    )
    history_final = restarted_client.get(f"/api/devices/{device_id}/chat").json()[
        "history"
    ]
    assert len(history_final) == 2
    assert history_final[0] == history_before[0]


def test_no_secret_shaped_value_ever_appears_in_indexed_chunk_or_chat_response(
    authed_client,
):
    device_id = _upload(authed_client, "vulnerable_running_config.txt").json()[
        "device_id"
    ]
    resp = authed_client.post(
        f"/api/devices/{device_id}/chat",
        json={"question": "What passwords are configured?"},
    )
    body_text = resp.text
    assert "SuperSecretEnablePW1" not in body_text
    assert "SuperSecretVtyPW1" not in body_text
    assert "WeakUserPW1" not in body_text

    history_text = authed_client.get(f"/api/devices/{device_id}/chat").text
    assert "SuperSecretEnablePW1" not in history_text
    assert "SuperSecretVtyPW1" not in history_text
    assert "WeakUserPW1" not in history_text
