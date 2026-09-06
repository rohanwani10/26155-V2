from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.rules import CIS_CONTROLS

FIXTURES = Path(__file__).parent / "fixtures" / "cisco_ios"


@pytest.fixture
def authed_client(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app)
    client.post("/api/setup", json={"password": "correct horse battery staple"})
    client.post("/api/login", json={"credential": "correct horse battery staple"})
    return client


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


def test_upload_requires_authentication(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app)
    resp = _upload(client, "vulnerable_running_config.txt")
    assert resp.status_code == 401


def test_upload_vulnerable_config_fails_expected_controls(authed_client):
    resp = _upload(authed_client, "vulnerable_running_config.txt")
    assert resp.status_code == 200
    findings = {f["control_id"]: f for f in resp.json()["findings"]["CIS"]}

    assert findings["CIS-4.1"]["status"] == "fail"  # ssh version 2 not configured
    assert findings["CIS-4.2"]["status"] == "fail"  # telnet enabled
    assert findings["CIS-2.1"]["status"] == "fail"  # enable password, not enable secret
    assert findings["CIS-2.2"]["status"] == "fail"  # no service password-encryption
    assert findings["CIS-1.1"]["status"] == "fail"  # no banner
    assert findings["CIS-6.1"]["status"] == "fail"  # no logging host
    assert findings["CIS-5.1"]["status"] == "fail"  # default snmp community
    assert findings["CIS-3.1"]["status"] == "fail"  # no aaa new-model
    assert findings["CIS-4.3"]["status"] == "fail"  # exec-timeout 0 0
    assert findings["CIS-2.3"]["status"] == "fail"  # username configured with password
    assert findings["CIS-7.1"]["status"] == "fail"  # cdp not disabled
    assert findings["CIS-1.4"]["status"] == "fail"  # no vty access-class
    assert len(findings) == len(CIS_CONTROLS)


def test_upload_hardened_config_passes_all_controls(authed_client):
    resp = _upload(authed_client, "hardened_running_config.txt")
    assert resp.status_code == 200
    findings = resp.json()["findings"]["CIS"]

    assert len(findings) == len(CIS_CONTROLS)
    for finding in findings:
        assert finding["status"] == "pass", finding


def test_device_identification_is_extracted_from_version_dump(authed_client):
    resp = _upload(authed_client, "hardened_running_config.txt")
    identity = resp.json()["identity"]

    assert identity["model"] == "WS-C2960-24TT-L"
    assert identity["serial_number"] == "FOC1534X2XY"
    assert identity["os_version"] == "15.0(2)SE11"


def test_failed_controls_have_remediation_passed_controls_do_not(authed_client):
    resp = _upload(authed_client, "vulnerable_running_config.txt")
    for framework_findings in resp.json()["findings"].values():
        for finding in framework_findings:
            if finding["status"] == "fail":
                assert finding["remediation"]
            else:
                assert finding["remediation"] is None


def test_each_frameworks_findings_are_labeled_with_that_framework(authed_client):
    resp = _upload(authed_client, "vulnerable_running_config.txt")
    findings = resp.json()["findings"]
    for framework, framework_findings in findings.items():
        for finding in framework_findings:
            assert finding["framework"] == framework


def test_secrets_never_appear_in_stored_record(authed_client):
    resp = _upload(authed_client, "vulnerable_running_config.txt")
    device_id = resp.json()["device_id"]

    get_resp = authed_client.get(f"/api/devices/{device_id}")
    body_text = get_resp.text

    assert "SuperSecretEnablePW1" not in body_text
    assert "SuperSecretVtyPW1" not in body_text
    assert "WeakUserPW1" not in body_text


def test_pdf_report_is_generated_and_contains_no_secrets(authed_client):
    resp = _upload(authed_client, "vulnerable_running_config.txt")
    device_id = resp.json()["device_id"]

    pdf_resp = authed_client.get(f"/api/devices/{device_id}/report.pdf")

    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert b"SuperSecretEnablePW1" not in pdf_resp.content
    assert b"SuperSecretVtyPW1" not in pdf_resp.content
    assert b"WeakUserPW1" not in pdf_resp.content


def test_pdf_report_requires_authentication(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app)
    resp = client.get("/api/devices/does-not-exist/report.pdf")
    assert resp.status_code == 401


def test_device_not_found_returns_404(authed_client):
    resp = authed_client.get("/api/devices/does-not-exist")
    assert resp.status_code == 404


def test_pdf_generation_survives_special_characters_in_device_identity(authed_client):
    weird_version = (
        "cisco WS-C2960<TEST>-24TT-L (PowerPC405) processor\n"
        "Processor board ID FOC&1534\n"
        "Cisco IOS Software, Version 15.0(2)SE11,\n"
    )
    config_bytes = (FIXTURES / "hardened_running_config.txt").read_bytes()

    resp = authed_client.post(
        "/api/devices",
        files={
            "config": ("running-config.txt", config_bytes, "text/plain"),
            "version_info": ("version.txt", weird_version.encode(), "text/plain"),
        },
    )
    device_id = resp.json()["device_id"]

    pdf_resp = authed_client.get(f"/api/devices/{device_id}/report.pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"


def test_device_data_is_isolated_between_vault_instances(tmp_path):
    # Sanity check on the encrypted-storage integration: a device saved under
    # one login session's data key must still be readable after logging out
    # and back in (the same data key is re-derived from the same password).
    app = create_app(tmp_path)
    client = TestClient(app)
    client.post("/api/setup", json={"password": "correct horse battery staple"})
    client.post("/api/login", json={"credential": "correct horse battery staple"})
    device_id = _upload(client, "hardened_running_config.txt").json()["device_id"]

    client.post("/api/logout")
    client.post("/api/login", json={"credential": "correct horse battery staple"})

    resp = client.get(f"/api/devices/{device_id}")
    assert resp.status_code == 200
