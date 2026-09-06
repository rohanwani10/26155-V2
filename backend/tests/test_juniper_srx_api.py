"""API-boundary tests for the Juniper SRX vendor path -- mirrors
test_devices_api.py's pattern (real fixture files through the HTTP API) so
the second vendor is proven end to end, not just at the parser unit level."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.rules import CIS_CONTROLS

FIXTURES = Path(__file__).parent / "fixtures" / "juniper_srx"


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


def test_juniper_upload_is_identified_as_juniper_srx_vendor(authed_client):
    resp = _upload(authed_client, "vulnerable_running_config.txt")
    assert resp.status_code == 200
    device_id = resp.json()["device_id"]

    get_resp = authed_client.get(f"/api/devices/{device_id}")
    assert get_resp.json()["vendor"] == "juniper_srx"


def test_device_identification_is_extracted_from_junos_version_dump(authed_client):
    resp = _upload(authed_client, "hardened_running_config.txt")
    identity = resp.json()["identity"]

    assert identity["model"] == "srx340"
    assert identity["serial_number"] == "JN123456AABC"
    assert identity["os_version"] == "21.2R3-S1.7"


def test_upload_vulnerable_config_fails_expected_controls(authed_client):
    resp = _upload(authed_client, "vulnerable_running_config.txt")
    assert resp.status_code == 200
    findings = {f["control_id"]: f for f in resp.json()["findings"]["CIS"]}

    assert findings["CIS-4.1"]["status"] == "fail"  # ssh protocol-version v2 not set
    assert findings["CIS-4.2"]["status"] == "fail"  # telnet enabled
    assert findings["CIS-2.1"]["status"] == "fail"  # root plain-text-password
    assert findings["CIS-2.2"]["status"] == "fail"  # plain-text-password present
    assert findings["CIS-1.1"]["status"] == "fail"  # no login message/announcement
    assert findings["CIS-6.1"]["status"] == "fail"  # no syslog host
    assert findings["CIS-5.1"]["status"] == "fail"  # default snmp community
    assert findings["CIS-3.1"]["status"] == "fail"  # no aaa authentication-order
    assert findings["CIS-4.3"]["status"] == "fail"  # no idle-timeout
    assert findings["CIS-2.3"]["status"] == "fail"  # local user has plain-text-password
    assert findings["CIS-7.1"]["status"] == "fail"  # lldp enabled
    assert len(findings) == len(CIS_CONTROLS)


def test_upload_hardened_config_passes_all_controls(authed_client):
    resp = _upload(authed_client, "hardened_running_config.txt")
    assert resp.status_code == 200
    findings = resp.json()["findings"]["CIS"]

    assert len(findings) == len(CIS_CONTROLS)
    for finding in findings:
        assert finding["status"] == "pass", finding


def test_hardened_config_passes_across_nist_and_stig_too(authed_client):
    resp = _upload(authed_client, "hardened_running_config.txt")
    findings = resp.json()["findings"]

    for framework in ("NIST SP 800-53", "DISA STIG"):
        assert len(findings[framework]) == len(CIS_CONTROLS)
        for finding in findings[framework]:
            assert finding["status"] == "pass", finding


def test_iso_evidence_is_produced_for_juniper_uploads(authed_client):
    resp = _upload(authed_client, "vulnerable_running_config.txt")
    iso_evidence = resp.json()["iso_evidence"]

    assert iso_evidence
    for annex in iso_evidence:
        assert annex["evidence"]


def test_failed_controls_use_junos_syntax_remediation_not_cisco(authed_client):
    resp = _upload(authed_client, "vulnerable_running_config.txt")
    findings = {f["control_id"]: f for f in resp.json()["findings"]["CIS"]}

    ssh_finding = findings["CIS-4.1"]
    assert ssh_finding["status"] == "fail"
    assert "ip ssh version 2" not in ssh_finding["remediation"]
    assert "set system services ssh protocol-version v2" in ssh_finding["remediation"]


def test_secrets_never_appear_in_stored_record(authed_client):
    resp = _upload(authed_client, "vulnerable_running_config.txt")
    device_id = resp.json()["device_id"]

    get_resp = authed_client.get(f"/api/devices/{device_id}")
    body_text = get_resp.text

    assert "SuperSecretRootPW1" not in body_text
    assert "WeakUserPW1" not in body_text


def test_pdf_report_is_generated_and_contains_no_secrets(authed_client):
    resp = _upload(authed_client, "vulnerable_running_config.txt")
    device_id = resp.json()["device_id"]

    pdf_resp = authed_client.get(f"/api/devices/{device_id}/report.pdf")

    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert b"SuperSecretRootPW1" not in pdf_resp.content
    assert b"WeakUserPW1" not in pdf_resp.content
