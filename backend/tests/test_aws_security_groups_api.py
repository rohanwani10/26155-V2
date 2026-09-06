import base64
import re
import zlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.rules import CIS_CONTROLS

FIXTURES = Path(__file__).parent / "fixtures" / "aws_security_groups"


def _pdf_text_bytes(pdf_bytes: bytes) -> bytes:
    """reportlab's content streams are ASCII85-then-Flate encoded by default,
    so a plain substring search over the raw PDF bytes won't find rendered
    text. Pull every stream/endstream block, undo both encodings, and search
    the decoded bytes instead."""
    decoded = b""
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", pdf_bytes, re.DOTALL):
        raw = match.group(1).rstrip(b"\r\n")
        if raw.endswith(b"~>"):
            raw = raw[:-2]
        try:
            raw = base64.a85decode(raw)
        except ValueError:
            pass
        try:
            decoded += zlib.decompress(raw)
        except zlib.error:
            decoded += raw
    return decoded


@pytest.fixture
def authed_client(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app)
    client.post("/api/setup", json={"password": "correct horse battery staple"})
    client.post("/api/login", json={"credential": "correct horse battery staple"})
    return client


def _upload(client, config_filename: str, version_filename: str = "identity_metadata.json"):
    config_bytes = (FIXTURES / config_filename).read_bytes()
    version_bytes = (FIXTURES / version_filename).read_bytes()
    return client.post(
        "/api/devices",
        files={
            "config": ("security-group.json", config_bytes, "application/json"),
            "version_info": ("identity.json", version_bytes, "application/json"),
        },
    )


def test_upload_is_recognized_as_aws_security_groups_vendor(authed_client):
    resp = _upload(authed_client, "hardened_security_group.json")
    assert resp.status_code == 200

    device_id = resp.json()["device_id"]
    record = authed_client.get(f"/api/devices/{device_id}").json()
    assert record["vendor"] == "aws_security_groups"


def test_upload_vulnerable_security_group_fails_expected_controls(authed_client):
    resp = _upload(authed_client, "vulnerable_security_group.json")
    assert resp.status_code == 200
    findings = {f["control_id"]: f for f in resp.json()["findings"]["CIS"]}

    assert findings["CIS-4.2"]["status"] == "fail"  # telnet_enabled: TCP 23 open to 0.0.0.0/0
    assert findings["CIS-4.1"]["status"] == "fail"  # ssh_version_2 repurposed: TCP 22 open
    assert findings["CIS-4.7"]["status"] == "fail"  # http_server_enabled: TCP 80 open
    assert findings["CIS-6.1"]["status"] == "fail"  # logging_host_configured: no flow logs
    assert findings["CIS-1.4"]["status"] == "fail"  # vty_access_class_configured: mgmt port open
    assert len(findings) == len(CIS_CONTROLS)


def test_upload_hardened_security_group_passes_all_controls(authed_client):
    resp = _upload(authed_client, "hardened_security_group.json")
    assert resp.status_code == 200
    findings = resp.json()["findings"]["CIS"]

    assert len(findings) == len(CIS_CONTROLS)
    for finding in findings:
        assert finding["status"] == "pass", finding


def test_findings_are_produced_across_all_technical_frameworks(authed_client):
    resp = _upload(authed_client, "vulnerable_security_group.json")
    findings = resp.json()["findings"]
    for framework in ("CIS", "NIST SP 800-53", "DISA STIG"):
        assert len(findings[framework]) == len(CIS_CONTROLS)


def test_iso_evidence_is_produced(authed_client):
    resp = _upload(authed_client, "vulnerable_security_group.json")
    iso_evidence = resp.json()["iso_evidence"]
    assert iso_evidence
    all_fact_ids = {fact_id for annex in iso_evidence for fact_id in (e["fact_id"] for e in annex["evidence"])}
    assert "telnet_enabled" in all_fact_ids


def test_device_identity_uses_cloud_native_fields(authed_client):
    resp = _upload(authed_client, "hardened_security_group.json")
    identity = resp.json()["identity"]

    assert identity["resource_id"] == "sg-0f9e8d7c6b5a43210"
    assert identity["account"] == "123456789012"
    assert identity["region"] == "us-east-1"
    assert identity["model"] is None
    assert identity["serial_number"] is None
    assert identity["os_version"] is None


def test_remediation_overrides_apply_to_vendor_specific_findings(authed_client):
    resp = _upload(authed_client, "vulnerable_security_group.json")
    findings = {f["control_id"]: f for f in resp.json()["findings"]["CIS"]}
    assert "aws ec2 revoke-security-group-ingress" in findings["CIS-4.2"]["remediation"]


def test_pdf_report_generates_and_shows_cloud_native_identity(authed_client):
    resp = _upload(authed_client, "hardened_security_group.json")
    device_id = resp.json()["device_id"]

    pdf_resp = authed_client.get(f"/api/devices/{device_id}/report.pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    text = _pdf_text_bytes(pdf_resp.content)
    assert b"sg-0f9e8d7c6b5a43210" in text
    assert b"123456789012" in text
    assert b"us-east-1" in text
    # No physical-device fields for a target that never had them.
    assert b"Model:" not in text
    assert b"Serial Number:" not in text


def test_pdf_report_for_cisco_device_is_unaffected(authed_client):
    # Regression guard: the report.py identity branch must not change the
    # existing Cisco (physical-device) output shape.
    cisco_fixtures = Path(__file__).parent / "fixtures" / "cisco_ios"
    resp = authed_client.post(
        "/api/devices",
        files={
            "config": (
                "running-config.txt",
                (cisco_fixtures / "hardened_running_config.txt").read_bytes(),
                "text/plain",
            ),
            "version_info": (
                "version.txt",
                (cisco_fixtures / "version_output.txt").read_bytes(),
                "text/plain",
            ),
        },
    )
    device_id = resp.json()["device_id"]

    pdf_resp = authed_client.get(f"/api/devices/{device_id}/report.pdf")
    assert pdf_resp.status_code == 200
    text = _pdf_text_bytes(pdf_resp.content)
    assert b"Model:" in text
    assert b"Serial Number:" in text
    assert b"OS Version:" in text
    assert b"Resource ID:" not in text
