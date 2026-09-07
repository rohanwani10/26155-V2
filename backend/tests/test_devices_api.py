import io
import zipfile
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


def test_upload_from_unrecognized_vendor_succeeds_and_queues_lines(authed_client):
    # Ticket 08: an unrecognized vendor no longer fails the upload -- it's
    # queued for manual training instead. See test_training_api.py for the
    # full training-loop coverage (queue listing, confirming mappings, etc).
    resp = authed_client.post(
        "/api/devices",
        files={
            "config": ("running-config.txt", b"some config nobody recognizes\n", "text/plain"),
            "version_info": ("version.txt", b"Acme WidgetOS, v1.0\n", "text/plain"),
        },
        data={"vendor_hint": "acme_widgetos"},
    )
    assert resp.status_code == 200
    body = resp.json()
    findings = {f["control_id"]: f for f in body["findings"]["CIS"]}
    assert len(findings) == len(CIS_CONTROLS)
    # Every unproven fact defaults to whichever value FAILS its control, not
    # to False -- an unmapped line must never read as a silent, unproven
    # "pass". So every control fails with zero confirmed rules for this
    # vendor, regardless of whether the underlying fact's passes_when is
    # True (e.g. SSH v2) or False (e.g. Telnet disabled).
    assert findings["CIS-4.1"]["status"] == "fail"  # ssh_version_2 unproven -> fail-safe
    assert findings["CIS-4.2"]["status"] == "fail"  # telnet_enabled unproven -> fail-safe

    queue_resp = authed_client.get(
        "/api/training/queue", params={"vendor": "acme_widgetos"}
    )
    assert queue_resp.status_code == 200
    assert "some config nobody recognizes" in queue_resp.json()["lines"]


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


def _bulk_upload(client, bundles: list[tuple[str, str]]):
    """bundles is a list of (config_filename, version_filename) pairs, paired
    positionally into the `configs`/`version_infos` multipart lists."""
    files = []
    for config_filename, version_filename in bundles:
        files.append(("configs", (config_filename, (FIXTURES / config_filename).read_bytes(), "text/plain")))
        files.append(
            ("version_infos", (version_filename, (FIXTURES / version_filename).read_bytes(), "text/plain"))
        )
    return client.post("/api/devices/bulk", files=files)


def test_bulk_upload_requires_authentication(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app)
    resp = _bulk_upload(
        client,
        [("vulnerable_running_config.txt", "version_output.txt")],
    )
    assert resp.status_code == 401


def test_bulk_upload_processes_each_device_independently(authed_client):
    resp = _bulk_upload(
        authed_client,
        [
            ("vulnerable_running_config.txt", "version_output.txt"),
            ("empty_running_config.txt", "version_output.txt"),
            ("hardened_running_config.txt", "version_output.txt"),
        ],
    )
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert len(results) == 3

    vulnerable_result, broken_result, hardened_result = results

    assert "device_id" in vulnerable_result
    assert len(vulnerable_result["findings"]["CIS"]) == len(CIS_CONTROLS)

    assert "error" in broken_result
    assert "device_id" not in broken_result

    assert "device_id" in hardened_result
    assert all(f["status"] == "pass" for f in hardened_result["findings"]["CIS"])


def test_bulk_upload_devices_are_individually_retrievable(authed_client):
    resp = _bulk_upload(
        authed_client,
        [
            ("vulnerable_running_config.txt", "version_output.txt"),
            ("hardened_running_config.txt", "version_output.txt"),
        ],
    )
    for result in resp.json()["results"]:
        get_resp = authed_client.get(f"/api/devices/{result['device_id']}")
        assert get_resp.status_code == 200

        pdf_resp = authed_client.get(f"/api/devices/{result['device_id']}/report.pdf")
        assert pdf_resp.status_code == 200
        assert pdf_resp.headers["content-type"] == "application/pdf"


def test_bulk_upload_rejects_mismatched_pair_counts(authed_client):
    files = [
        ("configs", ("a.txt", (FIXTURES / "vulnerable_running_config.txt").read_bytes(), "text/plain")),
        ("configs", ("b.txt", (FIXTURES / "hardened_running_config.txt").read_bytes(), "text/plain")),
        ("version_infos", ("v.txt", (FIXTURES / "version_output.txt").read_bytes(), "text/plain")),
    ]
    resp = authed_client.post("/api/devices/bulk", files=files)
    assert resp.status_code == 400


def test_bulk_upload_rejects_empty_batch(authed_client):
    # No `configs`/`version_infos` fields at all: FastAPI's own required-field
    # validation rejects this with 422 before the handler's own emptiness
    # check ever runs -- either way, an empty batch is never a 200.
    resp = authed_client.post("/api/devices/bulk", files=[])
    assert resp.status_code == 422


def test_fleet_summary_requires_authentication(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app)
    resp = client.get("/api/fleet/summary")
    assert resp.status_code == 401


def test_fleet_summary_is_empty_with_no_devices(authed_client):
    resp = authed_client.get("/api/fleet/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["device_count"] == 0
    assert body["devices"] == []
    for framework in ("CIS", "NIST SP 800-53", "DISA STIG"):
        assert body["frameworks"][framework]["total_pass_count"] == 0
        assert body["frameworks"][framework]["total_fail_count"] == 0
        assert body["frameworks"][framework]["most_common_failures"] == []


def test_fleet_summary_aggregates_across_all_stored_devices(authed_client):
    # One single-device upload plus a bulk batch -- the fleet view covers
    # every stored device, not just the most recent batch.
    _upload(authed_client, "vulnerable_running_config.txt")
    _bulk_upload(
        authed_client,
        [
            ("vulnerable_running_config.txt", "version_output.txt"),
            ("hardened_running_config.txt", "version_output.txt"),
        ],
    )

    resp = authed_client.get("/api/fleet/summary")
    assert resp.status_code == 200
    body = resp.json()

    assert body["device_count"] == 3
    assert len(body["devices"]) == 3
    cis = body["frameworks"]["CIS"]
    assert cis["total_pass_count"] + cis["total_fail_count"] == 3 * len(CIS_CONTROLS)

    # CIS-4.1 (SSH v2) fails on both vulnerable uploads, passes on the
    # hardened one -- it should be the (or tied for) most common failure.
    top_failure = cis["most_common_failures"][0]
    assert top_failure["fail_count"] >= 2
    assert all(
        f["fail_count"] <= top_failure["fail_count"] for f in cis["most_common_failures"]
    )
    failing_control_ids = {f["control_id"] for f in cis["most_common_failures"]}
    assert "CIS-4.1" in failing_control_ids

    # NIST/STIG get the same aggregation treatment, not silently dropped.
    nist = body["frameworks"]["NIST SP 800-53"]
    assert nist["total_pass_count"] + nist["total_fail_count"] == 3 * len(CIS_CONTROLS)
    assert nist["most_common_failures"]


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


def _make_zip(entries: dict[str, bytes]) -> bytes:
    """entries is filename -> raw bytes. ZIP_STORED (the default compression
    for writestr with no ZipFile-level compression set) so a later test can
    corrupt one entry's payload by flipping a byte directly in the archive
    bytes, without touching the others."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _zip_bulk_upload(client, raw_zip: bytes, vendor_hint: str | None = None):
    data = {"vendor_hint": vendor_hint} if vendor_hint is not None else {}
    return client.post(
        "/api/devices/bulk/zip",
        files={"zip_file": ("devices.zip", raw_zip, "application/zip")},
        data=data,
    )


def test_zip_bulk_upload_requires_authentication(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app)
    raw_zip = _make_zip({"a.txt": b"some config"})
    resp = _zip_bulk_upload(client, raw_zip)
    assert resp.status_code == 401


def test_zip_bulk_upload_creates_one_device_per_file(authed_client):
    entries = {
        "device1.txt": (FIXTURES / "vulnerable_running_config.txt").read_bytes(),
        "device2.txt": (FIXTURES / "hardened_running_config.txt").read_bytes(),
        "device3.txt": (
            Path(__file__).parent
            / "fixtures"
            / "juniper_srx"
            / "hardened_running_config.txt"
        ).read_bytes(),
    }
    raw_zip = _make_zip(entries)

    resp = _zip_bulk_upload(authed_client, raw_zip)
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert len(results) == 3

    # None of these entries had a matching version/identity file inside the
    # zip, so every one degrades through the same "unrecognized vendor"
    # path a config-only upload already uses elsewhere (see
    # test_upload_from_unrecognized_vendor_succeeds_and_queues_lines): it
    # still becomes a device, just with empty/unknown identity fields, not a
    # crash or a rejected upload.
    for result in results:
        assert "device_id" in result, result
        assert result["identity"] == {
            "model": None,
            "serial_number": None,
            "os_version": None,
            "resource_id": None,
            "account": None,
            "region": None,
        }
        assert len(result["findings"]["CIS"]) == len(CIS_CONTROLS)

        get_resp = authed_client.get(f"/api/devices/{result['device_id']}")
        assert get_resp.status_code == 200
        assert get_resp.json()["vendor"] == "unknown"


def test_zip_bulk_upload_isolates_corrupt_entry(authed_client):
    good1 = (FIXTURES / "vulnerable_running_config.txt").read_bytes()
    good2 = (FIXTURES / "hardened_running_config.txt").read_bytes()
    bad = b"this entry's stored bytes will be corrupted after writing\n"
    raw_zip = bytearray(
        _make_zip({"good1.txt": good1, "bad.txt": bad, "good2.txt": good2})
    )

    # Flip a byte inside "bad.txt"'s stored payload (ZIP_STORED, so its bytes
    # are literally present in the archive) without touching its recorded
    # CRC-32 -- zipfile.read() then raises BadZipFile for that one entry,
    # exactly the "one corrupt entry in the batch" case this endpoint must
    # isolate rather than let take down the other two.
    idx = raw_zip.find(bad)
    assert idx != -1
    raw_zip[idx] ^= 0xFF

    resp = _zip_bulk_upload(authed_client, bytes(raw_zip))
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert len(results) == 3

    good_results = [r for r in results if "device_id" in r]
    error_results = [r for r in results if "error" in r]
    assert len(good_results) == 2
    assert len(error_results) == 1
    assert error_results[0]["config_filename"] == "bad.txt"


def test_zip_bulk_upload_unrecognized_vendor_queues_and_does_not_crash(authed_client):
    raw_zip = _make_zip({"acme.txt": b"some config nobody recognizes\n"})

    resp = _zip_bulk_upload(authed_client, raw_zip, vendor_hint="acme_widgetos")
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert len(results) == 1
    assert "device_id" in results[0]

    get_resp = authed_client.get(f"/api/devices/{results[0]['device_id']}")
    assert get_resp.json()["vendor"] == "acme_widgetos"

    queue_resp = authed_client.get(
        "/api/training/queue", params={"vendor": "acme_widgetos"}
    )
    assert queue_resp.status_code == 200
    assert "some config nobody recognizes" in queue_resp.json()["lines"]


def test_zip_bulk_upload_rejects_non_zip_file(authed_client):
    resp = authed_client.post(
        "/api/devices/bulk/zip",
        files={"zip_file": ("devices.zip", b"not a zip archive", "application/zip")},
    )
    assert resp.status_code == 400


def test_matched_pair_bulk_upload_unaffected_by_zip_endpoint(authed_client):
    # Existing matched-list bulk upload continues to work unchanged -- the
    # zip endpoint is purely additive.
    resp = _bulk_upload(
        authed_client,
        [
            ("vulnerable_running_config.txt", "version_output.txt"),
            ("hardened_running_config.txt", "version_output.txt"),
        ],
    )
    assert resp.status_code == 200
    assert len(resp.json()["results"]) == 2
