"""API-boundary tests for the unknown-vendor training loop (ticket 08): no
internals mocked, everything driven through real HTTP endpoints against a
real (tmp_path) encrypted store -- same pattern as test_devices_api.py."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.rules import CIS_CONTROLS


@pytest.fixture
def authed_client(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app)
    client.post("/api/setup", json={"password": "correct horse battery staple"})
    client.post("/api/login", json={"credential": "correct horse battery staple"})
    return client


def _upload_unknown_vendor(client, config_text: str, vendor_hint: str = "acme_widgetos"):
    return client.post(
        "/api/devices",
        files={
            "config": ("running-config.txt", config_text.encode(), "text/plain"),
            "version_info": ("version.txt", b"Acme WidgetOS, v1.0\n", "text/plain"),
        },
        data={"vendor_hint": vendor_hint},
    )


UNKNOWN_CONFIG = (
    "hostname widget1\n"
    "! this is a comment, never queued\n"
    "\n"
    "secure-mode strict\n"
    "logging remote-collector on\n"
)


def test_training_queue_requires_authentication(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app)
    resp = client.get("/api/training/queue", params={"vendor": "acme_widgetos"})
    assert resp.status_code == 401


def test_training_mappings_requires_authentication(tmp_path):
    app = create_app(tmp_path)
    client = TestClient(app)
    resp = client.post(
        "/api/training/mappings",
        json={
            "vendor": "acme_widgetos",
            "line": "secure-mode strict",
            "fact_id": "ssh_version_2",
            "value": True,
        },
    )
    assert resp.status_code == 401


def test_unrecognized_lines_are_queued_for_the_right_vendor(authed_client):
    resp = _upload_unknown_vendor(authed_client, UNKNOWN_CONFIG)
    assert resp.status_code == 200

    queue_resp = authed_client.get(
        "/api/training/queue", params={"vendor": "acme_widgetos"}
    )
    assert queue_resp.status_code == 200
    lines = queue_resp.json()["lines"]
    assert "secure-mode strict" in lines
    assert "logging remote-collector on" in lines
    assert "hostname widget1" in lines
    # Blank lines and comment lines never make it into the queue.
    assert "! this is a comment, never queued" not in lines
    assert "" not in lines

    # A different vendor's queue is unaffected.
    other_resp = authed_client.get(
        "/api/training/queue", params={"vendor": "someone_else"}
    )
    assert other_resp.json()["lines"] == []


def test_duplicate_lines_across_devices_are_deduped_in_the_queue(authed_client):
    _upload_unknown_vendor(authed_client, UNKNOWN_CONFIG)
    _upload_unknown_vendor(authed_client, UNKNOWN_CONFIG)  # same vendor, same lines

    queue_resp = authed_client.get(
        "/api/training/queue", params={"vendor": "acme_widgetos"}
    )
    lines = queue_resp.json()["lines"]
    assert lines.count("secure-mode strict") == 1


def test_mapping_with_unknown_fact_id_is_rejected(authed_client):
    resp = authed_client.post(
        "/api/training/mappings",
        json={
            "vendor": "acme_widgetos",
            "line": "secure-mode strict",
            "fact_id": "not_a_real_fact",
            "value": True,
        },
    )
    assert resp.status_code == 400


def test_confirming_a_mapping_creates_a_rule_and_clears_the_queue(authed_client):
    _upload_unknown_vendor(authed_client, UNKNOWN_CONFIG)

    confirm_resp = authed_client.post(
        "/api/training/mappings",
        json={
            "vendor": "acme_widgetos",
            "line": "secure-mode strict",
            "fact_id": "ssh_version_2",
            "value": True,
        },
    )
    assert confirm_resp.status_code == 200

    queue_resp = authed_client.get(
        "/api/training/queue", params={"vendor": "acme_widgetos"}
    )
    lines = queue_resp.json()["lines"]
    assert "secure-mode strict" not in lines
    # Everything else this vendor's config didn't explain is still queued.
    assert "logging remote-collector on" in lines


def test_confirmed_rule_is_applied_deterministically_on_next_upload(authed_client):
    _upload_unknown_vendor(authed_client, UNKNOWN_CONFIG)
    authed_client.post(
        "/api/training/mappings",
        json={
            "vendor": "acme_widgetos",
            "line": "secure-mode strict",
            "fact_id": "ssh_version_2",
            "value": True,
        },
    )

    # Re-upload the same vendor's config: no further manual step needed --
    # the mapped line is no longer queued, and the fact it controls now flows
    # through as True instead of the fail-safe False default.
    resp = _upload_unknown_vendor(authed_client, UNKNOWN_CONFIG)
    assert resp.status_code == 200
    findings = {f["control_id"]: f for f in resp.json()["findings"]["CIS"]}
    assert findings["CIS-4.1"]["status"] == "pass"  # ssh_version_2 now True

    queue_resp = authed_client.get(
        "/api/training/queue", params={"vendor": "acme_widgetos"}
    )
    assert "secure-mode strict" not in queue_resp.json()["lines"]


def test_trained_vendor_findings_have_same_shape_as_builtin_vendor_findings(
    authed_client,
):
    resp = _upload_unknown_vendor(authed_client, UNKNOWN_CONFIG)
    body = resp.json()

    # Same multi-framework machinery as a Cisco upload: every framework
    # present, every control accounted for, no separate code path.
    for framework, findings in body["findings"].items():
        assert len(findings) == len(CIS_CONTROLS)
        for finding in findings:
            assert finding["framework"] == framework
            assert finding["control_id"]
            assert finding["severity"] in {"low", "medium", "high"}
            assert finding["status"] in {"pass", "fail"}

    assert len(body["iso_evidence"]) > 0


def test_falls_back_to_unknown_vendor_label_with_no_hint(authed_client):
    resp = authed_client.post(
        "/api/devices",
        files={
            "config": ("running-config.txt", UNKNOWN_CONFIG.encode(), "text/plain"),
            "version_info": ("version.txt", b"Acme WidgetOS, v1.0\n", "text/plain"),
        },
    )
    assert resp.status_code == 200

    queue_resp = authed_client.get("/api/training/queue", params={"vendor": "unknown"})
    assert "secure-mode strict" in queue_resp.json()["lines"]
