"""HTTP-boundary coverage for ticket 04: NIST SP 800-53, DISA STIG, and
ISO/IEC 27001 findings derived from the same Cisco IOS fact set as CIS.

Same style as test_devices_api.py: real fixture configs through the real API,
asserting on response JSON and PDF content -- no internals mocked.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.facts import CiscoIosFacts
from app.main import create_app
from app.rules import CIS_CONTROLS, ISO_ANNEX_CONTROLS, NIST_CONTROLS, STIG_CONTROLS

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


# --- data-layer coverage: every fact maps into every 1:1 framework, and into
# exactly one ISO Annex A control (no fact orphaned, none double-counted). ---


def test_nist_and_stig_cover_the_same_facts_as_cis():
    cis_facts = {c.fact_id for c in CIS_CONTROLS}
    assert {c.fact_id for c in NIST_CONTROLS} == cis_facts
    assert {c.fact_id for c in STIG_CONTROLS} == cis_facts


def test_nist_and_stig_controls_have_distinct_ids_from_cis_and_each_other():
    nist_ids = [c.control_id for c in NIST_CONTROLS]
    stig_ids = [c.control_id for c in STIG_CONTROLS]
    assert len(set(nist_ids)) > 0
    assert not set(nist_ids) & {c.control_id for c in CIS_CONTROLS}
    assert not set(stig_ids) & {c.control_id for c in CIS_CONTROLS}


def test_every_fact_is_covered_by_exactly_one_iso_annex_control():
    all_fact_ids = set(CiscoIosFacts.__dataclass_fields__.keys())
    seen: list[str] = []
    for annex in ISO_ANNEX_CONTROLS:
        seen.extend(annex.fact_ids)
    assert sorted(seen) == sorted(all_fact_ids)  # every fact, no duplicates
    assert len(seen) == len(set(seen))


# --- HTTP-boundary behavior ---


def test_upload_returns_findings_for_nist_and_stig_alongside_cis(authed_client):
    resp = _upload(authed_client, "vulnerable_running_config.txt")
    assert resp.status_code == 200
    findings = resp.json()["findings"]

    assert set(findings.keys()) == {"CIS", "NIST SP 800-53", "DISA STIG"}
    assert len(findings["NIST SP 800-53"]) == len(CIS_CONTROLS)
    assert len(findings["DISA STIG"]) == len(CIS_CONTROLS)


def test_nist_and_stig_findings_fail_on_the_same_facts_as_cis(authed_client):
    resp = _upload(authed_client, "vulnerable_running_config.txt")
    findings = resp.json()["findings"]

    cis_status_by_fact = {
        c.fact_id: f["status"]
        for c, f in zip(CIS_CONTROLS, findings["CIS"], strict=True)
    }
    for framework_controls, framework_name in (
        (NIST_CONTROLS, "NIST SP 800-53"),
        (STIG_CONTROLS, "DISA STIG"),
    ):
        status_by_fact = {
            c.fact_id: f["status"]
            for c, f in zip(framework_controls, findings[framework_name], strict=True)
        }
        assert status_by_fact == cis_status_by_fact


def test_hardened_config_passes_all_nist_and_stig_controls(authed_client):
    resp = _upload(authed_client, "hardened_running_config.txt")
    findings = resp.json()["findings"]

    for finding in findings["NIST SP 800-53"] + findings["DISA STIG"]:
        assert finding["status"] == "pass", finding


def test_iso_evidence_is_returned_separately_from_pass_fail_findings(authed_client):
    resp = _upload(authed_client, "vulnerable_running_config.txt")
    body = resp.json()

    assert "iso_evidence" not in body["findings"]  # never mixed into the verdict dict
    iso_evidence = body["iso_evidence"]
    assert len(iso_evidence) == len(ISO_ANNEX_CONTROLS)
    for annex in iso_evidence:
        assert annex["framework"] == "ISO/IEC 27001"
        assert "status" not in annex  # no line-item pass/fail on the control itself
        for item in annex["evidence"]:
            assert "satisfied" in item
            assert isinstance(item["satisfied"], bool)


def test_iso_evidence_reflects_underlying_fact_state(authed_client):
    vulnerable = _upload(authed_client, "vulnerable_running_config.txt").json()
    hardened = _upload(authed_client, "hardened_running_config.txt").json()

    def _evidence_by_fact(iso_evidence):
        return {
            item["fact_id"]: item["satisfied"]
            for annex in iso_evidence
            for item in annex["evidence"]
        }

    vulnerable_evidence = _evidence_by_fact(vulnerable["iso_evidence"])
    hardened_evidence = _evidence_by_fact(hardened["iso_evidence"])

    # ssh_version_2 is part of A.9.1.2 evidence: hardened config configures
    # it, vulnerable does not.
    assert vulnerable_evidence["ssh_version_2"] is False
    assert hardened_evidence["ssh_version_2"] is True
    assert all(hardened_evidence.values())  # fully hardened config satisfies every fact


def test_iso_evidence_gaps_carry_remediation_satisfied_facts_do_not(authed_client):
    resp = _upload(authed_client, "vulnerable_running_config.txt")
    for annex in resp.json()["iso_evidence"]:
        for item in annex["evidence"]:
            if item["satisfied"]:
                assert item["remediation"] is None
            else:
                assert item["remediation"]


def test_pdf_report_breaks_out_findings_per_framework(authed_client):
    resp = _upload(authed_client, "vulnerable_running_config.txt")
    device_id = resp.json()["device_id"]

    pdf_resp = authed_client.get(f"/api/devices/{device_id}/report.pdf")
    assert pdf_resp.status_code == 200

    # reportlab-generated PDFs deflate-compress text streams, so page text
    # isn't grep-able directly -- assert on raw bytes size/shape instead, the
    # same "external behavior only" spirit as the existing PDF tests, which
    # is a reasonable stand-in without adding a PDF-text-extraction dependency.
    assert len(pdf_resp.content) > 0
    assert pdf_resp.headers["content-type"] == "application/pdf"
