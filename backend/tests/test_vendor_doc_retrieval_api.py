"""API-boundary tests for ticket 11's online vendor-doc retrieval and
knowledge promotion, layered on ticket 09's GET /api/training/suggestions.
Same style as test_training_suggestions_api.py -- real HTTP calls,
FakeLlmClient + FakeDocFetcher injected via create_app for determinism. No
test in this file (or anywhere else) makes a real network call: FakeDocFetcher
never touches the network, and the one direct HttpDocFetcher test below
proves a non-allowlisted host is rejected before httpx is ever invoked (by
patching httpx.get to raise if called)."""

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.doc_fetcher import FakeDocFetcher, HttpDocFetcher, is_allowlisted_host
from app.llm import FakeLlmClient
from app.main import create_app
from app.vendor_knowledge_store import VendorKnowledgeStore

GOOD_RESPONSE = (
    "FACT_ID: ssh_version_2\nVALUE: true\nRATIONALE: line enables SSHv2 only."
)
DOC_TEXT = "Cisco IOS official docs: 'ssh very-strict-mode' enables SSH version 2 only."

# cisco_ios is a real entry in data/vendor_doc_allowlist.json (www.cisco.com);
# acme_widgetos (used by ticket 09's tests) deliberately is not, so those
# tests exercise the "unknown/untrained vendor -> no enrichment" path already.
ALLOWLISTED_VENDOR = "cisco_ios"
LINE = "ssh very-strict-mode"


def _make_app(tmp_path: Path, llm_client=None, doc_fetcher=None):
    return create_app(
        tmp_path,
        llm_client=llm_client or FakeLlmClient(),
        doc_fetcher=doc_fetcher or FakeDocFetcher(response=None),
    )


def _authed_client(tmp_path: Path, llm_client=None, doc_fetcher=None):
    app = _make_app(tmp_path, llm_client, doc_fetcher)
    client = TestClient(app)
    client.post("/api/setup", json={"password": "correct horse battery staple"})
    client.post("/api/login", json={"credential": "correct horse battery staple"})
    return client


def _suggest(client, vendor: str = ALLOWLISTED_VENDOR, line: str = LINE):
    return client.get(
        "/api/training/suggestions", params={"vendor": vendor, "line": line}
    )


def test_successful_fetch_verifies_and_promotes_knowledge(tmp_path):
    llm = FakeLlmClient(interpret_response=GOOD_RESPONSE, verify_result=True)
    fetcher = FakeDocFetcher(response=DOC_TEXT)
    client = _authed_client(tmp_path, llm, fetcher)

    resp = _suggest(client)
    assert resp.status_code == 200
    body = resp.json()
    assert body["verified"] is True
    assert body["doc_enrichment_used"] is True
    assert fetcher.fetched_urls == ["https://www.cisco.com/"]

    # Promoted knowledge is queryable, independent of the API response shape.
    store = VendorKnowledgeStore(tmp_path, llm)
    results = store.query(ALLOWLISTED_VENDOR, LINE)
    assert results
    assert results[0]["metadata"]["fact_id"] == "ssh_version_2"
    assert results[0]["metadata"]["source_url"] == "https://www.cisco.com/"


def test_offline_fetch_behaves_exactly_like_ticket_09(tmp_path):
    llm = FakeLlmClient(interpret_response=GOOD_RESPONSE, verify_result=True)
    fetcher = FakeDocFetcher(response=None)  # simulates offline / unavailable
    client = _authed_client(tmp_path, llm, fetcher)

    resp = _suggest(client)
    assert resp.status_code == 200
    body = resp.json()
    assert body["fact_id"] == "ssh_version_2"
    assert body["value"] is True
    assert body["verified"] is True
    assert body["doc_enrichment_used"] is False

    store = VendorKnowledgeStore(tmp_path, llm)
    assert store.query(ALLOWLISTED_VENDOR, LINE) == []


def test_unknown_vendor_gets_no_enrichment_attempt(tmp_path):
    # No allowlist entry at all -- urls_for_vendor returns [], so
    # FakeDocFetcher.fetch is never even called.
    llm = FakeLlmClient(interpret_response=GOOD_RESPONSE, verify_result=True)
    fetcher = FakeDocFetcher(response=DOC_TEXT)
    client = _authed_client(tmp_path, llm, fetcher)

    resp = _suggest(client, vendor="acme_widgetos", line="secure-mode strict")
    assert resp.status_code == 200
    assert resp.json()["doc_enrichment_used"] is False
    assert fetcher.fetched_urls == []


def test_fetch_never_attempted_for_a_non_allowlisted_host():
    with patch("app.doc_fetcher.httpx.get") as mock_get:
        result = HttpDocFetcher().fetch("https://evil-untrusted-vendor-site.com/docs")
    assert result is None
    mock_get.assert_not_called()

    assert is_allowlisted_host("https://evil-untrusted-vendor-site.com/docs") is False
    assert is_allowlisted_host("https://www.cisco.com/") is True


def test_verify_failure_blocks_promotion_even_after_a_successful_fetch(tmp_path):
    llm = FakeLlmClient(interpret_response=GOOD_RESPONSE, verify_result=False)
    fetcher = FakeDocFetcher(response=DOC_TEXT)
    client = _authed_client(tmp_path, llm, fetcher)

    resp = _suggest(client)
    assert resp.status_code == 200
    assert resp.json()["doc_enrichment_used"] is False

    store = VendorKnowledgeStore(tmp_path, llm)
    assert store.query(ALLOWLISTED_VENDOR, LINE) == []


def test_promoted_knowledge_persists_and_is_used_on_a_later_request_without_refetching(
    tmp_path,
):
    llm = FakeLlmClient(interpret_response=GOOD_RESPONSE, verify_result=True)
    first_client = _authed_client(tmp_path, llm, FakeDocFetcher(response=DOC_TEXT))
    first_resp = _suggest(first_client)
    assert first_resp.json()["doc_enrichment_used"] is True

    store = VendorKnowledgeStore(tmp_path, llm)
    assert store.query(ALLOWLISTED_VENDOR, LINE)

    # A brand new app/session against the same data_dir, this time offline --
    # the earlier promotion should still be there and get folded in, even
    # though this request never fetches anything fresh.
    offline_fetcher = FakeDocFetcher(response=None)
    second_client = _authed_client(tmp_path, llm, offline_fetcher)
    second_resp = _suggest(second_client)
    assert second_resp.status_code == 200
    assert second_resp.json()["doc_enrichment_used"] is False
    assert offline_fetcher.fetched_urls == ["https://www.cisco.com/"]  # it did try


def test_enrichment_never_creates_a_rule_or_touches_the_queue(tmp_path):
    llm = FakeLlmClient(interpret_response=GOOD_RESPONSE, verify_result=True)
    client = _authed_client(tmp_path, llm, FakeDocFetcher(response=DOC_TEXT))

    before = client.get(
        "/api/training/queue", params={"vendor": ALLOWLISTED_VENDOR}
    ).json()["lines"]

    _suggest(client)

    after = client.get(
        "/api/training/queue", params={"vendor": ALLOWLISTED_VENDOR}
    ).json()["lines"]
    assert after == before == []
