"""API-boundary tests for ticket 16's embedding-similarity pre-check ahead of
GET /api/training/suggestions. Same style as test_training_suggestions_api.py
-- real HTTP calls, FakeLlmClient injected via create_app for determinism.

FakeLlmClient.interpret_calls/verify_calls (see app/llm.py) stand in for a
spy/mock: the acceptance scenario asserts they never move for a line that
resolves via the embedding match.
"""

from pathlib import Path

from fastapi.testclient import TestClient

from app.llm import FakeLlmClient
from app.main import create_app

VENDOR = "acme_widgetos"


def _make_app(tmp_path: Path, llm_client=None):
    return create_app(tmp_path, llm_client=llm_client or FakeLlmClient())


def _authed_client(tmp_path: Path, llm_client=None):
    app = _make_app(tmp_path, llm_client)
    client = TestClient(app)
    client.post("/api/setup", json={"password": "correct horse battery staple"})
    client.post("/api/login", json={"credential": "correct horse battery staple"})
    return client


def _upload_unknown_vendor(client, config_text: str, vendor: str = VENDOR):
    return client.post(
        "/api/devices",
        files={
            "config": ("running-config.txt", config_text.encode(), "text/plain"),
            "version_info": ("version.txt", b"Acme WidgetOS, v1.0\n", "text/plain"),
        },
        data={"vendor_hint": vendor},
    )


def _confirm(client, line: str, fact_id: str, value: bool, vendor: str = VENDOR):
    resp = client.post(
        "/api/training/mappings",
        json={"vendor": vendor, "line": line, "fact_id": fact_id, "value": value},
    )
    assert resp.status_code == 200
    return resp


def test_similar_but_not_identical_line_resolves_via_embedding_without_llm(tmp_path):
    """The PRD's own acceptance scenario: train a line, then submit a
    similar-but-not-identical line (same command, different argument value)
    on a different device, and confirm it resolves via the embedding match
    with the LLM client never invoked."""
    llm = FakeLlmClient()
    client = _authed_client(tmp_path, llm)

    trained_config = "hostname widget1\nntp server 10.1.1.1\n"
    _upload_unknown_vendor(client, trained_config)
    _confirm(client, "ntp server 10.1.1.1", "logging_host_configured", True)

    # A different device, same vendor, same command but a different last
    # octet -- not byte-identical to the trained line.
    other_config = "hostname widget2\nntp server 10.1.1.2\n"
    _upload_unknown_vendor(client, other_config)

    assert llm.interpret_calls == 0
    assert llm.verify_calls == 0

    resp = client.get(
        "/api/training/suggestions",
        params={"vendor": VENDOR, "line": "ntp server 10.1.1.2"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["fact_id"] == "logging_host_configured"
    assert body["value"] is True
    assert body["verified"] is True

    # The whole point: no LLM call was made to produce this suggestion.
    assert llm.interpret_calls == 0
    assert llm.verify_calls == 0


def test_unrelated_line_falls_through_to_the_llm_path_unchanged(tmp_path):
    llm = FakeLlmClient(
        interpret_response=(
            "FACT_ID: telnet_enabled\nVALUE: false\nRATIONALE: disables telnet."
        ),
        verify_result=True,
    )
    client = _authed_client(tmp_path, llm)

    _upload_unknown_vendor(client, "hostname widget1\nntp server 10.1.1.1\n")
    _confirm(client, "ntp server 10.1.1.1", "logging_host_configured", True)

    resp = client.get(
        "/api/training/suggestions",
        params={"vendor": VENDOR, "line": "no service password-recovery"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["fact_id"] == "telnet_enabled"
    assert llm.interpret_calls == 1
    assert llm.verify_calls == 1


def test_embedding_match_is_scoped_to_vendor(tmp_path):
    llm = FakeLlmClient()
    client = _authed_client(tmp_path, llm)

    _upload_unknown_vendor(client, "hostname widget1\nntp server 10.1.1.1\n", vendor=VENDOR)
    _confirm(client, "ntp server 10.1.1.1", "logging_host_configured", True, vendor=VENDOR)

    # Same near-identical line, but a vendor with no confirmed mappings of
    # its own -- must not borrow another vendor's embedding match.
    resp = client.get(
        "/api/training/suggestions",
        params={"vendor": "other_vendor", "line": "ntp server 10.1.1.2"},
    )
    assert resp.status_code == 200
    # No confirmed mapping for other_vendor and FakeLlmClient's default
    # unparseable-ish interpret_response still runs the LLM path -- the
    # relevant assertion is simply that the LLM *was* invoked, i.e. the
    # embedding pre-check did not short-circuit across vendors.
    assert llm.interpret_calls == 1


def test_confirmed_mapping_is_embedded_immediately_not_lazily(tmp_path):
    """The mapping must be queryable via the embedding pre-check right after
    POST /api/training/mappings returns -- no separate indexing step."""
    llm = FakeLlmClient()
    client = _authed_client(tmp_path, llm)

    _upload_unknown_vendor(client, "hostname widget1\nntp server 10.1.1.1\n")
    _confirm(client, "ntp server 10.1.1.1", "logging_host_configured", True)

    resp = client.get(
        "/api/training/suggestions",
        params={"vendor": VENDOR, "line": "ntp server 10.1.1.1"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["fact_id"] == "logging_host_configured"
    assert body["value"] is True
    assert llm.interpret_calls == 0


def test_suggestion_from_embedding_match_is_never_auto_applied(tmp_path):
    llm = FakeLlmClient()
    client = _authed_client(tmp_path, llm)

    _upload_unknown_vendor(client, "hostname widget1\nntp server 10.1.1.1\n")
    _confirm(client, "ntp server 10.1.1.1", "logging_host_configured", True)

    other_config = "hostname widget2\nntp server 10.1.1.2\n"
    _upload_unknown_vendor(client, other_config)

    before = client.get(
        "/api/training/queue", params={"vendor": VENDOR}
    ).json()["lines"]
    assert "ntp server 10.1.1.2" in before

    client.get(
        "/api/training/suggestions",
        params={"vendor": VENDOR, "line": "ntp server 10.1.1.2"},
    )

    after = client.get(
        "/api/training/queue", params={"vendor": VENDOR}
    ).json()["lines"]
    assert after == before  # unchanged: still just a suggestion, not a rule
