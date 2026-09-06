"""API-boundary tests for ticket 09's AI-assisted training suggestions:
GET /api/training/suggestions. Same style as test_chat_api.py -- real HTTP
calls, FakeLlmClient injected via create_app for determinism."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.llm import FakeLlmClient
from app.main import create_app
from app.training import FACT_IDS


def _make_app(tmp_path: Path, llm_client=None):
    return create_app(tmp_path, llm_client=llm_client or FakeLlmClient())


def _authed_client(tmp_path: Path, llm_client=None):
    app = _make_app(tmp_path, llm_client)
    client = TestClient(app)
    client.post("/api/setup", json={"password": "correct horse battery staple"})
    client.post("/api/login", json={"credential": "correct horse battery staple"})
    return client


GOOD_RESPONSE = (
    "FACT_ID: ssh_version_2\nVALUE: true\nRATIONALE: line enables SSHv2 only."
)


def _upload_unknown_vendor(client, config_text: str, vendor_hint: str = "acme_widgetos"):
    return client.post(
        "/api/devices",
        files={
            "config": ("running-config.txt", config_text.encode(), "text/plain"),
            "version_info": ("version.txt", b"Acme WidgetOS, v1.0\n", "text/plain"),
        },
        data={"vendor_hint": vendor_hint},
    )


UNKNOWN_CONFIG = "hostname widget1\nsecure-mode strict\n"


def test_suggestions_requires_authentication(tmp_path):
    client = TestClient(_make_app(tmp_path))
    resp = client.get(
        "/api/training/suggestions",
        params={"vendor": "acme_widgetos", "line": "secure-mode strict"},
    )
    assert resp.status_code == 401


def test_suggestion_proposes_a_real_taxonomy_fact_id(tmp_path):
    llm = FakeLlmClient(interpret_response=GOOD_RESPONSE, verify_result=True)
    client = _authed_client(tmp_path, llm)

    resp = client.get(
        "/api/training/suggestions",
        params={"vendor": "acme_widgetos", "line": "secure-mode strict"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["fact_id"] in FACT_IDS
    assert body["value"] is True
    assert body["verified"] is True
    assert body["rationale"]


def test_failed_verification_is_reflected_not_hidden(tmp_path):
    llm = FakeLlmClient(interpret_response=GOOD_RESPONSE, verify_result=False)
    client = _authed_client(tmp_path, llm)

    resp = client.get(
        "/api/training/suggestions",
        params={"vendor": "acme_widgetos", "line": "secure-mode strict"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["verified"] is False


def test_suggestion_is_never_auto_applied(tmp_path):
    llm = FakeLlmClient(interpret_response=GOOD_RESPONSE, verify_result=True)
    client = _authed_client(tmp_path, llm)
    _upload_unknown_vendor(client, UNKNOWN_CONFIG)

    before = client.get(
        "/api/training/queue", params={"vendor": "acme_widgetos"}
    ).json()["lines"]
    assert "secure-mode strict" in before

    client.get(
        "/api/training/suggestions",
        params={"vendor": "acme_widgetos", "line": "secure-mode strict"},
    )

    after = client.get(
        "/api/training/queue", params={"vendor": "acme_widgetos"}
    ).json()["lines"]
    assert after == before  # unchanged: no rule was created, nothing dequeued


def test_malformed_fact_id_from_the_model_is_handled_gracefully(tmp_path):
    llm = FakeLlmClient(
        interpret_response="FACT_ID: not_a_real_fact\nVALUE: true\nRATIONALE: guess.",
        verify_result=True,
    )
    client = _authed_client(tmp_path, llm)

    resp = client.get(
        "/api/training/suggestions",
        params={"vendor": "acme_widgetos", "line": "secure-mode strict"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["verified"] is False
    assert body["fact_id"] is None


def test_unparseable_response_from_the_model_is_handled_gracefully(tmp_path):
    llm = FakeLlmClient(interpret_response="I'm not sure what this line does.")
    client = _authed_client(tmp_path, llm)

    resp = client.get(
        "/api/training/suggestions",
        params={"vendor": "acme_widgetos", "line": "secure-mode strict"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["verified"] is False
    assert body["fact_id"] is None
