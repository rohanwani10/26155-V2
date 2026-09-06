"""Smoke tests for the real Ollama-backed LlmClient implementation (spec's
"Testing Decisions", secondary seam). These are deliberately NOT part of the
main suite's fast feedback loop -- see pyproject.toml's
`addopts = "-m \"not llm_smoke\""`, which excludes the `llm_smoke` marker by
default. As a second line of defense (e.g. if someone runs `pytest -m
llm_smoke` directly on a machine with no Ollama running), each test also
does its own runtime connectivity check and skips cleanly rather than
failing or hanging.
"""

import httpx
import pytest

from app.llm import OllamaLlmClient

pytestmark = pytest.mark.llm_smoke

OLLAMA_URL = "http://localhost:11434"


def _ollama_reachable() -> bool:
    try:
        resp = httpx.get(OLLAMA_URL, timeout=1.0)
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


@pytest.fixture(autouse=True)
def _require_ollama():
    if not _ollama_reachable():
        pytest.skip("Ollama is not reachable at localhost:11434")


def test_interpret_returns_nonempty_text():
    client = OllamaLlmClient()
    result = client.interpret("Say hello in one word.")
    assert isinstance(result, str)
    assert result.strip()


def test_verify_returns_a_bool():
    client = OllamaLlmClient()
    result = client.verify("The sky is blue.", context="The sky appears blue.")
    assert isinstance(result, bool)


def test_embed_returns_a_vector():
    client = OllamaLlmClient()
    vector = client.embed("ssh version 2")
    assert isinstance(vector, list)
    assert len(vector) > 0
    assert all(isinstance(v, float) for v in vector)
