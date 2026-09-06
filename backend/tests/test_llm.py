"""Fast, deterministic tests for the LlmClient seam itself (no network, no
Ollama) -- the localhost-only guard on OllamaLlmClient, and FakeLlmClient's
deterministic behavior that the rest of the suite relies on."""

import pytest

from app.llm import FakeLlmClient, OllamaLlmClient


def test_ollama_client_refuses_non_localhost_base_url():
    with pytest.raises(ValueError):
        OllamaLlmClient(base_url="http://example.com:11434")


def test_ollama_client_accepts_localhost_variants():
    OllamaLlmClient(base_url="http://localhost:11434")
    OllamaLlmClient(base_url="http://127.0.0.1:11434")


def test_fake_llm_interpret_returns_configured_response():
    client = FakeLlmClient(interpret_response="canned answer")
    assert client.interpret("any prompt") == "canned answer"


def test_fake_llm_verify_returns_configured_result():
    passing = FakeLlmClient(verify_result=True)
    failing = FakeLlmClient(verify_result=False)
    assert passing.verify("claim", "context") is True
    assert failing.verify("claim", "context") is False


def test_fake_llm_embed_is_deterministic_and_fixed_length():
    client = FakeLlmClient()
    v1 = client.embed("ssh version 2")
    v2 = client.embed("ssh version 2")
    v3 = client.embed("telnet enabled")
    assert v1 == v2
    assert v1 != v3
    assert len(v1) == len(v3)
