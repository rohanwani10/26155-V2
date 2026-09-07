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


def test_fake_llm_embed_is_close_for_lines_sharing_most_tokens():
    # ticket 16's embedding pre-check needs this: a line differing from
    # another by one token (a changed argument, or pure whitespace) must
    # cosine-similarity-match closer than two lines sharing no vocabulary.
    client = FakeLlmClient()

    def cosine(a: list[float], b: list[float]) -> float:
        return sum(x * y for x, y in zip(a, b))  # both already L2-normalized

    close = cosine(
        client.embed("ntp server 10.1.1.1"), client.embed("ntp server 10.1.1.2")
    )
    far = cosine(client.embed("ntp server 10.1.1.1"), client.embed("hostname widget1"))
    identical_whitespace = cosine(
        client.embed("ntp server 10.1.1.1"), client.embed("ntp   server 10.1.1.1")
    )
    assert close > far
    assert identical_whitespace == pytest.approx(1.0)


def test_fake_llm_tracks_interpret_and_verify_call_counts():
    client = FakeLlmClient()
    assert client.interpret_calls == 0
    assert client.verify_calls == 0
    client.interpret("prompt")
    client.verify("claim", "context")
    client.verify("claim2", "context2")
    assert client.interpret_calls == 1
    assert client.verify_calls == 2
