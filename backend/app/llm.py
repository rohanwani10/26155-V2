"""The LLM client seam (spec's "Testing Decisions", secondary seam). All AI
calls in this codebase -- this ticket's RAG chat, and any future
training-loop ticket -- go through this interface, never call Ollama
directly. Two implementations: OllamaLlmClient (real, network to localhost
only) and FakeLlmClient (deterministic, in-memory, used by the main test
suite so tests never need a running Ollama instance).

One small local model serves both the `interpret` (draft an answer/
explanation) and `verify` (adversarial check of that answer against
retrieved context) roles via different prompting, not two separate model
weights -- see spec's AI pipeline decision. `embed` is a distinct call (a
real embedding model/endpoint), not prompting the same generative model. No
separate `chat` concept: for this ticket, `interpret` given a
question-plus-retrieved-context prompt *is* chat-answer generation, so a
fifth abstraction isn't earning its keep.
"""

import hashlib
from typing import Protocol
from urllib.parse import urlparse

import httpx

_ALLOWED_HOSTS = {"localhost", "127.0.0.1"}


class LlmClient(Protocol):
    def interpret(self, prompt: str) -> str:
        """Draft an answer/explanation from a prompt."""
        ...

    def verify(self, claim: str, context: str) -> bool:
        """The adversarial second pass: does `context` actually support
        `claim`? False means callers must never surface `claim` as-is."""
        ...

    def embed(self, text: str) -> list[float]:
        """A fixed-length embedding vector for `text`, for the RAG vector
        store."""
        ...


class OllamaLlmClient:
    """Real implementation, backed by a local Ollama instance's REST API.
    The only thing in this ticket that makes a network call -- and only ever
    to localhost, enforced in __init__, never anywhere else (see spec's
    air-gap/security decisions)."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.2:1b",
        embed_model: str = "nomic-embed-text",
        timeout: float = 30.0,
    ) -> None:
        host = urlparse(base_url).hostname
        if host not in _ALLOWED_HOSTS:
            raise ValueError(
                f"OllamaLlmClient may only talk to localhost, got base_url={base_url!r}"
            )
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._embed_model = embed_model
        self._timeout = timeout

    def _generate(self, prompt: str) -> str:
        resp = httpx.post(
            f"{self._base_url}/api/generate",
            json={"model": self._model, "prompt": prompt, "stream": False},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        text: str = resp.json()["response"]
        return text

    def interpret(self, prompt: str) -> str:
        return self._generate(prompt).strip()

    def verify(self, claim: str, context: str) -> bool:
        prompt = (
            "You are an adversarial fact-checker. Given the CONTEXT below, "
            "does it actually support the CLAIM? Reply with exactly one "
            f"word, YES or NO.\n\nCONTEXT:\n{context}\n\nCLAIM:\n{claim}\n\nANSWER:"
        )
        response = self._generate(prompt).strip().lower()
        return response.startswith("yes")

    def embed(self, text: str) -> list[float]:
        resp = httpx.post(
            f"{self._base_url}/api/embeddings",
            json={"model": self._embed_model, "prompt": text},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        embedding: list[float] = resp.json()["embedding"]
        return embedding


class FakeLlmClient:
    """Deterministic, in-memory implementation for the main test suite.
    `interpret_response`/`verify_result` are plain settable attributes so a
    test can reprogram them mid-test (e.g. to exercise the verify-fails
    fallback path). `embed` is a cheap hash-based fixed-length vector -- not
    semantically meaningful, but deterministic, so retrieval in tests is
    reproducible without a real embedding model."""

    def __init__(
        self,
        interpret_response: str = "Fake interpreted answer.",
        verify_result: bool = True,
    ) -> None:
        self.interpret_response = interpret_response
        self.verify_result = verify_result

    def interpret(self, prompt: str) -> str:
        return self.interpret_response

    def verify(self, claim: str, context: str) -> bool:
        return self.verify_result

    def embed(self, text: str) -> list[float]:
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        return [b / 255.0 for b in digest[:32]]
