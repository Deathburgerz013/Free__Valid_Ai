"""Loopback-only local model transport for Ollama."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Iterable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class LocalModelError(RuntimeError):
    """A local model could not produce a response."""


class ChatTransport(Protocol):
    def chat(self, model: str, messages: Iterable[Mapping[str, str]]) -> str: ...


@dataclass(frozen=True)
class OllamaTransport:
    endpoint: str = "http://127.0.0.1:11434/api/chat"
    timeout_seconds: float = 120.0
    num_gpu: int = 0

    def __post_init__(self) -> None:
        parsed = urlsplit(self.endpoint)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("Ollama endpoint must use HTTP on loopback")
        if parsed.username or parsed.password:
            raise ValueError("credentials are not permitted in the local endpoint")
        if parsed.path != "/api/chat" or parsed.query or parsed.fragment:
            raise ValueError("Ollama endpoint must target /api/chat without query or fragment")
        if not isinstance(self.num_gpu, int) or isinstance(self.num_gpu, bool) or self.num_gpu < 0:
            raise ValueError("num_gpu must be a non-negative integer")

    def chat(self, model: str, messages: Iterable[Mapping[str, str]]) -> str:
        return self._request(model, messages)

    def chat_structured(
        self,
        model: str,
        messages: Iterable[Mapping[str, str]],
        schema: Mapping[str, object],
    ) -> str:
        """Request local constrained JSON; response is still verified by caller."""
        if not isinstance(schema, Mapping) or not schema:
            raise ValueError("structured response schema must be a non-empty object")
        return self._request(model, messages, response_format=dict(schema))

    def _request(
        self,
        model: str,
        messages: Iterable[Mapping[str, str]],
        response_format: Mapping[str, object] | None = None,
    ) -> str:
        body = {
            "model": model,
            "messages": list(messages),
            "stream": False,
            "options": {"num_gpu": self.num_gpu},
        }
        if response_format is not None:
            body["format"] = response_format
        payload = json.dumps(
            body,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        request = Request(
            self.endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                result = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LocalModelError(f"local Ollama request failed: {exc}") from exc
        try:
            content = result["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise LocalModelError("local Ollama returned an invalid chat response") from exc
        if not isinstance(content, str):
            raise LocalModelError("local Ollama returned non-text content")
        return content
