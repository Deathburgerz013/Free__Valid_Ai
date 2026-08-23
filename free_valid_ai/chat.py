"""Interactive terminal conversation with a replaceable local model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .local_model import ChatTransport, LocalModelError


Input = Callable[[str], str]
Output = Callable[[str], None]


@dataclass
class ChatSession:
    model: str
    transport: ChatTransport
    assistant_name: str = "Simulator"
    runtime_envelope: str | None = None
    messages: list[dict[str, str]] = field(default_factory=list)

    def ask(self, text: str) -> str:
        text = text.strip()
        if not text:
            raise ValueError("message must not be empty")
        proposed: list[dict[str, str]] = []
        if self.runtime_envelope is not None:
            proposed.append({"role": "system", "content": self.runtime_envelope})
        proposed.extend(self.messages)
        proposed.append({"role": "user", "content": text})
        answer = self.transport.chat(self.model, proposed)
        self.messages.extend(
            ({"role": "user", "content": text}, {"role": "assistant", "content": answer})
        )
        return answer


def run_chat(
    session: ChatSession,
    *,
    input_fn: Input = input,
    output_fn: Output = print,
) -> int:
    output_fn("Free__Valid_Ai")
    output_fn(f"Assistant: {session.assistant_name}")
    output_fn(f"Model: {session.model}")
    output_fn("Transport: local Ollama (loopback only)")
    output_fn("Assistant write authority: NONE")
    output_fn("Assistant execution authority: NONE")
    output_fn("User authority: NOT_ASSESSED")
    output_fn("Type /exit to stop. Conversation is not saved.\n")
    while True:
        try:
            message = input_fn("You> ")
        except (EOFError, KeyboardInterrupt):
            output_fn("")
            return 0
        command = message.strip().lower()
        if command in {"/exit", "/quit"}:
            return 0
        if not command:
            continue
        try:
            output_fn(f"AI> {session.ask(message)}\n")
        except (LocalModelError, ValueError) as exc:
            output_fn(f"ERROR: {exc}")
            return 1
