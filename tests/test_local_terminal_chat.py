from __future__ import annotations

import json

import pytest

from free_valid_ai.chat import ChatSession, run_chat
from free_valid_ai.cli import build_parser, build_runtime_envelope
from free_valid_ai.local_model import OllamaTransport


class FakeTransport:
    def __init__(self, replies: list[str]) -> None:
        self.replies = iter(replies)
        self.calls: list[tuple[str, list[dict[str, str]]]] = []

    def chat(self, model, messages):
        copied = [dict(message) for message in messages]
        self.calls.append((model, copied))
        return next(self.replies)


ENVELOPE = build_runtime_envelope(
    model="local-test", endpoint="http://127.0.0.1:11434/api/chat", num_gpu=0
)


def test_conversation_carries_prior_turns() -> None:
    transport = FakeTransport(["hello", "still here"])
    session = ChatSession("local-test", transport, ENVELOPE)
    assert session.ask("Hi") == "hello"
    assert session.ask("Again?") == "still here"
    assert transport.calls[1][1] == [
        {"role": "system", "content": ENVELOPE},
        {"role": "user", "content": "Hi"},
        {"role": "assistant", "content": "hello"},
        {"role": "user", "content": "Again?"},
    ]


def test_runtime_envelope_precedes_every_conversation_turn() -> None:
    transport = FakeTransport(["local", "still local"])
    envelope = build_runtime_envelope(
        model="local-test",
        endpoint="http://127.0.0.1:11434/api/chat",
        num_gpu=0,
    )
    session = ChatSession("local-test", transport, runtime_envelope=envelope)
    session.ask("Where are you running?")
    session.ask("Still?")
    for _, messages in transport.calls:
        assert messages[0] == {"role": "system", "content": envelope}
        assert messages.count({"role": "system", "content": envelope}) == 1
    assert '"assistant_identity":"Simulator"' in envelope
    assert '"model_carrier":"local-test"' in envelope
    assert '"assistant_write_authority":"NONE"' in envelope
    assert '"user_authority":"NOT_ASSESSED"' in envelope
    assert '"write_authority":"NONE"' not in envelope.replace(
        '"assistant_write_authority":"NONE"', ""
    )
    assert '"cloud_service_claim":false' in envelope
    assert '"execution_selection":"CPU_ONLY"' in envelope


def test_altered_or_rebound_runtime_envelope_stops_before_transport() -> None:
    transport = FakeTransport(["must not be called"])
    altered = ENVELOPE.replace('"assistant_write_authority":"NONE"',
                                '"assistant_write_authority":"SOME"')
    with pytest.raises(ValueError, match="envelope"):
        ChatSession("local-test", transport, altered)
    with pytest.raises(ValueError, match="model_carrier_mismatch"):
        ChatSession("different-model", transport, ENVELOPE)
    assert transport.calls == []


def test_missing_or_blank_runtime_envelope_stops_before_transport() -> None:
    transport = FakeTransport(["must not be called"])
    with pytest.raises(TypeError):
        ChatSession("local-test", transport)
    for value in ("", "   ", None, b"not text"):
        with pytest.raises(ValueError, match="runtime_envelope"):
            ChatSession("local-test", transport, value)
    assert transport.calls == []


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:11434/api/chat",
        "http://example.com:11434/api/chat",
        "http://127.0.0.1:11434/other",
        "http://user:pass@127.0.0.1:11434/api/chat",
        "http://127.0.0.1:11434/api/chat?cloud=true",
    ],
)
def test_nonlocal_or_ambiguous_endpoints_are_rejected(endpoint: str) -> None:
    with pytest.raises(ValueError):
        OllamaTransport(endpoint=endpoint)


def test_ollama_request_has_no_credentials_and_disables_stream(monkeypatch) -> None:
    observed = {}

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def read(self): return b'{"message":{"content":"local answer"}}'

    def fake_urlopen(request, timeout):
        observed["url"] = request.full_url
        observed["headers"] = dict(request.header_items())
        observed["payload"] = json.loads(request.data)
        return Response()

    monkeypatch.setattr("free_valid_ai.local_model.urlopen", fake_urlopen)
    answer = OllamaTransport().chat("model", [{"role": "user", "content": "hi"}])
    assert answer == "local answer"
    assert observed["url"] == "http://127.0.0.1:11434/api/chat"
    assert "Authorization" not in observed["headers"]
    assert observed["payload"]["stream"] is False
    assert observed["payload"]["options"] == {"num_gpu": 0}


def test_structured_ollama_request_binds_format_schema(monkeypatch) -> None:
    observed = {}

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def read(self): return b'{"message":{"content":"{\\"assessment\\":\\"CLEAN\\",\\"issues\\":[]}"}}'

    def fake_urlopen(request, timeout):
        observed["payload"] = json.loads(request.data)
        return Response()

    monkeypatch.setattr("free_valid_ai.local_model.urlopen", fake_urlopen)
    schema = {"type": "object", "additionalProperties": False}
    result = OllamaTransport().chat_structured(
        "model", [{"role": "user", "content": "review"}], schema
    )
    assert json.loads(result)["assessment"] == "CLEAN"
    assert observed["payload"]["format"] == schema
    assert observed["payload"]["stream"] is False


def test_terminal_exits_without_persistence() -> None:
    inputs = iter(["hello", "/exit"])
    output = []
    session = ChatSession("local-test", FakeTransport(["hi"]), ENVELOPE)
    assert run_chat(session, input_fn=lambda _: next(inputs), output_fn=output.append) == 0
    assert any(line == "Assistant write authority: NONE" for line in output)
    assert any(line == "Assistant execution authority: NONE" for line in output)
    assert any(line == "User authority: NOT_ASSESSED" for line in output)
    assert any(line == "Assistant: Simulator" for line in output)
    assert any(line.startswith("AI> hi") for line in output)


def test_cli_defaults_to_local_model() -> None:
    args = build_parser().parse_args(["chat"])
    assert args.model == "llama3.2"
    assert args.endpoint == "http://127.0.0.1:11434/api/chat"
    assert args.num_gpu == 0


def test_gpu_selection_must_be_explicit_nonnegative_integer() -> None:
    assert OllamaTransport(num_gpu=3).num_gpu == 3
    for value in (-1, True, 1.5):
        with pytest.raises(ValueError):
            OllamaTransport(num_gpu=value)
