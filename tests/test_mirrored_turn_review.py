from __future__ import annotations

import copy
import json

import pytest

from free_valid_ai.chat import ChatSession, run_chat
from free_valid_ai.cli import build_parser
from free_valid_ai.local_model import LocalModelError
from free_valid_ai.mirrored_review import (
    MIRRORED_REVIEW_SCHEMA, MIRRORED_REVIEW_SCHEMA_SHA256,
    MirroredReviewError, parse_mirrored_review, verify_mirrored_review,
)


class FakeTransport:
    def __init__(self, replies: list[str]) -> None:
        self.replies = iter(replies)
        self.calls = []

    def chat(self, model, messages):
        self.calls.append((model, [dict(message) for message in messages]))
        return next(self.replies)


class StructuredFakeTransport(FakeTransport):
    def __init__(self, replies: list[str]) -> None:
        super().__init__(replies)
        self.schemas = []

    def chat_structured(self, model, messages, schema):
        self.schemas.append(schema)
        return self.chat(model, messages)


def _raw(assessment="CLEAN", issues=None):
    return json.dumps({"assessment": assessment, "issues": issues or []})


def test_clean_review_releases_unchanged_with_mirrored_receipt() -> None:
    transport = FakeTransport(["draft", _raw()])
    session = ChatSession("carrier", transport, mirrored_review=True)
    assert session.ask("question") == "draft"
    audit = session.last_turn_audit
    assert len(transport.calls) == 2
    assert audit["review"]["mode"] == "MIRRORED"
    assert audit["review"]["independence_claimed"] is False
    assert audit["interception"]["decision"] == "UNCHANGED"


def test_review_uses_bound_structured_transport_when_available() -> None:
    transport = StructuredFakeTransport(["draft", _raw()])
    session = ChatSession("carrier", transport, mirrored_review=True)
    assert session.ask("question") == "draft"
    assert transport.schemas == [MIRRORED_REVIEW_SCHEMA]
    assert session.last_turn_audit["review"]["review_schema_sha256"] == MIRRORED_REVIEW_SCHEMA_SHA256


def test_runtime_envelope_is_presented_to_review_and_correction() -> None:
    envelope = "RUNTIME_ENVELOPE_TEST"
    transport = StructuredFakeTransport([
        "wrong", _raw("CORRECTION_REQUIRED", ["runtime mismatch"]), "correct",
    ])
    session = ChatSession(
        "carrier", transport, runtime_envelope=envelope, mirrored_review=True
    )
    assert session.ask("question") == "correct"
    assert transport.calls[0][1][0] == {"role": "system", "content": envelope}
    assert transport.calls[1][1][0] == {"role": "system", "content": envelope}
    assert transport.calls[2][1][0] == {"role": "system", "content": envelope}
    for _, messages in transport.calls:
        assert messages.count({"role": "system", "content": envelope}) == 1


def test_required_correction_gets_exactly_one_correction_call() -> None:
    transport = FakeTransport([
        "wrong", _raw("CORRECTION_REQUIRED", ["unsupported runtime claim"]), "correct",
    ])
    session = ChatSession("carrier", transport, mirrored_review=True)
    assert session.ask("question") == "correct"
    assert len(transport.calls) == 3
    assert session.last_turn_audit["interception"]["decision"] == "CORRECTED"
    assert session.last_turn_audit["interception"]["correction_basis_sha256"] == session.last_turn_audit["review"]["review_hash"]


@pytest.mark.parametrize("raw", ["not json", "{}", '{"assessment":"CLEAN","issues":["x"]}'])
def test_malformed_review_is_unknown_and_never_releases(raw: str) -> None:
    session = ChatSession("carrier", FakeTransport(["draft", raw]), mirrored_review=True)
    with pytest.raises(LocalModelError, match="UNKNOWN"):
        session.ask("question")
    assert session.last_turn_audit["interception"]["decision"] == "UNKNOWN"
    assert session.last_turn_audit["interception"]["released_base64"] is None


def test_explicit_unknown_never_releases() -> None:
    session = ChatSession(
        "carrier", FakeTransport(["draft", _raw("UNKNOWN", ["insufficient context"])]),
        mirrored_review=True,
    )
    with pytest.raises(LocalModelError, match="UNKNOWN"):
        session.ask("question")
    assert session.last_turn_audit["interception"]["decision"] == "UNKNOWN"


@pytest.mark.parametrize("correction", ["", "wrong"])
def test_empty_or_unchanged_correction_is_blocked(correction: str) -> None:
    session = ChatSession(
        "carrier",
        FakeTransport(["wrong", _raw("CORRECTION_REQUIRED", ["issue"]), correction]),
        mirrored_review=True,
    )
    with pytest.raises(LocalModelError, match="deterministic"):
        session.ask("question")
    assert session.last_turn_audit["interception"]["decision"] == "BLOCKED"


def test_review_receipt_tamper_fails() -> None:
    receipt = parse_mirrored_review(
        _raw(), model_carrier="carrier", received_turn_hash="0" * 64,
        draft_sha256="1" * 64,
    )
    assert verify_mirrored_review(receipt)
    bad = copy.deepcopy(receipt)
    bad["independence_claimed"] = True
    with pytest.raises(MirroredReviewError, match="overclaim"):
        verify_mirrored_review(bad)
    bad_schema = copy.deepcopy(receipt)
    bad_schema["review_schema_sha256"] = "0" * 64
    with pytest.raises(MirroredReviewError, match="schema_mismatch"):
        verify_mirrored_review(bad_schema)


def test_exit_makes_zero_model_calls_with_review_enabled() -> None:
    transport = FakeTransport([])
    session = ChatSession("carrier", transport, mirrored_review=True)
    assert run_chat(session, input_fn=lambda _: "/exit", output_fn=lambda _: None) == 0
    assert transport.calls == []


def test_cli_enables_review_by_default_and_allows_explicit_disable() -> None:
    parser = build_parser()
    assert parser.parse_args(["chat"]).mirror_review is True
    assert parser.parse_args(["chat", "--no-mirror-review"]).mirror_review is False


def test_received_turn_chain_advances_only_after_released_answer() -> None:
    transport = FakeTransport(["one", _raw(), "two", _raw()])
    session = ChatSession("carrier", transport, mirrored_review=True)
    session.ask("first")
    first = session.previous_received_turn_hash
    session.ask("second")
    assert session.turn_sequence == 2
    assert session.last_turn_audit["received"]["previous_received_turn_hash"] == first
