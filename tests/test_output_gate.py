import hashlib

import pytest

from free_valid_ai import create_claim
from free_valid_ai.frozen_index import DEFAULT_FROZEN_CHECK_INDEX
from free_valid_ai.output_gate import (
    OutputGateError,
    gate_is_caller_independent,
    run_verified_model_call,
)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def exact_output_claim(expected: bytes, *, source_id="draft"):
    return create_claim(
        statement="The draft exactly matches the predeclared output digest.",
        scope={"check": {"type": "source_sha256_equals", "version": 1,
                         "source_id": source_id,
                         "expected_sha256": digest(expected)}},
        conditions=["the model draft bytes are presented directly"],
        sources=[{
            "source_id": source_id, "locator": "runtime://model-draft",
            "creator_id": "runtime", "creator_name": "Runtime",
            "license": "RUNTIME-EVIDENCE-V1", "content_sha256": digest(expected),
            "usage_terms": {
                "training_use": "PROHIBITED", "commercial_use": "PROHIBITED",
                "redistribution": "PROHIBITED", "attribution_required": False,
                "compensation_terms": "None", "consent_receipt": "runtime-v1",
            },
        }],
        author={"author_id": "gate-policy", "display_name": "Gate Policy"},
        observed_at="2026-08-26T00:00:00Z",
    )


def run(reply="allowed", *, claims=None, invoke=None, messages=None):
    claims = claims or [exact_output_claim(b"allowed")]
    invoke = invoke or (lambda model, bound: reply)
    messages = messages or [{"role": "user", "content": "respond exactly"}]
    return run_verified_model_call(
        model="local-test", messages=messages, invoke=invoke, claims=claims,
        frozen_index=DEFAULT_FROZEN_CHECK_INDEX, verifier_id="runtime-gate",
        observed_at="2026-08-26T00:01:00Z",
    )


def test_matching_draft_releases_after_verified_receipt() -> None:
    result = run()
    assert result["decision"] == "RELEASE"
    assert result["released"] == "allowed"
    assert result["receipts"][0]["result"] == "HELD"
    assert result["accepted"] is False
    assert result["write_authority"] == "NONE"
    assert result["execution_authority"] == "NONE"


def test_nonmatching_draft_is_not_exposed_by_gate_result() -> None:
    result = run("private rejected draft")
    assert result["decision"] == "BLOCK"
    assert result["released"] is None
    assert result["receipts"][0]["result"] == "UNKNOWN"
    assert "private rejected draft" not in repr(result)


def test_empty_draft_is_blocked() -> None:
    result = run("")
    assert result["decision"] == "BLOCK"
    assert result["released"] is None


def test_claims_and_index_are_checked_before_invocation() -> None:
    calls = []
    bad = exact_output_claim(b"allowed")
    bad["claim_hash"] = "0" * 64
    with pytest.raises(Exception):
        run(claims=[bad], invoke=lambda model, messages: calls.append(True) or "allowed")
    assert calls == []


def test_unadmitted_check_stops_before_invocation() -> None:
    calls = []
    bad = exact_output_claim(b"allowed")
    bad["scope"]["check"]["type"] = "caller_check"
    with pytest.raises(Exception):
        run(claims=[bad], invoke=lambda model, messages: calls.append(True) or "allowed")
    assert calls == []


def test_full_context_is_hash_bound_and_passed_as_a_copy() -> None:
    seen = []
    messages = [{"role": "system", "content": "bound"},
                {"role": "user", "content": "respond exactly"}]
    first = run(messages=messages, invoke=lambda model, value: seen.append(value) or "allowed")
    messages[0]["content"] = "changed after invocation"
    assert seen[0][0]["content"] == "bound"
    second = run(messages=messages)
    assert first["context_sha256"] != second["context_sha256"]


def test_multiple_predeclared_claims_must_all_hold() -> None:
    claims = [exact_output_claim(b"allowed", source_id="a"),
              exact_output_claim(b"different", source_id="b")]
    result = run(claims=claims)
    assert result["decision"] == "BLOCK"
    assert result["released"] is None
    assert sorted(receipt["result"] for receipt in result["receipts"]) == [
        "HELD", "UNKNOWN"
    ]


def test_caller_cannot_supply_decision_or_released_output() -> None:
    assert gate_is_caller_independent() is True
    with pytest.raises(TypeError):
        run_verified_model_call(
            model="m", messages=[{"role": "user", "content": "x"}],
            invoke=lambda model, messages: "x", claims=[exact_output_claim(b"x")],
            frozen_index=DEFAULT_FROZEN_CHECK_INDEX, verifier_id="v",
            observed_at="2026-08-26T00:01:00Z", decision="RELEASE",
        )
