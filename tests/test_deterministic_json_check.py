import hashlib
import inspect
import json

import pytest

from free_valid_ai import assess_claim, create_claim, run_json_pointer_check
from free_valid_ai.checks import JSON_PROCEDURE_SHA256
from free_valid_ai.claims import ClaimContractError


def canonical(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


DOCUMENT = {
    "tests": {"passed": 25, "skipped": 0, "complete": True},
    "paths": {"a/b": {"~state": "held"}},
    "items": ["zero", {"value": 7}],
}
BYTES = canonical(DOCUMENT)


def claim(pointer: str, expected_value, *, source_bytes: bytes = BYTES):
    return create_claim(
        statement="The JSON value at the declared pointer matches the expectation.",
        scope={
            "check": {
                "type": "json_pointer_equals",
                "version": 1,
                "source_id": "results-json",
                "pointer": pointer,
                "expected_value": expected_value,
            }
        },
        conditions=["the identified JSON bytes are presented directly"],
        sources=[{
            "source_id": "results-json",
            "locator": "fixture://results.json",
            "creator_id": "operator-1",
            "creator_name": "Operator One",
            "license": "CREATOR-DECLARED-V1",
            "content_sha256": digest(source_bytes),
            "usage_terms": {
                "training_use": "PERMITTED",
                "commercial_use": "PROHIBITED",
                "redistribution": "PERMITTED",
                "attribution_required": True,
                "compensation_terms": "No payment required for this fixture.",
                "consent_receipt": "operator-consent-1",
            },
        }],
        author={"author_id": "model-proposer", "display_name": "Model Proposer"},
        observed_at="2026-08-23T01:00:00Z",
    )


def run(bound_claim, observed_bytes, **extra):
    return run_json_pointer_check(
        claim=bound_claim,
        verifier_id="deterministic-json-tool",
        observed_at=extra.pop("observed_at", "2026-08-23T01:01:00Z"),
        observed_bytes=observed_bytes,
        **extra,
    )


def test_caller_cannot_choose_result() -> None:
    assert "result" not in inspect.signature(run_json_pointer_check).parameters


def test_json_number_claim_holds() -> None:
    bound = claim("/tests/passed", 25)
    receipt = run(bound, BYTES)
    assert receipt["result"] == "HELD"
    assert receipt["method"]["procedure_sha256"] == JSON_PROCEDURE_SHA256
    assert assess_claim(
        bound, [receipt], as_of="2026-08-23T01:02:00Z"
    )["status"] == "HELD"


def test_different_json_value_is_contradicted() -> None:
    assert run(claim("/tests/passed", 26), BYTES)["result"] == "CONTRADICTED"


def test_json_types_are_not_coerced() -> None:
    assert run(claim("/tests/complete", 1), BYTES)["result"] == "CONTRADICTED"
    assert run(claim("/tests/complete", True), BYTES)["result"] == "HELD"


def test_missing_pointer_is_contradicted() -> None:
    receipt = run(claim("/tests/failed", 0), BYTES)
    assert receipt["result"] == "CONTRADICTED"
    assert receipt["limitations"] == ["declared JSON Pointer was absent"]


def test_rfc6901_escaping_is_resolved() -> None:
    assert run(claim("/paths/a~1b/~0state", "held"), BYTES)["result"] == "HELD"


def test_array_pointer_is_resolved_without_loose_indices() -> None:
    assert run(claim("/items/1/value", 7), BYTES)["result"] == "HELD"
    assert run(claim("/items/01", "zero"), BYTES)["result"] == "CONTRADICTED"


def test_bound_non_json_is_blocked() -> None:
    raw = b"not json"
    receipt = run(claim("/value", 1, source_bytes=raw), raw)
    assert receipt["result"] == "BLOCKED"
    assert receipt["limitations"] == [
        "bound source bytes were not valid UTF-8 JSON"
    ]


def test_missing_bytes_are_blocked() -> None:
    receipt = run(claim("/tests/passed", 25), None)
    assert receipt["result"] == "BLOCKED"
    assert receipt["evidence"] == []


def test_source_identity_mismatch_is_unknown_before_json_interpretation() -> None:
    receipt = run(claim("/tests/passed", 25), b'{"tests":{"passed":25}}')
    assert receipt["result"] == "UNKNOWN"


@pytest.mark.parametrize("pointer", ["tests/passed", "/bad~2escape", "/bad~"])
def test_invalid_json_pointer_is_rejected(pointer) -> None:
    bound = claim("/tests/passed", 25)
    bound["scope"]["check"]["pointer"] = pointer
    with pytest.raises(ClaimContractError):
        run(bound, BYTES)


def test_recheck_preserves_prior_held_and_exposes_new_identity() -> None:
    bound = claim("/tests/passed", 25)
    first = run(bound, BYTES)
    changed = canonical({**DOCUMENT, "tests": {"passed": 24}})
    second = run(
        bound,
        changed,
        previous_receipt=first,
        observed_at="2026-08-23T01:03:00Z",
    )
    assert first["result"] == "HELD"
    assert second["result"] == "UNKNOWN"
    assert second["previous_receipt_hash"] == first["receipt_hash"]
