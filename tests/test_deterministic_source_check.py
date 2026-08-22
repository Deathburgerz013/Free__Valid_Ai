import hashlib
import inspect

import pytest

from free_valid_ai import assess_claim, create_claim, run_source_sha256_check
from free_valid_ai.checks import PROCEDURE_SHA256
from free_valid_ai.claims import ClaimContractError


ACTUAL = b"independently presented source bytes"
OTHER = b"different bytes"


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def bound_claim(*, expected: str | None = None, source_hash: str | None = None):
    source_hash = source_hash or digest(ACTUAL)
    expected = expected or digest(ACTUAL)
    return create_claim(
        statement="The declared source has the expected SHA-256 digest.",
        scope={
            "check": {
                "type": "source_sha256_equals",
                "version": 1,
                "source_id": "source-1",
                "expected_sha256": expected,
            }
        },
        conditions=["the identified source bytes are presented directly"],
        sources=[{
            "source_id": "source-1",
            "locator": "fixture://source-1",
            "creator_id": "creator-1",
            "creator_name": "Creator One",
            "license": "CREATOR-DECLARED-V1",
            "content_sha256": source_hash,
            "usage_terms": {
                "training_use": "PROHIBITED",
                "commercial_use": "PROHIBITED",
                "redistribution": "PERMITTED",
                "attribution_required": True,
                "compensation_terms": "No payment required for this declared use.",
                "consent_receipt": "creator-consent-1",
            },
        }],
        author={"author_id": "model-proposer", "display_name": "Model Proposer"},
        observed_at="2026-08-23T00:00:00Z",
    )


def run(claim, observed_bytes, **extra):
    return run_source_sha256_check(
        claim=claim,
        verifier_id="deterministic-sha256-tool",
        observed_at=extra.pop("observed_at", "2026-08-23T00:01:00Z"),
        observed_bytes=observed_bytes,
        **extra,
    )


def test_caller_cannot_choose_result() -> None:
    assert "result" not in inspect.signature(run_source_sha256_check).parameters


def test_exact_bound_bytes_hold() -> None:
    claim = bound_claim()
    receipt = run(claim, ACTUAL)
    assert receipt["result"] == "HELD"
    assert receipt["evidence"][0]["content_sha256"] == digest(ACTUAL)
    assert receipt["method"]["procedure_sha256"] == PROCEDURE_SHA256
    assert assess_claim(
        claim, [receipt], as_of="2026-08-23T00:02:00Z"
    )["status"] == "HELD"


def test_bound_bytes_can_contradict_expected_digest() -> None:
    claim = bound_claim(expected=digest(OTHER))
    receipt = run(claim, ACTUAL)
    assert receipt["result"] == "CONTRADICTED"


def test_wrong_source_identity_is_unknown_not_contradicted() -> None:
    claim = bound_claim()
    receipt = run(claim, OTHER)
    assert receipt["result"] == "UNKNOWN"
    assert receipt["limitations"] == [
        "presented bytes did not match the claim-bound source identity"
    ]


def test_missing_bytes_are_blocked_without_fabricated_evidence() -> None:
    claim = bound_claim()
    receipt = run(claim, None)
    assert receipt["result"] == "BLOCKED"
    assert receipt["evidence"] == []
    assert receipt["limitations"] == ["source bytes were not presented"]


def test_recheck_exposes_changed_environment_in_receipt_chain() -> None:
    claim = bound_claim()
    first = run(claim, ACTUAL)
    second = run(
        claim,
        OTHER,
        previous_receipt=first,
        observed_at="2026-08-23T00:03:00Z",
    )
    assessment = assess_claim(
        claim, [first, second], as_of="2026-08-23T00:04:00Z"
    )
    assert first["result"] == "HELD"
    assert second["result"] == "UNKNOWN"
    assert second["previous_receipt_hash"] == first["receipt_hash"]
    assert assessment["status"] == "UNKNOWN"


@pytest.mark.parametrize(
    "check",
    [
        {},
        {"type": "source_sha256_equals"},
        {
            "type": "source_sha256_equals",
            "version": 2,
            "source_id": "source-1",
            "expected_sha256": digest(ACTUAL),
        },
    ],
)
def test_malformed_or_unknown_check_contract_is_rejected(check) -> None:
    claim = bound_claim()
    claim["scope"]["check"] = check
    # Recreating is required because direct mutation invalidates the claim hash.
    with pytest.raises(ClaimContractError):
        run(claim, ACTUAL)


def test_non_bytes_input_is_rejected() -> None:
    with pytest.raises(ClaimContractError, match="observed_bytes"):
        run(bound_claim(), "text is not bytes")
