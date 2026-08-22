import copy
import hashlib

import pytest

from free_valid_ai.claims import (
    ClaimContractError,
    assess_claim,
    create_claim,
    create_verification_receipt,
    verify_claim,
    verify_verification_receipt,
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source() -> dict:
    return {
        "source_id": "source-1",
        "locator": "https://example.invalid/source-1",
        "creator_id": "creator-1",
        "creator_name": "Example Creator",
        "license": "CREATOR-DECLARED-V1",
        "content_sha256": digest(b"source bytes"),
        "usage_terms": {
            "training_use": "PROHIBITED",
            "commercial_use": "PROHIBITED",
            "redistribution": "PERMITTED",
            "attribution_required": True,
            "compensation_terms": "No payment required for this declared use.",
            "consent_receipt": "creator-signed-receipt-1",
        },
    }


def claim(**changes) -> dict:
    values = {
        "statement": "The fixture bytes have the declared digest.",
        "scope": {"fixture": "source-1", "algorithm": "sha256"},
        "conditions": ["the referenced bytes remain unchanged"],
        "sources": [source()],
        "author": {"author_id": "author-1", "display_name": "Author One"},
        "observed_at": "2026-08-22T20:00:00Z",
        "valid_until": "2026-08-23T20:00:00Z",
    }
    values.update(changes)
    return create_claim(**values)


def method() -> dict:
    return {
        "method_id": "sha256-file-v1",
        "description": "Hash the presented bytes with SHA-256.",
        "procedure_sha256": digest(b"sha256-file-v1 procedure"),
    }


def evidence() -> list[dict]:
    return [{
        "evidence_id": "evidence-1",
        "locator": "fixture://source-1",
        "content_sha256": digest(b"source bytes"),
    }]


def receipt(bound_claim: dict, **changes) -> dict:
    values = {
        "claim": bound_claim,
        "verifier_id": "verifier-1",
        "method": method(),
        "observed_at": "2026-08-22T20:05:00Z",
        "evidence": evidence(),
        "result": "HELD",
    }
    values.update(changes)
    return create_verification_receipt(**values)


def test_claim_is_deterministic_unaccepted_and_unverified() -> None:
    first = claim()
    second = claim()
    assert first == second
    assert verify_claim(first) is True
    assessment = assess_claim(first, [], as_of="2026-08-22T20:01:00Z")
    assert assessment["status"] == "UNVERIFIED"
    assert first["accepted"] is False
    assert first["truth_claimed"] is False
    assert first["write_authority"] == "NONE"


@pytest.mark.parametrize(
    "field,value",
    [
        ("creator_name", ""),
        ("license", ""),
        ("content_sha256", "not-a-hash"),
    ],
)
def test_source_without_attribution_or_integrity_is_rejected(field, value) -> None:
    bad = source()
    bad[field] = value
    with pytest.raises(ClaimContractError):
        claim(sources=[bad])


@pytest.mark.parametrize(
    "field,value",
    [
        ("training_use", "UNSPECIFIED"),
        ("commercial_use", None),
        ("compensation_terms", ""),
        ("consent_receipt", ""),
    ],
)
def test_source_usage_must_be_explicit(field, value) -> None:
    bad = source()
    bad["usage_terms"][field] = value
    with pytest.raises(ClaimContractError):
        claim(sources=[bad])


def test_claim_tamper_and_extra_field_are_rejected() -> None:
    original = claim()
    changed = copy.deepcopy(original)
    changed["statement"] = "different"
    with pytest.raises(ClaimContractError, match="claim_hash_mismatch"):
        verify_claim(changed)
    extra = copy.deepcopy(original)
    extra["model_confidence"] = 1.0
    with pytest.raises(ClaimContractError, match="claim_fields_mismatch"):
        verify_claim(extra)


def test_declared_verifier_must_differ_from_claim_author() -> None:
    bound = claim()
    with pytest.raises(ClaimContractError, match="verifier_must_differ"):
        receipt(bound, verifier_id="author-1")


def test_receipt_is_hash_bound_and_grants_no_authority() -> None:
    bound = claim()
    checked = receipt(bound)
    assert verify_verification_receipt(checked, claim=bound) is True
    assert checked["accepted"] is False
    assert checked["truth_claimed"] is False
    assert checked["write_authority"] == "NONE"
    changed = copy.deepcopy(checked)
    changed["result"] = "CONTRADICTED"
    with pytest.raises(ClaimContractError, match="receipt_hash_mismatch"):
        verify_verification_receipt(changed, claim=bound)


def test_receipts_form_an_append_only_chain() -> None:
    bound = claim()
    first = receipt(bound)
    second = receipt(
        bound,
        previous_receipt=first,
        observed_at="2026-08-22T20:10:00Z",
        result="CONTRADICTED",
    )
    assert second["sequence"] == 2
    assert second["previous_receipt_hash"] == first["receipt_hash"]
    assessment = assess_claim(
        bound, [first, second], as_of="2026-08-22T20:11:00Z"
    )
    assert assessment["status"] == "CONTRADICTED"
    assert assessment["latest_receipt_hash"] == second["receipt_hash"]


def test_chain_gap_or_reordering_is_rejected() -> None:
    bound = claim()
    first = receipt(bound)
    second = receipt(
        bound,
        previous_receipt=first,
        observed_at="2026-08-22T20:10:00Z",
    )
    with pytest.raises(ClaimContractError, match="receipt_sequence_gap"):
        assess_claim(bound, [second], as_of="2026-08-22T20:11:00Z")


def test_expired_claim_is_stale_even_after_held_receipt() -> None:
    bound = claim()
    checked = receipt(bound)
    assessment = assess_claim(
        bound, [checked], as_of="2026-08-24T20:00:00Z"
    )
    assert assessment["status"] == "STALE"
    assert assessment["truth_claimed"] is False


def test_correction_supersedes_without_mutating_original() -> None:
    original = claim()
    before = copy.deepcopy(original)
    corrected = claim(
        statement="The corrected fixture bytes have the declared digest.",
        observed_at="2026-08-22T21:00:00Z",
        valid_until="2026-08-23T21:00:00Z",
        supersedes=original,
    )
    assert original == before
    assert corrected["supersedes_claim_hash"] == original["claim_hash"]
    assert corrected["claim_hash"] != original["claim_hash"]
