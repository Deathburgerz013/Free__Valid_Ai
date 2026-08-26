import copy
import hashlib

import pytest

from free_valid_ai.directional_comparator import (
    DirectionalComparatorError,
    compare_directional,
    verify_directional_comparison,
)
from free_valid_ai import create_claim, run_source_sha256_check
from free_valid_ai.frozen_index import DEFAULT_FROZEN_CHECK_INDEX


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def bound_evidence(name: str):
    observed = name.encode()
    claim = create_claim(
        statement=f"Evidence {name} has its declared digest.",
        scope={"check": {"type": "source_sha256_equals", "version": 1,
                         "source_id": name, "expected_sha256": digest(observed)}},
        conditions=["the identified bytes are presented directly"],
        sources=[{
            "source_id": name, "locator": f"fixture://{name}",
            "creator_id": "test", "creator_name": "Test",
            "license": "TEST-V1", "content_sha256": digest(observed),
            "usage_terms": {
                "training_use": "PROHIBITED", "commercial_use": "PROHIBITED",
                "redistribution": "PERMITTED", "attribution_required": True,
                "compensation_terms": "None", "consent_receipt": "test-consent",
            },
        }],
        author={"author_id": "test", "display_name": "Test"},
        observed_at="2026-08-26T00:00:00Z",
    )
    receipt = run_source_sha256_check(
        claim=claim, verifier_id="deterministic-sha256-tool",
        observed_at="2026-08-26T00:01:00Z", observed_bytes=observed,
    )
    return {
        "check_id": "source_sha256_equals", "check_version": 1,
        "claim": claim, "observed_bytes_hex": observed.hex(), "receipt": receipt,
    }


def evidence(*ids: str):
    return {item: bound_evidence(item) for item in ids}


def compare(*, latency=8, accuracy=11, evidence_value=None, invariant=True):
    evidence_value = evidence_value or evidence("inv", "latency", "accuracy")
    return compare_directional(
        scope={"task_id": "task", "baseline_id": "base", "candidate_id": "next"},
        invariants=[{
            "name": "same output schema", "baseline_holds": True,
            "candidate_holds": invariant, "evidence": ["inv"],
        }],
        measures=[
            {"name": "latency", "direction": "LOWER_IS_BETTER",
             "baseline": 10, "candidate": latency, "evidence": ["latency"]},
            {"name": "accuracy", "direction": "HIGHER_IS_BETTER",
             "baseline": 10, "candidate": accuracy, "evidence": ["accuracy"]},
        ],
        evidence=evidence_value,
        frozen_index=DEFAULT_FROZEN_CHECK_INDEX,
    )


def test_computes_advanced_without_accepting() -> None:
    made = compare()
    assert made["classification"] == "ADVANCED"
    assert made["accepted"] is False
    assert made["truth_claimed"] is False
    assert made["write_authority"] == "NONE"


@pytest.mark.parametrize(
    ("latency", "accuracy", "expected"),
    [(10, 10, "EQUIVALENT"), (12, 9, "REGRESSED"), (8, 9, "MIXED")],
)
def test_directional_classifications(latency, accuracy, expected) -> None:
    assert compare(latency=latency, accuracy=accuracy)["classification"] == expected


def test_invariant_loss_is_regression_even_when_measures_improve() -> None:
    assert compare(invariant=False)["classification"] == "REGRESSED"


def test_missing_failed_or_unadmitted_evidence_is_unknown() -> None:
    missing = evidence("inv", "latency")
    assert compare(evidence_value=missing)["classification"] == "UNKNOWN"
    failed = evidence("inv", "latency", "accuracy")
    failed["accuracy"]["receipt"]["result"] = "CONTRADICTED"
    assert compare(evidence_value=failed)["classification"] == "UNKNOWN"
    unadmitted = evidence("inv", "latency", "accuracy")
    unadmitted["accuracy"]["check_id"] = "caller_says_so"
    assert compare(evidence_value=unadmitted)["classification"] == "UNKNOWN"


def test_fabricated_pass_envelope_is_unknown() -> None:
    fabricated = evidence("inv", "latency", "accuracy")
    fabricated["accuracy"] = {
        "check_id": "source_sha256_equals", "check_version": 1,
        "result": "PASS", "receipt_sha256": "0" * 64,
    }
    result = compare(evidence_value=fabricated)
    assert result["classification"] == "UNKNOWN"
    assert result["unknown_reasons"] == ["evidence_set_not_exact", "measure_evidence_incomplete:accuracy"]


def test_receipt_cannot_be_rebound_to_different_presented_bytes() -> None:
    rebound = evidence("inv", "latency", "accuracy")
    rebound["accuracy"]["observed_bytes_hex"] = b"other".hex()
    assert compare(evidence_value=rebound)["classification"] == "UNKNOWN"


def test_extra_evidence_is_not_silently_ignored() -> None:
    assert compare(
        evidence_value=evidence("inv", "latency", "accuracy", "extra")
    )["classification"] == "UNKNOWN"


def test_caller_cannot_supply_classification_or_undeclared_scope() -> None:
    with pytest.raises(DirectionalComparatorError, match="scope_fields_mismatch"):
        compare_directional(
            scope={"task_id": "task", "baseline_id": "a", "candidate_id": "b",
                   "classification": "ADVANCED"},
            invariants=[{"name": "i", "baseline_holds": True,
                         "candidate_holds": True, "evidence": ["inv"]}],
            measures=[{"name": "m", "direction": "HIGHER_IS_BETTER",
                       "baseline": 1, "candidate": 2, "evidence": ["m"]}],
            evidence=evidence("inv", "m"),
            frozen_index=DEFAULT_FROZEN_CHECK_INDEX,
        )


def test_result_is_deterministic_and_hash_bound() -> None:
    first = compare()
    second = compare()
    assert first == second
    assert verify_directional_comparison(
        first, frozen_index=DEFAULT_FROZEN_CHECK_INDEX
    ) == first
    changed = copy.deepcopy(first)
    changed["classification"] = "REGRESSED"
    with pytest.raises(DirectionalComparatorError, match="comparison_content_mismatch"):
        verify_directional_comparison(
            changed, frozen_index=DEFAULT_FROZEN_CHECK_INDEX
        )


def test_rebound_hash_is_also_rejected() -> None:
    changed = compare()
    changed["classification"] = "REGRESSED"
    body = {key: value for key, value in changed.items() if key != "comparison_hash"}
    changed["comparison_hash"] = hashlib.sha256(
        __import__("json").dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()
    with pytest.raises(DirectionalComparatorError, match="comparison_hash_mismatch"):
        verify_directional_comparison(
            changed, frozen_index=DEFAULT_FROZEN_CHECK_INDEX
        )
