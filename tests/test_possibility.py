import copy
import hashlib

import pytest

from free_valid_ai import (
    PossibilityAssessmentError,
    assess_possibility,
    create_claim,
    run_source_sha256_check,
    verify_possibility_assessment,
)
from free_valid_ai.frozen_index import DEFAULT_FROZEN_CHECK_INDEX


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def evidence_item(name: str, *, holds: bool = True):
    observed = name.encode()
    expected = observed if holds else b"different"
    claim = create_claim(
        statement=f"Constraint {name} is satisfied.",
        scope={"check": {"type": "source_sha256_equals", "version": 1,
                         "source_id": name, "expected_sha256": digest(expected)}},
        conditions=["the constraint evidence is presented directly"],
        sources=[{
            "source_id": name, "locator": f"fixture://{name}",
            "creator_id": "test", "creator_name": "Test", "license": "TEST-V1",
            "content_sha256": digest(observed),
            "usage_terms": {
                "training_use": "PROHIBITED", "commercial_use": "PROHIBITED",
                "redistribution": "PERMITTED", "attribution_required": True,
                "compensation_terms": "None", "consent_receipt": "test-consent",
            },
        }],
        author={"author_id": "test", "display_name": "Test"},
        observed_at="2026-08-27T00:00:00Z",
    )
    receipt = run_source_sha256_check(
        claim=claim, verifier_id="deterministic-sha256-tool",
        observed_at="2026-08-27T00:01:00Z", observed_bytes=observed,
    )
    return {
        "check_id": "source_sha256_equals", "check_version": 1,
        "claim": claim, "observed_bytes_hex": observed.hex(), "receipt": receipt,
    }


def assess(kind="LOGICAL", *, holds=True, evidence=None):
    evidence = evidence if evidence is not None else {
        "constraint": evidence_item("constraint", holds=holds)
    }
    return assess_possibility(
        scope={"assessment_id": "a-1", "proposal": "perform bounded operation",
               "environment_id": "test-environment"},
        constraints=[{"constraint_id": "c-1", "kind": kind,
                      "requirement": "declared requirement must hold",
                      "evidence": ["constraint"]}],
        evidence=evidence,
        frozen_index=DEFAULT_FROZEN_CHECK_INDEX,
    )


def test_all_constraints_held_is_only_possible_within_constraints() -> None:
    result = assess()
    assert result["assessment"] == "POSSIBLE_WITHIN_CONSTRAINTS"
    assert result["reassessment_required_if_constraints_change"] is True
    assert result["accepted"] is False
    assert result["truth_claimed"] is False
    assert result["write_authority"] == "NONE"
    assert result["execution_authority"] == "NONE"


@pytest.mark.parametrize(
    ("kind", "expected"),
    [("LOGICAL", "IMPOSSIBLE_UNDER_CONSTRAINTS"),
     ("RESOURCE", "CURRENTLY_INFEASIBLE"),
     ("SCOPE", "OUT_OF_SCOPE")],
)
def test_violated_constraint_kind_selects_bounded_outcome(kind, expected) -> None:
    result = assess(kind, holds=False)
    assert result["assessment"] == expected
    assert result["blocking_constraints"] == [
        {"constraint_id": "c-1", "kind": kind}
    ]


def test_missing_or_fabricated_evidence_is_unknown() -> None:
    missing = assess(evidence={})
    assert missing["assessment"] == "UNKNOWN"
    fabricated = assess(evidence={"constraint": {
        "check_id": "source_sha256_equals", "check_version": 1,
        "result": "CONTRADICTED", "receipt_sha256": "0" * 64,
    }})
    assert fabricated["assessment"] == "UNKNOWN"


def test_extra_evidence_is_unknown() -> None:
    supplied = {"constraint": evidence_item("constraint"),
                "extra": evidence_item("extra")}
    assert assess(evidence=supplied)["assessment"] == "UNKNOWN"


def test_caller_cannot_supply_outcome_or_undeclared_scope() -> None:
    with pytest.raises(PossibilityAssessmentError, match="scope_fields_mismatch"):
        assess_possibility(
            scope={"assessment_id": "a", "proposal": "p", "environment_id": "e",
                   "assessment": "POSSIBLE_WITHIN_CONSTRAINTS"},
            constraints=[{"constraint_id": "c", "kind": "LOGICAL",
                          "requirement": "r", "evidence": ["constraint"]}],
            evidence={"constraint": evidence_item("constraint")},
            frozen_index=DEFAULT_FROZEN_CHECK_INDEX,
        )


def test_receipt_is_recomputed_and_hash_bound() -> None:
    result = assess()
    assert verify_possibility_assessment(
        result, frozen_index=DEFAULT_FROZEN_CHECK_INDEX
    ) == result
    changed = copy.deepcopy(result)
    changed["assessment"] = "IMPOSSIBLE_UNDER_CONSTRAINTS"
    with pytest.raises(PossibilityAssessmentError, match="assessment_content_mismatch"):
        verify_possibility_assessment(
            changed, frozen_index=DEFAULT_FROZEN_CHECK_INDEX
        )
