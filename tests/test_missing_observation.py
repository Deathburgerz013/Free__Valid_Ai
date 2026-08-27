import copy
import hashlib

import pytest

from free_valid_ai import (
    MissingObservationError,
    assess_missing_observations,
    create_claim,
    missing_observation_assessment_is_caller_independent,
    run_source_sha256_check,
    verify_missing_observation_assessment,
)
from free_valid_ai.frozen_index import DEFAULT_FROZEN_CHECK_INDEX


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def evidence_item(name: str, *, holds: bool = True):
    observed = name.encode()
    expected = observed if holds else b"different"
    claim = create_claim(
        statement=f"Observation {name} holds.",
        scope={"check": {"type": "source_sha256_equals", "version": 1,
                         "source_id": name, "expected_sha256": digest(expected)}},
        conditions=["the observation bytes are presented directly"],
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


def assess(*, second_evidence=None, evidence=None):
    supplied = {"technical": evidence_item("technical")}
    if second_evidence is not None:
        supplied["downstream"] = second_evidence
    if evidence is not None:
        supplied = evidence
    return assess_missing_observations(
        scope={
            "assessment_id": "missing-1", "proposal": "divert bounded flow",
            "environment_id": "test-environment",
            "coverage_boundary": "declared technical and downstream observations",
        },
        required_observations=[
            {"observation_id": "technical", "question": "Does the mechanism function?",
             "affected_scope": "SYSTEM", "evidence": ["technical"]},
            {"observation_id": "downstream", "question": "Who is affected downstream?",
             "affected_scope": "PUBLIC",
             "evidence": ["downstream"] if second_evidence is not None else []},
        ],
        evidence=supplied,
        frozen_index=DEFAULT_FROZEN_CHECK_INDEX,
    )


def test_held_checks_do_not_hide_a_missing_dimension() -> None:
    result = assess()
    assert result["coverage"] == "INCOMPLETE"
    assert result["audit_targets"] == [{
        "observation_id": "downstream", "question": "Who is affected downstream?",
        "affected_scope": "PUBLIC", "status": "MISSING",
    }]
    assert result["overall_safety"] == "NOT_ASSESSED"
    assert result["undeclared_dimensions_assessed"] is False


def test_all_declared_observations_only_complete_declared_scope() -> None:
    result = assess(second_evidence=evidence_item("downstream"))
    assert result["coverage"] == "COMPLETE_DECLARED_SCOPE"
    assert result["audit_targets"] == []
    assert result["overall_safety"] == "NOT_ASSESSED"


def test_contradicted_observation_remains_an_audit_target() -> None:
    result = assess(second_evidence=evidence_item("downstream", holds=False))
    assert result["coverage"] == "INCOMPLETE"
    assert result["audit_targets"][0]["status"] == "CONTRADICTED"


def test_fabricated_or_extra_evidence_is_unknown() -> None:
    fabricated = {
        "technical": {"result": "HELD"},
        "downstream": evidence_item("downstream"),
    }
    assert assess(second_evidence=fabricated["downstream"], evidence=fabricated)[
        "coverage"
    ] == "UNKNOWN"
    extra = {
        "technical": evidence_item("technical"),
        "extra": evidence_item("extra"),
    }
    assert assess(evidence=extra)["coverage"] == "UNKNOWN"


def test_caller_cannot_supply_coverage_or_probe_execution() -> None:
    assert missing_observation_assessment_is_caller_independent()
    with pytest.raises(MissingObservationError, match="scope_fields_mismatch"):
        assess_missing_observations(
            scope={"assessment_id": "a", "proposal": "p", "environment_id": "e",
                   "coverage_boundary": "b", "coverage": "COMPLETE_DECLARED_SCOPE"},
            required_observations=[{
                "observation_id": "o", "question": "q", "affected_scope": "SYSTEM",
                "evidence": [],
            }], evidence={}, frozen_index=DEFAULT_FROZEN_CHECK_INDEX,
        )


def test_duplicate_and_invalid_observations_are_rejected() -> None:
    base = {"observation_id": "o", "question": "q", "affected_scope": "SYSTEM",
            "evidence": []}
    scope = {"assessment_id": "a", "proposal": "p", "environment_id": "e",
             "coverage_boundary": "b"}
    with pytest.raises(MissingObservationError, match="observation_id_duplicate"):
        assess_missing_observations(
            scope=scope, required_observations=[base, base], evidence={},
            frozen_index=DEFAULT_FROZEN_CHECK_INDEX,
        )
    bad = dict(base, affected_scope="EVERYTHING")
    with pytest.raises(MissingObservationError, match="affected_scope_invalid"):
        assess_missing_observations(
            scope=scope, required_observations=[bad], evidence={},
            frozen_index=DEFAULT_FROZEN_CHECK_INDEX,
        )


def test_receipt_recomputes_and_rejects_tampering() -> None:
    result = assess()
    assert verify_missing_observation_assessment(
        result, frozen_index=DEFAULT_FROZEN_CHECK_INDEX
    ) == result
    changed = copy.deepcopy(result)
    changed["overall_safety"] = "SAFE"
    with pytest.raises(MissingObservationError, match="assessment_content_mismatch"):
        verify_missing_observation_assessment(
            changed, frozen_index=DEFAULT_FROZEN_CHECK_INDEX
        )
