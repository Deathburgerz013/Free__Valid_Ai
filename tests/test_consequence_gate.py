import copy
import hashlib
import json

import pytest

from free_valid_ai import (
    ConsequenceGateError,
    assess_consequences,
    assess_possibility,
    consequence_gate_is_caller_independent,
    create_claim,
    run_source_sha256_check,
    run_json_pointer_check,
    verify_consequence_gate,
)
from free_valid_ai.frozen_index import DEFAULT_FROZEN_CHECK_INDEX


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def evidence_item(*, holds=True):
    observed = b"safety-boundary"
    expected = observed if holds else b"different"
    claim = create_claim(
        statement="The declared safety requirement holds.",
        scope={"check": {"type": "source_sha256_equals", "version": 1,
                         "source_id": "safety", "expected_sha256": digest(expected)}},
        conditions=["the safety evidence is presented directly"],
        sources=[{
            "source_id": "safety", "locator": "fixture://safety",
            "creator_id": "test", "creator_name": "Test", "license": "TEST-V1",
            "content_sha256": digest(observed),
            "usage_terms": {
                "training_use": "PROHIBITED", "commercial_use": "PROHIBITED",
                "redistribution": "PERMITTED", "attribution_required": True,
                "compensation_terms": "None", "consent_receipt": "test-consent",
            },
        }],
        author={"author_id": "safety-policy", "display_name": "Safety Policy"},
        observed_at="2026-08-27T00:00:00Z",
    )
    receipt = run_source_sha256_check(
        claim=claim, verifier_id="deterministic-sha256-tool",
        observed_at="2026-08-27T00:01:00Z", observed_bytes=observed,
    )
    return {"check_id": "source_sha256_equals", "check_version": 1,
            "claim": claim, "observed_bytes_hex": observed.hex(), "receipt": receipt}


def possibility(*, assessment="POSSIBLE", holds=True):
    evidence = {"safety": evidence_item(holds=holds)}
    kind = "LOGICAL" if assessment == "POSSIBLE" else assessment
    return assess_possibility(
        scope={"assessment_id": "safety-a1", "proposal": "write candidate locally",
               "environment_id": "bounded-test"},
        constraints=[{"constraint_id": "safety", "kind": kind,
                      "requirement": "safety boundary must hold", "evidence": ["safety"]}],
        evidence=evidence, frozen_index=DEFAULT_FROZEN_CHECK_INDEX,
    )


def impact_bundle(people="INDIVIDUAL", systems="LOCAL", reversibility="REVERSIBLE"):
    impact = {"people_scope": people, "systems_scope": systems,
              "reversibility": reversibility}
    observed = json.dumps(impact, sort_keys=True, separators=(",", ":")).encode()
    evidence = {}
    references = {}
    for field, expected in impact.items():
        claim = create_claim(
            statement=f"The observed impact field {field} equals its declaration.",
            scope={"check": {"type": "json_pointer_equals", "version": 1,
                             "source_id": "impact", "pointer": f"/{field}",
                             "expected_value": expected}},
            conditions=["the bound impact JSON is presented directly"],
            sources=[{
                "source_id": "impact", "locator": "fixture://impact",
                "creator_id": "observer", "creator_name": "Impact Observer",
                "license": "TEST-V1", "content_sha256": digest(observed),
                "usage_terms": {
                    "training_use": "PROHIBITED", "commercial_use": "PROHIBITED",
                    "redistribution": "PERMITTED", "attribution_required": True,
                    "compensation_terms": "None", "consent_receipt": "test-consent",
                },
            }],
            author={"author_id": "impact-policy", "display_name": "Impact Policy"},
            observed_at="2026-08-27T00:00:00Z",
        )
        receipt = run_json_pointer_check(
            claim=claim, verifier_id="deterministic-json-tool",
            observed_at="2026-08-27T00:01:00Z", observed_bytes=observed,
        )
        evidence[field] = {
            "check_id": "json_pointer_equals", "check_version": 1,
            "claim": claim, "observed_bytes_hex": observed.hex(), "receipt": receipt,
        }
        references[field] = [field]
    return impact, references, evidence


def gate(*, people="INDIVIDUAL", systems="LOCAL", reversibility="REVERSIBLE",
         unknowns=(), possibility_value=None, impact_values=None):
    impact, references, evidence = impact_values or impact_bundle(
        people, systems, reversibility
    )
    return assess_consequences(
        action={"action_id": "action-1", "description": "write candidate locally",
                "environment_id": "bounded-test"},
        impact=impact, impact_evidence=references, evidence=evidence,
        unknown_consequences=unknowns,
        possibility_assessment=possibility_value or possibility(),
        frozen_index=DEFAULT_FROZEN_CHECK_INDEX,
    )


def test_bounded_reversible_verified_action_is_only_eligible_for_authorization() -> None:
    result = gate()
    assert result["decision"] == "ELIGIBLE"
    assert result["eligible_for"] == "SEPARATE_AUTHORIZATION_ONLY"
    assert result["execution_authority"] == "NONE"
    assert result["accepted"] is False


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [("people", "PUBLIC", "public_impact_not_authorizable_by_this_gate"),
     ("systems", "UNBOUNDED", "unbounded_system_impact"),
     ("reversibility", "IRREVERSIBLE", "reversibility_irreversible"),
     ("reversibility", "UNKNOWN", "reversibility_unknown")],
)
def test_broad_or_irreversible_impact_is_blocked(field, value, reason) -> None:
    kwargs = {field: value}
    result = gate(**kwargs)
    assert result["decision"] == "BLOCKED"
    assert reason in result["reasons"]
    assert result["eligible_for"] == "NONE"


def test_logical_safety_contradiction_is_prohibited() -> None:
    result = gate(possibility_value=possibility(assessment="LOGICAL", holds=False))
    assert result["decision"] == "PROHIBITED"
    assert result["reasons"] == ["logical_safety_constraint_contradicted"]


def test_missing_or_rebound_impact_evidence_is_blocked() -> None:
    impact, references, evidence = impact_bundle()
    missing = copy.deepcopy(references)
    missing["people_scope"] = ["missing"]
    result = gate(impact_values=(impact, missing, evidence))
    assert result["decision"] == "BLOCKED"
    assert "impact_evidence_incomplete:people_scope" in result["reasons"]
    rebound = copy.deepcopy(evidence)
    rebound["people_scope"]["claim"]["scope"]["check"]["expected_value"] = "NONE"
    result = gate(impact_values=(impact, references, rebound))
    assert result["decision"] == "BLOCKED"


def test_unknown_possibility_is_blocked() -> None:
    value = assess_possibility(
        scope={"assessment_id": "safety-a1", "proposal": "write candidate locally",
               "environment_id": "bounded-test"},
        constraints=[{"constraint_id": "safety", "kind": "LOGICAL",
                      "requirement": "safety boundary must hold",
                      "evidence": ["missing"]}],
        evidence={}, frozen_index=DEFAULT_FROZEN_CHECK_INDEX,
    )
    result = gate(possibility_value=value)
    assert result["decision"] == "BLOCKED"
    assert result["reasons"] == ["possibility_not_established:UNKNOWN"]


@pytest.mark.parametrize(
    "kwargs",
    [{"unknowns": ["downstream effect not established"]},
     {"people": "GROUP"}, {"systems": "EXTERNAL"},
     {"reversibility": "COMPENSATABLE"}],
)
def test_contained_but_unresolved_impact_is_sandbox_only(kwargs) -> None:
    result = gate(**kwargs)
    assert result["decision"] == "SANDBOX_ONLY"
    assert result["execution_authority"] == "NONE"


def test_possibility_must_bind_the_same_action_and_environment() -> None:
    value = possibility()
    value["scope"]["proposal"] = "different action"
    with pytest.raises(Exception):
        gate(possibility_value=value)


def test_caller_cannot_supply_decision_or_execution() -> None:
    assert consequence_gate_is_caller_independent() is True
    impact, references, evidence = impact_bundle(people="NONE")
    with pytest.raises(TypeError):
        assess_consequences(
            action={"action_id": "a", "description": "d", "environment_id": "e"},
            impact=impact, impact_evidence=references, evidence=evidence,
            unknown_consequences=[], possibility_assessment=possibility(),
            frozen_index=DEFAULT_FROZEN_CHECK_INDEX,
            decision="ELIGIBLE",
        )


def test_gate_receipt_is_closed_recomputed_and_hash_bound() -> None:
    result = gate()
    assert verify_consequence_gate(
        result, frozen_index=DEFAULT_FROZEN_CHECK_INDEX
    ) == result
    changed = copy.deepcopy(result)
    changed["decision"] = "PROHIBITED"
    with pytest.raises(ConsequenceGateError, match="gate_content_mismatch"):
        verify_consequence_gate(
            changed, frozen_index=DEFAULT_FROZEN_CHECK_INDEX
        )
