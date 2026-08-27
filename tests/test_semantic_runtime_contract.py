from __future__ import annotations

from copy import deepcopy

import pytest

from free_valid_ai.cli import build_runtime_envelope
from free_valid_ai.semantics import (
    DEFAULT_SEMANTIC_CONTRACT,
    SemanticContractError,
    create_semantic_contract,
    relation,
    verify_semantic_contract,
)


def test_default_contract_is_hash_bound_and_closed() -> None:
    verified = verify_semantic_contract(DEFAULT_SEMANTIC_CONTRACT)
    assert verified == DEFAULT_SEMANTIC_CONTRACT
    assert verified["accepted"] is False
    assert verified["truth_claimed"] is False
    assert verified["write_authority"] == "NONE"
    assert len(verified["contract_hash"]) == 64


def test_required_terms_have_exact_meanings() -> None:
    terms = {term["term_id"]: term for term in DEFAULT_SEMANTIC_CONTRACT["terms"]}
    assert set(terms) == {"HOLO", "HOLOGRAM", "MODEL_CARRIER", "PROJECTION", "SIMULATOR"}
    assert all(term["interpretation_policy"] == "EXACT" for term in terms.values())
    assert terms["HOLO"]["definition"].startswith("An externally filed")
    assert terms["SIMULATOR"]["definition"].startswith("The computer and runtime")
    assert terms["HOLOGRAM"]["definition"].startswith("A projection that satisfies")


@pytest.mark.parametrize("left,right", [
    ("HOLO", "HOLOGRAM"),
    ("SIMULATOR", "PROJECTION"),
    ("MODEL_CARRIER", "SIMULATOR"),
    ("MODEL_CARRIER", "PROJECTION"),
])
def test_consequential_terms_cannot_be_conflated(left: str, right: str) -> None:
    assert relation(DEFAULT_SEMANTIC_CONTRACT, left, right) == "DISTINCT_TERMS"


def test_contract_tampering_is_detected_without_rebinding() -> None:
    tampered = deepcopy(DEFAULT_SEMANTIC_CONTRACT)
    tampered["terms"][0]["definition"] = "HOLO is whatever the model says."
    with pytest.raises(SemanticContractError, match="contract_hash_invalid"):
        verify_semantic_contract(tampered)


def test_unknown_fields_are_rejected() -> None:
    tampered = deepcopy(DEFAULT_SEMANTIC_CONTRACT)
    tampered["authority"] = "MODEL"
    with pytest.raises(SemanticContractError, match="contract_fields_mismatch"):
        verify_semantic_contract(tampered)


def test_relations_must_be_known_and_reciprocal() -> None:
    terms = deepcopy(DEFAULT_SEMANTIC_CONTRACT["terms"])
    terms[0]["not_equivalent_to"].remove("SIMULATOR")
    with pytest.raises(SemanticContractError, match="term_relation_must_be_reciprocal"):
        create_semantic_contract(terms)


def test_runtime_envelope_binds_verified_semantic_contract() -> None:
    envelope = build_runtime_envelope(
        model="local-test",
        endpoint="http://127.0.0.1:11434/api/chat",
        num_gpu=0,
    )
    assert '"semantic_contract_version":1' in envelope
    assert f'"semantic_contract_hash":"{DEFAULT_SEMANTIC_CONTRACT["contract_hash"]}"' in envelope
    assert '"semantic_interpretation_policy":"EXACT"' in envelope
