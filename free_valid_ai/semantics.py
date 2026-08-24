"""Closed, hash-bound meanings for the Simulator runtime."""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any, Iterable, Mapping


CONTRACT_TYPE = "free_valid_ai_semantic_contract"
CONTRACT_VERSION = 1
INTERPRETATION_POLICIES = {"EXACT", "OPEN"}

_CONTRACT_FIELDS = {
    "type", "version", "terms", "accepted", "truth_claimed",
    "write_authority", "execution_authority", "deletion_authority",
    "contract_hash",
}
_TERM_FIELDS = {
    "term_id", "definition", "interpretation_policy", "not_equivalent_to",
}


class SemanticContractError(ValueError):
    """A semantic contract violates its closed schema or hash binding."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SemanticContractError("value_not_canonical_json") from exc


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SemanticContractError(f"{label}_must_be_nonempty_string")
    return value


def _term(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SemanticContractError("term_must_be_object")
    term = json.loads(_canonical(dict(value)).decode("utf-8"))
    if set(term) != _TERM_FIELDS:
        raise SemanticContractError("term_fields_mismatch")
    _nonempty(term["term_id"], "term_id")
    _nonempty(term["definition"], "term_definition")
    if term["interpretation_policy"] not in INTERPRETATION_POLICIES:
        raise SemanticContractError("term_interpretation_policy_invalid")
    if not isinstance(term["not_equivalent_to"], list):
        raise SemanticContractError("term_not_equivalent_to_must_be_list")
    if len(term["not_equivalent_to"]) != len(set(term["not_equivalent_to"])):
        raise SemanticContractError("term_not_equivalent_to_duplicates")
    for other in term["not_equivalent_to"]:
        _nonempty(other, "term_not_equivalent_to_item")
        if other == term["term_id"]:
            raise SemanticContractError("term_cannot_differ_from_itself")
    if term["not_equivalent_to"] != sorted(term["not_equivalent_to"]):
        raise SemanticContractError("term_not_equivalent_to_must_be_sorted")
    return term


def create_semantic_contract(terms: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    checked = [_term(term) for term in terms]
    if not checked:
        raise SemanticContractError("terms_must_not_be_empty")
    ids = [term["term_id"] for term in checked]
    if len(ids) != len(set(ids)):
        raise SemanticContractError("term_ids_must_be_unique")
    if ids != sorted(ids):
        raise SemanticContractError("terms_must_be_sorted_by_id")
    known = set(ids)
    for term in checked:
        for other in term["not_equivalent_to"]:
            if other not in known:
                raise SemanticContractError("term_relation_target_unknown")
            reciprocal = next(item for item in checked if item["term_id"] == other)
            if term["term_id"] not in reciprocal["not_equivalent_to"]:
                raise SemanticContractError("term_relation_must_be_reciprocal")
    body = {
        "type": CONTRACT_TYPE,
        "version": CONTRACT_VERSION,
        "terms": checked,
        "accepted": False,
        "truth_claimed": False,
        "write_authority": "NONE",
        "execution_authority": "NONE",
        "deletion_authority": "NONE",
    }
    return {**body, "contract_hash": _hash(body)}


def verify_semantic_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SemanticContractError("contract_must_be_object")
    contract = json.loads(_canonical(dict(value)).decode("utf-8"))
    if set(contract) != _CONTRACT_FIELDS:
        raise SemanticContractError("contract_fields_mismatch")
    rebuilt = create_semantic_contract(contract["terms"])
    for field in _CONTRACT_FIELDS - {"contract_hash"}:
        if contract[field] != rebuilt[field]:
            raise SemanticContractError(f"contract_{field}_invalid")
    if not isinstance(contract["contract_hash"], str) or not secrets.compare_digest(
        contract["contract_hash"], rebuilt["contract_hash"]
    ):
        raise SemanticContractError("contract_hash_invalid")
    return contract


def relation(contract: Mapping[str, Any], left: str, right: str) -> str:
    verified = verify_semantic_contract(contract)
    terms = {term["term_id"]: term for term in verified["terms"]}
    if left not in terms or right not in terms:
        raise SemanticContractError("relation_term_unknown")
    if left == right:
        return "SAME_TERM"
    if right in terms[left]["not_equivalent_to"]:
        return "DISTINCT_TERMS"
    return "UNSPECIFIED"


_DISTINCT = {
    "HOLO", "HOLOGRAM", "MODEL_CARRIER", "PROJECTION", "SIMULATOR"
}

DEFAULT_SEMANTIC_CONTRACT = create_semantic_contract(
    [
        {
            "term_id": "HOLO",
            "definition": "An externally filed information structure presented to an AI for reconstruction.",
            "interpretation_policy": "EXACT",
            "not_equivalent_to": sorted(_DISTINCT - {"HOLO"}),
        },
        {
            "term_id": "HOLOGRAM",
            "definition": "A projection that satisfies its declared reconstruction and verification checks.",
            "interpretation_policy": "EXACT",
            "not_equivalent_to": sorted(_DISTINCT - {"HOLOGRAM"}),
        },
        {
            "term_id": "MODEL_CARRIER",
            "definition": "A replaceable model providing inference and language during a projection.",
            "interpretation_policy": "EXACT",
            "not_equivalent_to": sorted(_DISTINCT - {"MODEL_CARRIER"}),
        },
        {
            "term_id": "PROJECTION",
            "definition": "A situated AI instance produced by a Simulator using a model carrier and presented inputs.",
            "interpretation_policy": "EXACT",
            "not_equivalent_to": sorted(_DISTINCT - {"PROJECTION"}),
        },
        {
            "term_id": "SIMULATOR",
            "definition": "The computer and runtime environment performing the computation that supports a projection.",
            "interpretation_policy": "EXACT",
            "not_equivalent_to": sorted(_DISTINCT - {"SIMULATOR"}),
        },
    ]
)
