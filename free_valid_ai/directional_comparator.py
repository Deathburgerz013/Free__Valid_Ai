"""Scoped, evidence-bound directional comparison without acceptance authority."""

from __future__ import annotations

import hashlib
import json
from numbers import Real
from typing import Any, Iterable, Mapping

from .frozen_index import admitted_check, verify_frozen_check_index


COMPARISONS = {"ADVANCED", "EQUIVALENT", "REGRESSED", "MIXED", "UNKNOWN"}
DIRECTIONS = {"HIGHER_IS_BETTER", "LOWER_IS_BETTER"}


class DirectionalComparatorError(ValueError):
    """The caller supplied a malformed comparison contract."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DirectionalComparatorError("value_not_canonical_json") from exc


def _clone(value: object) -> Any:
    return json.loads(_canonical(value).decode("utf-8"))


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DirectionalComparatorError(f"{label}_must_be_nonempty_string")
    return value


def _objects(values: Iterable[Mapping[str, Any]], label: str) -> list[dict[str, Any]]:
    if isinstance(values, (str, bytes, Mapping)):
        raise DirectionalComparatorError(f"{label}_must_be_iterable_of_objects")
    made = [_clone(dict(value)) for value in values]
    if not made:
        raise DirectionalComparatorError(f"{label}_must_not_be_empty")
    return made


def _evidence_status(
    references: Any,
    evidence: Mapping[str, Any],
    frozen_index: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    if not isinstance(references, list) or not references:
        return False, []
    used: list[str] = []
    for evidence_id in references:
        if not isinstance(evidence_id, str) or evidence_id not in evidence:
            return False, used
        item = evidence[evidence_id]
        if not isinstance(item, Mapping) or set(item) != {
            "check_id", "check_version", "result", "receipt_sha256"
        }:
            return False, used
        admitted = admitted_check(
            frozen_index, item["check_id"], item["check_version"]
        )
        digest = item["receipt_sha256"]
        if (
            admitted is None
            or item["result"] != "PASS"
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            return False, used
        used.append(evidence_id)
    return True, used


def compare_directional(
    *,
    scope: Mapping[str, Any],
    invariants: Iterable[Mapping[str, Any]],
    measures: Iterable[Mapping[str, Any]],
    evidence: Mapping[str, Mapping[str, Any]],
    frozen_index: Mapping[str, Any],
) -> dict[str, Any]:
    """Compute a classification; no classification/acceptance input is accepted."""
    index = verify_frozen_check_index(frozen_index)
    declared_scope = _clone(dict(scope))
    if set(declared_scope) != {"task_id", "baseline_id", "candidate_id"}:
        raise DirectionalComparatorError("scope_fields_mismatch")
    for field, value in declared_scope.items():
        _nonempty(value, f"scope_{field}")
    if declared_scope["baseline_id"] == declared_scope["candidate_id"]:
        raise DirectionalComparatorError("scope_endpoints_must_differ")

    invariant_items = _objects(invariants, "invariants")
    measure_items = _objects(measures, "measures")
    evidence_items = _clone(dict(evidence))
    names: set[str] = set()
    used: list[str] = []
    unknown_reasons: list[str] = []
    invariant_regression = False

    for item in invariant_items:
        if set(item) != {"name", "baseline_holds", "candidate_holds", "evidence"}:
            raise DirectionalComparatorError("invariant_fields_mismatch")
        name = _nonempty(item["name"], "invariant_name")
        if name in names:
            raise DirectionalComparatorError("criterion_name_duplicate")
        names.add(name)
        if not isinstance(item["baseline_holds"], bool) or not isinstance(
            item["candidate_holds"], bool
        ):
            raise DirectionalComparatorError("invariant_values_must_be_boolean")
        complete, refs = _evidence_status(item["evidence"], evidence_items, index)
        used.extend(refs)
        if not complete:
            unknown_reasons.append(f"invariant_evidence_incomplete:{name}")
        if item["baseline_holds"] and not item["candidate_holds"]:
            invariant_regression = True
        if not item["baseline_holds"]:
            unknown_reasons.append(f"baseline_invariant_not_established:{name}")

    signs: list[int] = []
    for item in measure_items:
        if set(item) != {"name", "direction", "baseline", "candidate", "evidence"}:
            raise DirectionalComparatorError("measure_fields_mismatch")
        name = _nonempty(item["name"], "measure_name")
        if name in names:
            raise DirectionalComparatorError("criterion_name_duplicate")
        names.add(name)
        if item["direction"] not in DIRECTIONS:
            raise DirectionalComparatorError("measure_direction_invalid")
        baseline, candidate = item["baseline"], item["candidate"]
        if (
            not isinstance(baseline, Real) or isinstance(baseline, bool)
            or not isinstance(candidate, Real) or isinstance(candidate, bool)
        ):
            raise DirectionalComparatorError("measure_values_must_be_numbers")
        complete, refs = _evidence_status(item["evidence"], evidence_items, index)
        used.extend(refs)
        if not complete:
            unknown_reasons.append(f"measure_evidence_incomplete:{name}")
        delta = candidate - baseline
        if item["direction"] == "LOWER_IS_BETTER":
            delta = -delta
        signs.append(1 if delta > 0 else -1 if delta < 0 else 0)

    if set(used) != set(evidence_items):
        unknown_reasons.append("evidence_set_not_exact")

    if unknown_reasons:
        classification = "UNKNOWN"
    elif invariant_regression:
        classification = "REGRESSED"
    elif all(sign == 0 for sign in signs):
        classification = "EQUIVALENT"
    elif all(sign >= 0 for sign in signs) and any(sign > 0 for sign in signs):
        classification = "ADVANCED"
    elif all(sign <= 0 for sign in signs) and any(sign < 0 for sign in signs):
        classification = "REGRESSED"
    else:
        classification = "MIXED"

    body = {
        "type": "free_valid_ai_directional_comparison",
        "schema_version": 1,
        "scope": declared_scope,
        "frozen_index_hash": index["index_hash"],
        "invariants": invariant_items,
        "measures": measure_items,
        "evidence": evidence_items,
        "classification": classification,
        "unknown_reasons": sorted(set(unknown_reasons)),
        "accepted": False,
        "truth_claimed": False,
        "write_authority": "NONE",
    }
    return {**body, "comparison_hash": _hash(body)}


def verify_directional_comparison(
    value: Mapping[str, Any],
    *,
    frozen_index: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify the closed receipt and recompute its caller-independent result."""
    if not isinstance(value, Mapping):
        raise DirectionalComparatorError("comparison_must_be_object")
    received = _clone(dict(value))
    expected_fields = {
        "type", "schema_version", "scope", "frozen_index_hash", "invariants",
        "measures", "evidence", "classification", "unknown_reasons", "accepted",
        "truth_claimed", "write_authority", "comparison_hash",
    }
    if set(received) != expected_fields:
        raise DirectionalComparatorError("comparison_fields_mismatch")
    if (
        received["type"] != "free_valid_ai_directional_comparison"
        or received["schema_version"] != 1
    ):
        raise DirectionalComparatorError("comparison_schema_mismatch")
    rebuilt = compare_directional(
        scope=received["scope"],
        invariants=received["invariants"],
        measures=received["measures"],
        evidence=received["evidence"],
        frozen_index=frozen_index,
    )
    if received != rebuilt:
        if received.get("comparison_hash") != rebuilt["comparison_hash"]:
            raise DirectionalComparatorError("comparison_hash_mismatch")
        raise DirectionalComparatorError("comparison_content_mismatch")
    return received
